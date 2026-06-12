// Package handler implements the AuthService gRPC server.
package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/malvinpratama/iam-go-auth/internal/cache"
	"github.com/malvinpratama/iam-go-auth/internal/db"
	"github.com/malvinpratama/iam-go-auth/internal/email"
	"github.com/malvinpratama/iam-go-auth/internal/jwt"
	"github.com/malvinpratama/iam-go-auth/internal/password"
	authv1 "github.com/malvinpratama/iam-go-contracts/gen/auth/v1"
	"github.com/malvinpratama/iam-go-libs/config"
	"github.com/malvinpratama/iam-go-libs/events"
	"github.com/malvinpratama/iam-go-libs/grpcutil"
)

const defaultRole = "user"

// AuthHandler implements authv1.AuthServiceServer.
type AuthHandler struct {
	authv1.UnimplementedAuthServiceServer
	pool       *pgxpool.Pool
	q          *db.Queries
	jwt        *jwt.Manager
	refreshTTL time.Duration
	dummyHash  string // for constant-time login on unknown users
	mail       email.Sender
	cache      *cache.Cache // optional Redis: token denylist + permission cache
}

// New builds an AuthHandler.
func New(pool *pgxpool.Pool, jwtMgr *jwt.Manager, refreshTTL time.Duration, mail email.Sender, c *cache.Cache) *AuthHandler {
	// Precompute an argon2 hash so Login spends comparable time whether or not
	// the user exists (mitigates user-enumeration via timing).
	dummy, _ := password.Hash("constant-time-dummy-password")
	return &AuthHandler{pool: pool, q: db.New(pool), jwt: jwtMgr, refreshTTL: refreshTTL, dummyHash: dummy, mail: mail, cache: c}
}

// requirePerm enforces a permission from the gateway-supplied identity metadata
// (defense-in-depth: services re-check, not just the gateway).
func requirePerm(ctx context.Context, perm string) error {
	if grpcutil.FromIncoming(ctx).HasPermission(perm) {
		return nil
	}
	return status.Error(codes.PermissionDenied, "permission denied: "+perm)
}

// audit records a sensitive action; the actor comes from gateway metadata.
func (h *AuthHandler) audit(ctx context.Context, action, target, detail string) {
	id := grpcutil.FromIncoming(ctx)
	h.auditAs(ctx, id.UserID, id.Email, action, target, detail)
}

// auditAs records an action with an explicit actor (e.g. during login).
func (h *AuthHandler) auditAs(ctx context.Context, actorID, actorEmail, action, target, detail string) {
	if !config.AuditEnabled() {
		return
	}
	_ = h.q.InsertAuditEvent(ctx, db.InsertAuditEventParams{
		ActorID: actorID, ActorEmail: actorEmail, Action: action, Target: target, Detail: detail,
		TenantID: auditTenant(ctx),
	})
}

// auditTenant stamps an audit row with the caller's active tenant so each
// organization's trail is isolated. Pre-tenant events (login/register, before a
// tenant is bound) carry a NULL tenant and never surface in a tenant view.
func auditTenant(ctx context.Context) pgtype.UUID {
	if t, err := activeTenant(ctx); err == nil {
		return pgTenant(t)
	}
	return pgtype.UUID{}
}

// Register creates a user, assigns the default role, and returns the user id.
func (h *AuthHandler) Register(ctx context.Context, req *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {
	if req.GetEmail() == "" || req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "email and password are required")
	}
	hash, err := password.Hash(req.GetPassword())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to hash password")
	}

	// Create user + assign default role atomically.
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "tx begin failed")
	}
	defer tx.Rollback(ctx)
	qtx := h.q.WithTx(tx)

	user, err := qtx.CreateUser(ctx, db.CreateUserParams{Email: req.GetEmail(), PasswordHash: hash})
	if err != nil {
		return nil, status.Error(codes.AlreadyExists, "email already registered")
	}
	if err := qtx.AssignRoleToUser(ctx, db.AssignRoleToUserParams{UserID: user.ID, Name: defaultRole, TenantID: defaultTenantUUID}); err != nil {
		return nil, status.Error(codes.Internal, "failed to assign default role")
	}
	// M6: every new identity joins the default tenant so it can log in. (Tenant-
	// scoped registration / invites refine this in a later phase.)
	if err := qtx.CreateMembership(ctx, db.CreateMembershipParams{UserID: user.ID, TenantID: defaultTenantUUID}); err != nil {
		return nil, status.Error(codes.Internal, "failed to create membership")
	}
	// Enqueue a UserRegistered event in the SAME transaction (outbox pattern).
	// The user service creates the matching profile asynchronously; nothing
	// here calls the user service directly.
	payload, err := json.Marshal(events.UserRegistered{
		UserID: user.ID.String(), Email: user.Email, DisplayName: displayFromEmail(user.Email),
	})
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to encode event")
	}
	if err := qtx.InsertOutbox(ctx, db.InsertOutboxParams{
		AggregateID: user.ID, EventType: events.TypeUserRegistered, Payload: payload,
	}); err != nil {
		return nil, status.Error(codes.Internal, "failed to enqueue event")
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, status.Error(codes.Internal, "tx commit failed")
	}

	h.auditAs(ctx, user.ID.String(), user.Email, "user.register", "", "")
	return &authv1.RegisterResponse{UserId: user.ID.String(), Email: user.Email}, nil
}

// Login verifies credentials and issues an access + refresh token pair.
func (h *AuthHandler) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.TokenPair, error) {
	user, err := h.q.GetUserByEmail(ctx, req.GetEmail())
	if err != nil {
		// Unknown user: still run a hash compare so timing doesn't leak existence.
		password.Verify(h.dummyHash, req.GetPassword())
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}

	// Account lockout: refuse while locked.
	if user.LockedUntil.Valid && user.LockedUntil.Time.After(time.Now()) {
		return nil, status.Error(codes.Unauthenticated, "account temporarily locked, try again later")
	}

	if !password.Verify(user.PasswordHash, req.GetPassword()) {
		if max := config.LoginMaxFailures(); max > 0 {
			if n, ierr := h.q.IncrementLoginFailure(ctx, user.ID); ierr == nil && int(n) >= max {
				_ = h.q.LockUser(ctx, db.LockUserParams{
					ID:          user.ID,
					LockedUntil: pgtype.Timestamptz{Time: time.Now().Add(config.LockoutDuration()), Valid: true},
				})
				h.auditAs(ctx, user.ID.String(), user.Email, "login.locked", "", "too many failed attempts")
			}
		}
		h.auditAs(ctx, user.ID.String(), user.Email, "login.failure", "", "")
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}

	// Optional: require a verified email before allowing login.
	if config.RequireEmailVerification() && !user.EmailVerified {
		return nil, status.Error(codes.Unauthenticated, "email not verified")
	}

	// Soft-deleted identities cannot log in (reported as invalid credentials so
	// account existence isn't leaked).
	if user.DeletedAt.Valid {
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}

	_ = h.q.ResetLoginState(ctx, user.ID)

	// 2FA: when TOTP is enabled the password step alone is not enough. Issue a
	// short-lived MFA token; the client completes login via LoginTotp with a
	// TOTP or recovery code.
	if user.TotpEnabled {
		h.auditAs(ctx, user.ID.String(), user.Email, "login.mfa_challenge", "", "")
		mfaTok, err := h.jwt.IssueMFA(user.ID.String(), mfaTokenTTL)
		if err != nil {
			return nil, status.Error(codes.Internal, "failed to issue mfa token")
		}
		return &authv1.TokenPair{MfaRequired: true, MfaToken: mfaTok, TokenType: "Bearer"}, nil
	}

	h.auditAs(ctx, user.ID.String(), user.Email, "login.success", "", "")
	return h.issueForActiveTenant(ctx, user.ID, user.Email)
}

// mfaTokenTTL bounds how long the password step stays valid while the user
// fetches a TOTP code.
const mfaTokenTTL = 5 * time.Minute

// refreshRotationGrace is how long after a refresh token is rotated a concurrent
// re-presentation of it is still treated as the benign parallel-refresh race
// (re-issue) rather than token theft (family wipe). Short enough to bound replay
// risk; long enough to absorb a client firing several requests at once.
const refreshRotationGrace = 60 * time.Second

// Refresh rotates a valid refresh token for a new token pair.
func (h *AuthHandler) Refresh(ctx context.Context, req *authv1.RefreshRequest) (*authv1.TokenPair, error) {
	hash := hashToken(req.GetRefreshToken())
	row, err := h.q.GetRefreshToken(ctx, hash)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid refresh token")
	}
	if row.RevokedAt.Valid {
		// A token revoked by *rotation* (replaced_by set) and re-presented within
		// the grace window is the benign concurrent-refresh race — e.g. NextAuth
		// firing several requests at once after the access token expires, each
		// refreshing with the same token. Re-issue instead of treating it as theft.
		rotated := row.ReplacedBy != nil && *row.ReplacedBy != ""
		if rotated && time.Since(row.RevokedAt.Time) < refreshRotationGrace {
			user, err := h.q.GetUserByID(ctx, row.UserID)
			if err != nil {
				return nil, status.Error(codes.Unauthenticated, "user not found")
			}
			return h.issueTokens(ctx, user.ID, user.Email, row.TenantID, row.ProjectID)
		}
		// Otherwise (revoked by logout, or rotated outside the grace) genuine
		// reuse suggests theft → revoke the whole token family (defensive).
		_ = h.q.RevokeAllUserRefreshTokens(ctx, row.UserID)
		h.auditAs(ctx, row.UserID.String(), "", "refresh.reuse_detected", "", "all sessions revoked")
		return nil, status.Error(codes.Unauthenticated, "refresh token revoked")
	}
	if row.ExpiresAt.Valid && row.ExpiresAt.Time.Before(time.Now()) {
		return nil, status.Error(codes.Unauthenticated, "refresh token expired")
	}
	user, err := h.q.GetUserByID(ctx, row.UserID)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "user not found")
	}
	// Rotate: issue the fresh pair bound to the same tenant/project, then mark the
	// presented token rotated and point it at its successor (so a concurrent
	// re-presentation hits the grace path above, not the family wipe).
	pair, err := h.issueTokens(ctx, user.ID, user.Email, row.TenantID, row.ProjectID)
	if err != nil {
		return nil, err
	}
	successor := hashToken(pair.RefreshToken)
	_ = h.q.RotateRefreshToken(ctx, db.RotateRefreshTokenParams{TokenHash: hash, ReplacedBy: &successor})
	return pair, nil
}

// Logout revokes the refresh token and denylists the access token (by jti).
func (h *AuthHandler) Logout(ctx context.Context, req *authv1.LogoutRequest) (*authv1.LogoutResponse, error) {
	if err := h.q.RevokeRefreshToken(ctx, hashToken(req.GetRefreshToken())); err != nil {
		return nil, status.Error(codes.Internal, "failed to revoke token")
	}
	// Best-effort: denylist the access token so it stops working immediately.
	if at := req.GetAccessToken(); at != "" {
		if claims, err := h.jwt.Parse(at); err == nil && claims.ID != "" && claims.ExpiresAt != nil {
			_ = h.q.RevokeAccessJTI(ctx, db.RevokeAccessJTIParams{
				Jti:       claims.ID,
				ExpiresAt: pgtype.Timestamptz{Time: claims.ExpiresAt.Time, Valid: true},
			})
			// Mirror into the Redis denylist so other replicas reject it at once.
			h.cache.Deny(ctx, claims.ID, time.Until(claims.ExpiresAt.Time))
		}
	}
	h.audit(ctx, "auth.logout", "", "")
	return &authv1.LogoutResponse{Success: true}, nil
}

// ValidateToken verifies an access token and returns the caller's roles + permissions.
func (h *AuthHandler) ValidateToken(ctx context.Context, req *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
	claims, err := h.jwt.Parse(req.GetAccessToken())
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid or expired token")
	}
	// An MFA-purpose token only completes a 2FA login; it is not a bearer token.
	if claims.Purpose != "" {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}
	if claims.ID != "" {
		// Prefer the Redis denylist (shared across replicas); fall back to the
		// durable Postgres denylist when Redis is off or errors.
		if denied, ok := h.cache.IsDenied(ctx, claims.ID); ok {
			if denied {
				return nil, status.Error(codes.Unauthenticated, "token revoked")
			}
		} else {
			revoked, err := h.q.IsTokenRevoked(ctx, claims.ID)
			if err != nil {
				return nil, status.Error(codes.Internal, "failed to check token status")
			}
			if revoked {
				return nil, status.Error(codes.Unauthenticated, "token revoked")
			}
		}
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid subject")
	}
	// Reject tokens for a soft-deleted (or removed) identity.
	active, err := h.q.IsUserActive(ctx, userID)
	if err != nil || !active {
		return nil, status.Error(codes.Unauthenticated, "account is not active")
	}
	// M6: the token is bound to a tenant — verify the user is still an active
	// member (so removing a membership invalidates their tokens for it).
	if claims.TenantID != "" {
		tid, perr := uuid.Parse(claims.TenantID)
		if perr != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid tenant")
		}
		member, merr := h.q.IsActiveMember(ctx, db.IsActiveMemberParams{UserID: userID, TenantID: tid})
		if merr != nil || !member {
			return nil, status.Error(codes.Unauthenticated, "tenant membership revoked")
		}
	}
	// M6.3: roles/permissions are scoped to the token's tenant (+ optional
	// project) — the same user can hold different roles in different tenants.
	// A token without a tenant claim (legacy) falls back to the global view.
	var roles []string
	if claims.TenantID != "" {
		tid, perr := uuid.Parse(claims.TenantID)
		if perr != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid tenant")
		}
		proj := parseOptionalUUID(claims.ProjectID)
		roles, err = h.q.GetUserRolesScoped(ctx, db.GetUserRolesScopedParams{UserID: userID, TenantID: tid, ProjectID: proj})
	} else {
		roles, err = h.q.GetUserRoles(ctx, userID)
	}
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to load roles")
	}
	// Permission cache (Redis, short TTL) cuts the RBAC join off the hot path
	// of every authenticated request; misses fall back to Postgres. The key is
	// scoped to tenant/project so a tenant switch can't read stale perms.
	perms, hit := h.cache.GetPerms(ctx, claims.TenantID, claims.ProjectID, claims.Subject)
	if !hit {
		if claims.TenantID != "" {
			tid, _ := uuid.Parse(claims.TenantID)
			proj := parseOptionalUUID(claims.ProjectID)
			perms, err = h.q.GetUserPermissionsScoped(ctx, db.GetUserPermissionsScopedParams{UserID: userID, TenantID: tid, ProjectID: proj})
		} else {
			perms, err = h.q.GetUserPermissions(ctx, userID)
		}
		if err != nil {
			return nil, status.Error(codes.Internal, "failed to load permissions")
		}
		h.cache.SetPerms(ctx, claims.TenantID, claims.ProjectID, claims.Subject, perms)
	}
	return &authv1.ValidateTokenResponse{
		UserId:      claims.Subject,
		Email:       claims.Email,
		Roles:       roles,
		Permissions: perms,
		TenantId:    claims.TenantID,
		ProjectId:   claims.ProjectID,
	}, nil
}

// DeleteUser removes the identity entirely (FK cascade drops roles & refresh
// tokens). Requires user:delete.
func (h *AuthHandler) DeleteUser(ctx context.Context, req *authv1.DeleteUserRequest) (*authv1.DeleteUserResponse, error) {
	if err := requirePerm(ctx, "user:delete"); err != nil {
		return nil, err
	}
	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}
	// Delete the identity and enqueue a UserDeleted event in one transaction;
	// the user service drops the matching profile asynchronously.
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "tx begin failed")
	}
	defer tx.Rollback(ctx)
	qtx := h.q.WithTx(tx)
	// Hard delete removes the row entirely (FK cascade); the default soft delete
	// just stamps deleted_at so the identity can be restored.
	if req.GetHard() {
		if err := qtx.DeleteUser(ctx, userID); err != nil {
			return nil, status.Error(codes.Internal, "failed to delete user")
		}
	} else {
		if err := qtx.SoftDeleteUser(ctx, userID); err != nil {
			return nil, status.Error(codes.Internal, "failed to delete user")
		}
		// Revoke active sessions so a soft-deleted user is logged out everywhere.
		_ = qtx.RevokeAllUserRefreshTokens(ctx, userID)
	}
	payload, err := json.Marshal(events.UserDeleted{UserID: userID.String(), Hard: req.GetHard()})
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to encode event")
	}
	if err := qtx.InsertOutbox(ctx, db.InsertOutboxParams{
		AggregateID: userID, EventType: events.TypeUserDeleted, Payload: payload,
	}); err != nil {
		return nil, status.Error(codes.Internal, "failed to enqueue event")
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, status.Error(codes.Internal, "tx commit failed")
	}
	h.audit(ctx, "user.delete", req.GetUserId(), map[bool]string{true: "hard", false: "soft"}[req.GetHard()])
	return &authv1.DeleteUserResponse{Success: true}, nil
}

// displayFromEmail derives a default display name from the local part of an
// email (the same rule the gateway uses when lazily healing a missing profile).
func displayFromEmail(emailAddr string) string {
	if i := strings.Index(emailAddr, "@"); i > 0 {
		return emailAddr[:i]
	}
	return emailAddr
}

// ── RBAC management ─────────────────────────────────────────

func (h *AuthHandler) CreateRole(ctx context.Context, req *authv1.CreateRoleRequest) (*authv1.Role, error) {
	if err := requirePerm(ctx, "role:write"); err != nil {
		return nil, err
	}
	tenant, err := activeTenant(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "role name is required")
	}
	if isBuiltinRole(req.GetName()) {
		return nil, status.Error(codes.FailedPrecondition, "name reserved for a built-in role")
	}
	// Custom roles belong to the active tenant (never a NULL-tenant template).
	// The write runs inside an iam_rls transaction so RLS WITH CHECK enforces the
	// tenant binding at the database, not just the query's own tenant_id.
	var role db.CreateRoleRow
	if err := h.withTenant(ctx, tenant, func(q *db.Queries) error {
		var e error
		role, e = q.CreateRole(ctx, db.CreateRoleParams{Name: req.GetName(), Description: req.GetDescription(), TenantID: pgTenant(tenant)})
		return e
	}); err != nil {
		return nil, status.Error(codes.AlreadyExists, "role already exists")
	}
	h.audit(ctx, "role.create", req.GetName(), "")
	return &authv1.Role{Id: role.ID, Name: role.Name, Description: role.Description}, nil
}

func (h *AuthHandler) UpdateRole(ctx context.Context, req *authv1.UpdateRoleRequest) (*authv1.Role, error) {
	if err := requirePerm(ctx, "role:write"); err != nil {
		return nil, err
	}
	tenant, err := activeTenant(ctx)
	if err != nil {
		return nil, err
	}
	if isBuiltinRole(req.GetName()) {
		return nil, status.Error(codes.FailedPrecondition, "cannot modify a built-in role")
	}
	var role db.UpdateRoleRow
	if err := h.withTenant(ctx, tenant, func(q *db.Queries) error {
		var e error
		role, e = q.UpdateRole(ctx, db.UpdateRoleParams{Name: req.GetName(), Description: req.GetDescription(), TenantID: pgTenant(tenant)})
		return e
	}); err != nil {
		return nil, status.Error(codes.NotFound, "role not found in this tenant")
	}
	return &authv1.Role{Id: role.ID, Name: role.Name, Description: role.Description}, nil
}

func (h *AuthHandler) DeleteRole(ctx context.Context, req *authv1.DeleteRoleRequest) (*authv1.DeleteRoleResponse, error) {
	if err := requirePerm(ctx, "role:write"); err != nil {
		return nil, err
	}
	tenant, err := activeTenant(ctx)
	if err != nil {
		return nil, err
	}
	if isBuiltinRole(req.GetName()) {
		return nil, status.Error(codes.FailedPrecondition, "cannot delete a built-in role")
	}
	if _, err := h.q.GetTenantRole(ctx, db.GetTenantRoleParams{Name: req.GetName(), TenantID: pgTenant(tenant)}); err != nil {
		return nil, status.Error(codes.NotFound, "role not found in this tenant")
	}
	if err := h.withTenant(ctx, tenant, func(q *db.Queries) error {
		return q.DeleteRole(ctx, db.DeleteRoleParams{Name: req.GetName(), TenantID: pgTenant(tenant)})
	}); err != nil {
		return nil, status.Error(codes.Internal, "failed to delete role")
	}
	h.audit(ctx, "role.delete", req.GetName(), "")
	return &authv1.DeleteRoleResponse{Success: true}, nil
}

func (h *AuthHandler) ListRoles(ctx context.Context, _ *authv1.ListRolesRequest) (*authv1.ListRolesResponse, error) {
	if err := requirePerm(ctx, "role:read"); err != nil {
		return nil, err
	}
	tenant, err := activeTenant(ctx)
	if err != nil {
		return nil, err
	}
	// The tenant's own roles + shared built-in templates, aggregated — no N+1.
	roles, err := h.q.ListRolesWithPermissions(ctx, pgTenant(tenant))
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to list roles")
	}
	out := make([]*authv1.Role, 0, len(roles))
	for _, r := range roles {
		out = append(out, &authv1.Role{Id: r.ID, Name: r.Name, Description: r.Description, Permissions: r.Permissions})
	}
	return &authv1.ListRolesResponse{Roles: out}, nil
}

func (h *AuthHandler) AssignRole(ctx context.Context, req *authv1.AssignRoleRequest) (*authv1.AssignRoleResponse, error) {
	if err := requirePerm(ctx, "role:assign"); err != nil {
		return nil, err
	}
	tenant, err := activeTenant(ctx)
	if err != nil {
		return nil, err
	}
	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}
	if err := h.validateAssign(ctx, req.GetRoleName(), req.GetProjectId(), tenant); err != nil {
		return nil, err
	}
	if err := h.withTenant(ctx, tenant, func(q *db.Queries) error {
		return q.AssignRoleToUser(ctx, db.AssignRoleToUserParams{UserID: userID, Name: req.GetRoleName(), TenantID: tenant, ProjectID: parseOptionalUUID(req.GetProjectId())})
	}); err != nil {
		return nil, status.Error(codes.Internal, "failed to assign role")
	}
	h.cache.InvalidatePerms(ctx, req.GetUserId())
	h.audit(ctx, "role.assign", req.GetUserId(), req.GetRoleName())
	return &authv1.AssignRoleResponse{Success: true}, nil
}

// AssignRoleBulk assigns one role to many users; returns the count assigned and
// the user_ids that failed (invalid id or assignment error). Partial success is
// allowed — valid users still get the role even if some ids are bad.
func (h *AuthHandler) AssignRoleBulk(ctx context.Context, req *authv1.AssignRoleBulkRequest) (*authv1.AssignRoleBulkResponse, error) {
	if err := requirePerm(ctx, "role:assign"); err != nil {
		return nil, err
	}
	tenant, err := activeTenant(ctx)
	if err != nil {
		return nil, err
	}
	bulkProject := parseOptionalUUID(req.GetProjectId())
	if err := h.validateAssign(ctx, req.GetRoleName(), req.GetProjectId(), tenant); err != nil {
		return nil, err
	}
	var assigned int32
	var failed []string
	for _, uid := range req.GetUserIds() {
		userID, err := uuid.Parse(uid)
		if err != nil {
			failed = append(failed, uid)
			continue
		}
		if err := h.withTenant(ctx, tenant, func(q *db.Queries) error {
			return q.AssignRoleToUser(ctx, db.AssignRoleToUserParams{UserID: userID, Name: req.GetRoleName(), TenantID: tenant, ProjectID: bulkProject})
		}); err != nil {
			failed = append(failed, uid)
			continue
		}
		h.cache.InvalidatePerms(ctx, uid)
		assigned++
	}
	h.audit(ctx, "role.assign_bulk", req.GetRoleName(), fmt.Sprintf("%d assigned, %d failed", assigned, len(failed)))
	return &authv1.AssignRoleBulkResponse{Assigned: assigned, Failed: failed}, nil
}

func (h *AuthHandler) RevokeRole(ctx context.Context, req *authv1.RevokeRoleRequest) (*authv1.RevokeRoleResponse, error) {
	if err := requirePerm(ctx, "role:assign"); err != nil {
		return nil, err
	}
	tenant, err := activeTenant(ctx)
	if err != nil {
		return nil, err
	}
	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}
	if _, err := h.q.GetRoleByName(ctx, req.GetRoleName()); err != nil {
		return nil, status.Error(codes.NotFound, "role not found")
	}
	if err := h.withTenant(ctx, tenant, func(q *db.Queries) error {
		return q.RevokeRoleFromUser(ctx, db.RevokeRoleFromUserParams{UserID: userID, Name: req.GetRoleName(), TenantID: tenant, ProjectID: parseOptionalUUID(req.GetProjectId())})
	}); err != nil {
		return nil, status.Error(codes.Internal, "failed to revoke role")
	}
	h.cache.InvalidatePerms(ctx, req.GetUserId())
	h.audit(ctx, "role.revoke", req.GetUserId(), req.GetRoleName())
	return &authv1.RevokeRoleResponse{Success: true}, nil
}

func (h *AuthHandler) ListPermissions(ctx context.Context, _ *authv1.ListPermissionsRequest) (*authv1.ListPermissionsResponse, error) {
	if err := requirePerm(ctx, "role:read"); err != nil {
		return nil, err
	}
	perms, err := h.q.ListPermissions(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to list permissions")
	}
	out := make([]*authv1.Permission, 0, len(perms))
	for _, p := range perms {
		out = append(out, &authv1.Permission{Id: p.ID, Name: p.Name, Description: p.Description})
	}
	return &authv1.ListPermissionsResponse{Permissions: out}, nil
}

// permRoleGuard validates a permission grant/revoke target: must be one of the
// tenant's OWN roles (built-in templates are platform-managed, shared across
// tenants, and must not be mutable from a tenant context).
func (h *AuthHandler) permRoleGuard(ctx context.Context, roleName string, tenant uuid.UUID) error {
	if isBuiltinRole(roleName) {
		return status.Error(codes.FailedPrecondition, "cannot modify a built-in role's permissions")
	}
	if _, err := h.q.GetTenantRole(ctx, db.GetTenantRoleParams{Name: roleName, TenantID: pgTenant(tenant)}); err != nil {
		return status.Error(codes.NotFound, "role not found in this tenant")
	}
	return nil
}

func (h *AuthHandler) GrantPermission(ctx context.Context, req *authv1.GrantPermissionRequest) (*authv1.GrantPermissionResponse, error) {
	if err := requirePerm(ctx, "role:write"); err != nil {
		return nil, err
	}
	tenant, err := activeTenant(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.permRoleGuard(ctx, req.GetRoleName(), tenant); err != nil {
		return nil, err
	}
	if err := h.withTenant(ctx, tenant, func(q *db.Queries) error {
		return q.GrantPermissionToRole(ctx, db.GrantPermissionToRoleParams{Name: req.GetRoleName(), Name_2: req.GetPermissionName(), TenantID: pgTenant(tenant)})
	}); err != nil {
		return nil, status.Error(codes.Internal, "failed to grant permission")
	}
	h.audit(ctx, "permission.grant", req.GetRoleName(), req.GetPermissionName())
	return &authv1.GrantPermissionResponse{Success: true}, nil
}

func (h *AuthHandler) RevokePermission(ctx context.Context, req *authv1.RevokePermissionRequest) (*authv1.RevokePermissionResponse, error) {
	if err := requirePerm(ctx, "role:write"); err != nil {
		return nil, err
	}
	tenant, err := activeTenant(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.permRoleGuard(ctx, req.GetRoleName(), tenant); err != nil {
		return nil, err
	}
	if err := h.withTenant(ctx, tenant, func(q *db.Queries) error {
		return q.RevokePermissionFromRole(ctx, db.RevokePermissionFromRoleParams{Name: req.GetRoleName(), Name_2: req.GetPermissionName(), TenantID: pgTenant(tenant)})
	}); err != nil {
		return nil, status.Error(codes.Internal, "failed to revoke permission")
	}
	h.audit(ctx, "permission.revoke", req.GetRoleName(), req.GetPermissionName())
	return &authv1.RevokePermissionResponse{Success: true}, nil
}

// ── Account recovery & verification (v0.2) ──────────────────

func (h *AuthHandler) RequestEmailVerification(ctx context.Context, req *authv1.EmailRequest) (*authv1.DevTokenResponse, error) {
	resp := &authv1.DevTokenResponse{Success: true}
	user, err := h.q.GetUserByEmail(ctx, req.GetEmail())
	if err != nil {
		return resp, nil // don't reveal whether the email exists
	}
	token, err := newRefreshToken()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate token")
	}
	exp := pgtype.Timestamptz{Time: time.Now().Add(24 * time.Hour), Valid: true}
	if err := h.q.CreateEmailVerification(ctx, db.CreateEmailVerificationParams{
		TokenHash: hashToken(token), UserID: user.ID, ExpiresAt: exp,
	}); err != nil {
		return nil, status.Error(codes.Internal, "failed to create verification")
	}
	h.mail.Send(user.Email, "Verify your email", "Your email verification token: "+token)
	h.auditAs(ctx, user.ID.String(), user.Email, "email.verification_requested", "", "")
	if !config.IsProduction() {
		resp.DevToken = token
	}
	return resp, nil
}

func (h *AuthHandler) VerifyEmail(ctx context.Context, req *authv1.TokenRequest) (*authv1.GenericResponse, error) {
	uid, err := h.q.ConsumeEmailVerification(ctx, hashToken(req.GetToken()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid or expired token")
	}
	if err := h.q.MarkEmailVerified(ctx, uid); err != nil {
		return nil, status.Error(codes.Internal, "failed to verify email")
	}
	h.auditAs(ctx, uid.String(), "", "email.verified", "", "")
	return &authv1.GenericResponse{Success: true}, nil
}

func (h *AuthHandler) RequestPasswordReset(ctx context.Context, req *authv1.EmailRequest) (*authv1.DevTokenResponse, error) {
	resp := &authv1.DevTokenResponse{Success: true}
	user, err := h.q.GetUserByEmail(ctx, req.GetEmail())
	if err != nil {
		return resp, nil // don't reveal whether the email exists
	}
	token, err := newRefreshToken()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate token")
	}
	exp := pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}
	if err := h.q.CreatePasswordReset(ctx, db.CreatePasswordResetParams{
		TokenHash: hashToken(token), UserID: user.ID, ExpiresAt: exp,
	}); err != nil {
		return nil, status.Error(codes.Internal, "failed to create reset token")
	}
	h.mail.Send(user.Email, "Reset your password", "Your password reset token: "+token)
	h.auditAs(ctx, user.ID.String(), user.Email, "password.reset_requested", "", "")
	if !config.IsProduction() {
		resp.DevToken = token
	}
	return resp, nil
}

func (h *AuthHandler) ResetPassword(ctx context.Context, req *authv1.ResetPasswordRequest) (*authv1.GenericResponse, error) {
	if len(req.GetNewPassword()) < 8 {
		return nil, status.Error(codes.InvalidArgument, "password must be at least 8 characters")
	}
	uid, err := h.q.ConsumePasswordReset(ctx, hashToken(req.GetToken()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid or expired token")
	}
	hash, err := password.Hash(req.GetNewPassword())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to hash password")
	}
	if err := h.q.UpdatePassword(ctx, db.UpdatePasswordParams{ID: uid, PasswordHash: hash}); err != nil {
		return nil, status.Error(codes.Internal, "failed to update password")
	}
	_ = h.q.RevokeAllUserRefreshTokens(ctx, uid) // force re-login everywhere
	h.auditAs(ctx, uid.String(), "", "password.reset", "", "")
	return &authv1.GenericResponse{Success: true}, nil
}

// ChangePassword lets an authenticated caller rotate their own password by
// proving the current one — no email/reset-token round-trip. All refresh tokens
// are revoked so other sessions must re-authenticate.
func (h *AuthHandler) ChangePassword(ctx context.Context, req *authv1.ChangePasswordRequest) (*authv1.GenericResponse, error) {
	uid, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	if len(req.GetNewPassword()) < 8 {
		return nil, status.Error(codes.InvalidArgument, "password must be at least 8 characters")
	}
	user, err := h.q.GetUserByID(ctx, uid)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "user not found")
	}
	if !password.Verify(user.PasswordHash, req.GetOldPassword()) {
		return nil, status.Error(codes.Unauthenticated, "current password is incorrect")
	}
	hash, err := password.Hash(req.GetNewPassword())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to hash password")
	}
	if err := h.q.UpdatePassword(ctx, db.UpdatePasswordParams{ID: uid, PasswordHash: hash}); err != nil {
		return nil, status.Error(codes.Internal, "failed to update password")
	}
	_ = h.q.RevokeAllUserRefreshTokens(ctx, uid) // force re-login everywhere
	h.auditAs(ctx, uid.String(), user.Email, "password.change", "", "")
	return &authv1.GenericResponse{Success: true}, nil
}

// ── Audit (v0.2) ────────────────────────────────────────────

func (h *AuthHandler) ListAuditEvents(ctx context.Context, req *authv1.ListAuditEventsRequest) (*authv1.ListAuditEventsResponse, error) {
	if err := requirePerm(ctx, "audit:read"); err != nil {
		return nil, err
	}
	tenant, err := activeTenant(ctx)
	if err != nil {
		return nil, err
	}
	limit := req.GetLimit()
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := h.q.ListAuditEvents(ctx, db.ListAuditEventsParams{TenantID: pgTenant(tenant), Limit: limit})
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to list audit events")
	}
	out := make([]*authv1.AuditEvent, 0, len(rows))
	for _, e := range rows {
		created := ""
		if e.CreatedAt.Valid {
			created = e.CreatedAt.Time.UTC().Format("2006-01-02T15:04:05Z07:00")
		}
		out = append(out, &authv1.AuditEvent{
			Id: e.ID, ActorId: e.ActorID, ActorEmail: e.ActorEmail,
			Action: e.Action, Target: e.Target, Detail: e.Detail, CreatedAt: created,
		})
	}
	return &authv1.ListAuditEventsResponse{Events: out}, nil
}

func isBuiltinRole(name string) bool {
	return name == "admin" || name == "user"
}

// ── helpers ─────────────────────────────────────────────────

// defaultTenantID matches the seed in migration 000010 (shared across stacks).
const defaultTenantID = "00000000-0000-0000-0000-000000000001"

var defaultTenantUUID = uuid.MustParse(defaultTenantID)

// issueTokens signs an access token bound to (tenant, project) and persists a
// refresh token carrying the same binding (so refresh re-issues for it).
func (h *AuthHandler) issueTokens(ctx context.Context, userID uuid.UUID, email string, tenantID uuid.UUID, projectID pgtype.UUID) (*authv1.TokenPair, error) {
	projStr := ""
	if projectID.Valid {
		projStr = uuid.UUID(projectID.Bytes).String()
	}
	access, err := h.jwt.Issue(userID.String(), email, tenantID.String(), projStr)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to sign token")
	}
	refresh, err := newRefreshToken()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate refresh token")
	}
	expires := pgtype.Timestamptz{Time: time.Now().Add(h.refreshTTL), Valid: true}
	if _, err := h.q.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
		UserID: userID, TokenHash: hashToken(refresh), ExpiresAt: expires,
		TenantID: tenantID, ProjectID: projectID,
	}); err != nil {
		return nil, status.Error(codes.Internal, "failed to persist refresh token")
	}
	return &authv1.TokenPair{
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresIn:    int64(h.jwt.AccessTTL().Seconds()),
		TokenType:    "Bearer",
	}, nil
}

// issueForActiveTenant picks the user's first active membership (tenant-wide,
// no project) and issues a token bound to it.
func (h *AuthHandler) issueForActiveTenant(ctx context.Context, userID uuid.UUID, email string) (*authv1.TokenPair, error) {
	members, err := h.q.ListMembershipsByUser(ctx, userID)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to load memberships")
	}
	if len(members) == 0 {
		return nil, status.Error(codes.PermissionDenied, "user has no tenant membership")
	}
	return h.issueTokens(ctx, userID, email, members[0].TenantID, pgtype.UUID{})
}

func newRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
