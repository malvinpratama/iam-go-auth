package handler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/malvinpratama/iam-go-auth/internal/db"
	"github.com/malvinpratama/iam-go-auth/internal/totp"
	authv1 "github.com/malvinpratama/iam-go-contracts/gen/auth/v1"
	"github.com/malvinpratama/iam-go-libs/config"
	"github.com/malvinpratama/iam-go-libs/events"
	"github.com/malvinpratama/iam-go-libs/grpcutil"
)

const recoveryCodeCount = 10

// callerID extracts the authenticated user id from gateway-supplied metadata.
func callerID(ctx context.Context) (uuid.UUID, error) {
	id := grpcutil.FromIncoming(ctx)
	uid, err := uuid.Parse(id.UserID)
	if err != nil {
		return uuid.Nil, status.Error(codes.Unauthenticated, "missing or invalid caller identity")
	}
	return uid, nil
}

// ── 2FA / TOTP (v0.9) ───────────────────────────────────────

// EnrollTotp generates a fresh TOTP secret + recovery codes for the caller. The
// secret is stored but not active until ActivateTotp succeeds.
func (h *AuthHandler) EnrollTotp(ctx context.Context, _ *authv1.EnrollTotpRequest) (*authv1.EnrollTotpResponse, error) {
	uid, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	user, err := h.q.GetUserByID(ctx, uid)
	if err != nil {
		return nil, status.Error(codes.NotFound, "user not found")
	}
	// Re-enrolling would reset the secret and silently disable working 2FA;
	// require an explicit disable first.
	if user.TotpEnabled {
		return nil, status.Error(codes.FailedPrecondition, "2FA is already enabled; disable it first")
	}
	secret, err := totp.Generate(user.Email)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate secret")
	}
	recoveryCodes, err := totp.GenerateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate recovery codes")
	}
	// Encrypt the shared secret before it touches the DB (TS3). The plaintext is
	// still returned to the caller below so they can add it to their authenticator.
	stored, err := h.totpEnc.Encrypt(secret.Base32)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to encrypt secret")
	}
	if err := h.q.SetTotpSecret(ctx, db.SetTotpSecretParams{ID: uid, TotpSecret: &stored}); err != nil {
		return nil, status.Error(codes.Internal, "failed to store secret")
	}
	// Replace any previous (now stale) recovery codes.
	_ = h.q.DeleteRecoveryCodes(ctx, uid)
	for _, c := range recoveryCodes {
		if err := h.q.InsertRecoveryCode(ctx, db.InsertRecoveryCodeParams{UserID: uid, CodeHash: hashToken(c)}); err != nil {
			return nil, status.Error(codes.Internal, "failed to store recovery code")
		}
	}
	h.audit(ctx, "totp.enroll", "", "")
	return &authv1.EnrollTotpResponse{Secret: secret.Base32, OtpauthUri: secret.OtpauthURI, RecoveryCodes: recoveryCodes}, nil
}

// GetTotpStatus reports whether 2FA is active for the caller.
func (h *AuthHandler) GetTotpStatus(ctx context.Context, _ *authv1.GetTotpStatusRequest) (*authv1.GetTotpStatusResponse, error) {
	uid, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	user, err := h.q.GetUserByID(ctx, uid)
	if err != nil {
		return nil, status.Error(codes.NotFound, "user not found")
	}
	return &authv1.GetTotpStatusResponse{Enabled: user.TotpEnabled}, nil
}

// ActivateTotp turns on 2FA after the caller proves the authenticator works.
func (h *AuthHandler) ActivateTotp(ctx context.Context, req *authv1.ActivateTotpRequest) (*authv1.GenericResponse, error) {
	uid, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	user, err := h.q.GetUserByID(ctx, uid)
	if err != nil {
		return nil, status.Error(codes.NotFound, "user not found")
	}
	if user.TotpSecret == nil {
		return nil, status.Error(codes.FailedPrecondition, "no pending enrollment; call EnrollTotp first")
	}
	secret, err := h.totpEnc.Decrypt(*user.TotpSecret)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to read secret")
	}
	if !totp.Validate(req.GetCode(), secret) {
		return nil, status.Error(codes.Unauthenticated, "invalid code")
	}
	if err := h.q.EnableTotp(ctx, uid); err != nil {
		return nil, status.Error(codes.Internal, "failed to enable 2FA")
	}
	h.audit(ctx, "totp.activate", "", "")
	return &authv1.GenericResponse{Success: true}, nil
}

// DisableTotp turns off 2FA after verifying a current TOTP or recovery code.
func (h *AuthHandler) DisableTotp(ctx context.Context, req *authv1.DisableTotpRequest) (*authv1.GenericResponse, error) {
	uid, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	user, err := h.q.GetUserByID(ctx, uid)
	if err != nil {
		return nil, status.Error(codes.NotFound, "user not found")
	}
	if !user.TotpEnabled {
		return &authv1.GenericResponse{Success: true}, nil // already off
	}
	ok := false
	if user.TotpSecret != nil {
		if secret, derr := h.totpEnc.Decrypt(*user.TotpSecret); derr == nil {
			ok = totp.Validate(req.GetCode(), secret)
		}
	}
	if !ok && !h.consumeRecoveryCode(ctx, uid, req.GetCode()) {
		return nil, status.Error(codes.Unauthenticated, "invalid code")
	}
	if err := h.q.DisableTotp(ctx, uid); err != nil {
		return nil, status.Error(codes.Internal, "failed to disable 2FA")
	}
	_ = h.q.DeleteRecoveryCodes(ctx, uid)
	h.audit(ctx, "totp.disable", "", "")
	return &authv1.GenericResponse{Success: true}, nil
}

// LoginTotp completes a 2FA login: validate the MFA token from the password
// step plus a TOTP or recovery code, then issue real tokens.
func (h *AuthHandler) LoginTotp(ctx context.Context, req *authv1.LoginTotpRequest) (*authv1.TokenPair, error) {
	claims, err := h.jwt.Parse(req.GetMfaToken())
	if err != nil || claims.Purpose != "mfa" {
		return nil, status.Error(codes.Unauthenticated, "invalid or expired mfa token")
	}
	uid, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid mfa token")
	}
	user, err := h.q.GetUserByID(ctx, uid)
	if err != nil || user.DeletedAt.Valid || !user.TotpEnabled || user.TotpSecret == nil {
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}
	// The MFA step is brute-forceable (6-digit TOTP / recovery codes) within the
	// MFA token's TTL, so it gets the same lockout as the password step.
	if user.LockedUntil.Valid && user.LockedUntil.Time.After(time.Now()) {
		return nil, status.Error(codes.Unauthenticated, "account temporarily locked, try again later")
	}
	secret, derr := h.totpEnc.Decrypt(*user.TotpSecret)
	ok := derr == nil && totp.Validate(req.GetCode(), secret)
	if !ok && !h.consumeRecoveryCode(ctx, uid, req.GetCode()) {
		if max := config.LoginMaxFailures(); max > 0 {
			if n, ierr := h.q.IncrementLoginFailure(ctx, uid); ierr == nil && int(n) >= max {
				_ = h.q.LockUser(ctx, db.LockUserParams{
					ID:          uid,
					LockedUntil: pgtype.Timestamptz{Time: time.Now().Add(config.LockoutDuration()), Valid: true},
				})
				h.auditAs(ctx, uid.String(), user.Email, "login.locked", "", "too many failed mfa attempts")
			}
		}
		h.auditAs(ctx, uid.String(), user.Email, "login.mfa_failure", "", "")
		return nil, status.Error(codes.Unauthenticated, "invalid code")
	}
	_ = h.q.ResetLoginState(ctx, uid) // clear the failure counter on success
	h.auditAs(ctx, uid.String(), user.Email, "login.success", "", "2fa")
	return h.issueForActiveTenant(ctx, uid, user.Email)
}

// consumeRecoveryCode atomically spends a one-time recovery code; true on success.
func (h *AuthHandler) consumeRecoveryCode(ctx context.Context, uid uuid.UUID, code string) bool {
	_, err := h.q.ConsumeRecoveryCode(ctx, db.ConsumeRecoveryCodeParams{UserID: uid, CodeHash: hashToken(code)})
	return err == nil
}

// ── API keys (v0.9) ─────────────────────────────────────────

// CreateApiKey mints a scoped API key. The requested scopes must be a subset of
// the caller's own permissions; the full secret is returned exactly once.
func (h *AuthHandler) CreateApiKey(ctx context.Context, req *authv1.CreateApiKeyRequest) (*authv1.CreateApiKeyResponse, error) {
	id := grpcutil.FromIncoming(ctx)
	uid, err := uuid.Parse(id.UserID)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "missing or invalid caller identity")
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	for _, s := range req.GetScopes() {
		if !id.HasPermission(s) {
			return nil, status.Error(codes.PermissionDenied, "cannot grant a scope you do not hold: "+s)
		}
	}
	keyID, err := randToken(8)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate key")
	}
	secret, err := randToken(24)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate key")
	}
	full := "iamk_" + keyID + "_" + secret

	var expires pgtype.Timestamptz
	if ttl := req.GetTtlSeconds(); ttl > 0 {
		expires = pgtype.Timestamptz{Time: time.Now().Add(time.Duration(ttl) * time.Second), Valid: true}
	}
	// Bind the key to the tenant (+ optional project) it is minted in, so its
	// effective permissions can never exceed the owner's access in that tenant.
	tenant, err := activeTenant(ctx)
	if err != nil {
		return nil, err
	}
	project := parseOptionalUUID(id.ProjectID)
	if err := h.q.CreateApiKey(ctx, db.CreateApiKeyParams{
		ID: keyID, UserID: uid, KeyHash: hashToken(full),
		Name: req.GetName(), Scopes: req.GetScopes(), ExpiresAt: expires,
		TenantID: tenant, ProjectID: project,
	}); err != nil {
		return nil, status.Error(codes.Internal, "failed to create api key")
	}
	h.audit(ctx, "apikey.create", keyID, req.GetName())
	return &authv1.CreateApiKeyResponse{
		Secret: full,
		Key: &authv1.ApiKey{
			Id: keyID, Name: req.GetName(), Scopes: req.GetScopes(),
			CreatedAt: time.Now().UTC().Format(time.RFC3339), ExpiresAt: tsString(expires),
		},
	}, nil
}

// ListApiKeys returns the caller's active API keys (metadata only, never secrets).
func (h *AuthHandler) ListApiKeys(ctx context.Context, _ *authv1.ListApiKeysRequest) (*authv1.ListApiKeysResponse, error) {
	id := grpcutil.FromIncoming(ctx)
	uid, err := uuid.Parse(id.UserID)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "missing or invalid caller identity")
	}
	rows, err := h.q.ListApiKeysByUser(ctx, uid)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to list api keys")
	}
	out := make([]*authv1.ApiKey, 0, len(rows))
	for _, r := range rows {
		out = append(out, &authv1.ApiKey{
			Id: r.ID, Name: r.Name, Scopes: r.Scopes,
			CreatedAt: tsString(r.CreatedAt), ExpiresAt: tsString(r.ExpiresAt), LastUsedAt: tsString(r.LastUsedAt),
		})
	}
	return &authv1.ListApiKeysResponse{Keys: out}, nil
}

// RevokeApiKey revokes one of the caller's keys.
func (h *AuthHandler) RevokeApiKey(ctx context.Context, req *authv1.RevokeApiKeyRequest) (*authv1.GenericResponse, error) {
	id := grpcutil.FromIncoming(ctx)
	uid, err := uuid.Parse(id.UserID)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "missing or invalid caller identity")
	}
	if err := h.q.RevokeApiKey(ctx, db.RevokeApiKeyParams{ID: req.GetId(), UserID: uid}); err != nil {
		return nil, status.Error(codes.Internal, "failed to revoke api key")
	}
	h.audit(ctx, "apikey.revoke", req.GetId(), "")
	return &authv1.GenericResponse{Success: true}, nil
}

// ValidateApiKey is called by the gateway for iamk_ bearer tokens. It returns
// the owner plus the effective scopes (requested ∩ the owner's current perms),
// so revoking a role immediately narrows every key that depended on it.
func (h *AuthHandler) ValidateApiKey(ctx context.Context, req *authv1.ValidateApiKeyRequest) (*authv1.ValidateApiKeyResponse, error) {
	row, err := h.q.GetApiKeyByHash(ctx, hashToken(req.GetApiKey()))
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid api key")
	}
	if row.RevokedAt.Valid {
		return nil, status.Error(codes.Unauthenticated, "api key revoked")
	}
	if row.ExpiresAt.Valid && row.ExpiresAt.Time.Before(time.Now()) {
		return nil, status.Error(codes.Unauthenticated, "api key expired")
	}
	user, err := h.q.GetUserByID(ctx, row.UserID)
	if err != nil || user.DeletedAt.Valid {
		return nil, status.Error(codes.Unauthenticated, "invalid api key")
	}
	// The key only carries the permissions its owner still holds in the tenant it
	// was minted in. If that membership (or the tenant) was deactivated, the key
	// is dead — this prevents a key from granting cross-tenant or stale access.
	member, merr := h.q.IsActiveMember(ctx, db.IsActiveMemberParams{UserID: row.UserID, TenantID: row.TenantID})
	if merr != nil || !member {
		return nil, status.Error(codes.Unauthenticated, "api key tenant membership revoked")
	}
	// Joins user_roles + roles (Kept-strict RLS, Phase 3c) — read with the key's
	// own tenant set as app.tenant_id so a non-superuser iam_app connection can see
	// the rows. The key's tenant is trusted: it was pinned at creation.
	var perms []string
	if err := h.withTenantGUC(ctx, row.TenantID, func(q *db.Queries) error {
		var e error
		perms, e = q.GetUserPermissionsScoped(ctx, db.GetUserPermissionsScopedParams{
			UserID: row.UserID, TenantID: row.TenantID, ProjectID: row.ProjectID,
		})
		return e
	}); err != nil {
		return nil, status.Error(codes.Internal, "failed to load permissions")
	}
	have := make(map[string]struct{}, len(perms))
	for _, p := range perms {
		have[p] = struct{}{}
	}
	effective := make([]string, 0, len(row.Scopes))
	for _, s := range row.Scopes {
		if _, ok := have[s]; ok {
			effective = append(effective, s)
		}
	}
	_ = h.q.TouchApiKey(ctx, row.ID)
	return &authv1.ValidateApiKeyResponse{UserId: row.UserID.String(), Email: user.Email, Scopes: effective}, nil
}

// ── Soft-delete restore (v0.9) ──────────────────────────────

// RestoreUser reverses a soft delete and publishes a UserRestored event so the
// user service un-deletes the matching profile.
func (h *AuthHandler) RestoreUser(ctx context.Context, req *authv1.RestoreUserRequest) (*authv1.GenericResponse, error) {
	if err := requirePerm(ctx, "user:delete"); err != nil {
		return nil, err
	}
	uid, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "tx begin failed")
	}
	defer tx.Rollback(ctx)
	qtx := h.q.WithTx(tx)
	if err := qtx.RestoreUser(ctx, uid); err != nil {
		return nil, status.Error(codes.Internal, "failed to restore user")
	}
	payload, err := json.Marshal(events.UserRestored{UserID: uid.String()})
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to encode event")
	}
	if err := qtx.InsertOutbox(ctx, db.InsertOutboxParams{
		AggregateID: uid, EventType: events.TypeUserRestored, Payload: payload,
	}); err != nil {
		return nil, status.Error(codes.Internal, "failed to enqueue event")
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, status.Error(codes.Internal, "tx commit failed")
	}
	h.audit(ctx, "user.restore", req.GetUserId(), "")
	return &authv1.GenericResponse{Success: true}, nil
}

// ── helpers ─────────────────────────────────────────────────

func randToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func tsString(ts pgtype.Timestamptz) string {
	if !ts.Valid {
		return ""
	}
	return ts.Time.UTC().Format(time.RFC3339)
}
