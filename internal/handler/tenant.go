package handler

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/malvinpratama/iam-go-auth/internal/db"
	authv1 "github.com/malvinpratama/iam-go-contracts/gen/auth/v1"
	"github.com/malvinpratama/iam-go-libs/grpcutil"
)

// withTenant runs fn inside a transaction that assumes the restricted iam_rls
// role and sets app.tenant_id, so Postgres Row-Level Security enforces tenant
// isolation on top of the app-layer WHERE (defense in depth). Because the policy
// is fail-closed, a query that forgets its tenant filter still cannot read
// another tenant's rows. fn receives a *db.Queries bound to the transaction.
func (h *AuthHandler) withTenant(ctx context.Context, tenant uuid.UUID, fn func(*db.Queries) error) error {
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE iam_rls"); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenant.String()); err != nil {
		return err
	}
	if err := fn(h.q.WithTx(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// activeTenant returns the tenant the caller's token is bound to (forwarded by
// the gateway as x-tenant-id). Tenant-scoped admin operations act within it.
func activeTenant(ctx context.Context) (uuid.UUID, error) {
	tid := grpcutil.FromIncoming(ctx).TenantID
	if tid == "" {
		return uuid.Nil, status.Error(codes.FailedPrecondition, "no active tenant on token")
	}
	id, err := uuid.Parse(tid)
	if err != nil {
		return uuid.Nil, status.Error(codes.Internal, "invalid active tenant")
	}
	return id, nil
}

// ListMyMemberships returns the tenants the caller is an active member of.
func (h *AuthHandler) ListMyMemberships(ctx context.Context, _ *authv1.ListMembershipsRequest) (*authv1.ListMembershipsResponse, error) {
	uid, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := h.q.ListMembershipsByUser(ctx, uid)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to list memberships")
	}
	out := make([]*authv1.Membership, 0, len(rows))
	for _, r := range rows {
		out = append(out, &authv1.Membership{
			TenantId: r.TenantID.String(), TenantSlug: r.TenantSlug,
			TenantName: r.TenantName, Status: r.Status,
		})
	}
	return &authv1.ListMembershipsResponse{Memberships: out}, nil
}

// SwitchTenant re-issues a token bound to a different tenant (and optional
// project) the caller belongs to.
func (h *AuthHandler) SwitchTenant(ctx context.Context, req *authv1.SwitchTenantRequest) (*authv1.TokenPair, error) {
	uid, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	tid, err := uuid.Parse(req.GetTenantId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid tenant id")
	}
	member, err := h.q.IsActiveMember(ctx, db.IsActiveMemberParams{UserID: uid, TenantID: tid})
	if err != nil || !member {
		return nil, status.Error(codes.PermissionDenied, "not a member of that tenant")
	}
	if req.GetProjectId() != "" {
		if _, perr := uuid.Parse(req.GetProjectId()); perr != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid project id")
		}
	}
	project := parseOptionalUUID(req.GetProjectId())
	user, err := h.q.GetUserByID(ctx, uid)
	if err != nil {
		return nil, status.Error(codes.NotFound, "user not found")
	}
	h.audit(ctx, "tenant.switch", req.GetTenantId(), req.GetProjectId())
	return h.issueTokens(ctx, uid, user.Email, tid, project)
}

// CreateTenant provisions a new organization (platform op) and enrolls the
// creator as its first member, atomically.
func (h *AuthHandler) CreateTenant(ctx context.Context, req *authv1.CreateTenantRequest) (*authv1.Tenant, error) {
	if err := requirePerm(ctx, "tenant:write"); err != nil {
		return nil, err
	}
	if req.GetSlug() == "" || req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "slug and name are required")
	}
	uid, err := callerID(ctx)
	if err != nil {
		return nil, err
	}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "could not start tx")
	}
	defer tx.Rollback(ctx)
	qtx := h.q.WithTx(tx)
	t, err := qtx.CreateTenant(ctx, db.CreateTenantParams{Slug: req.GetSlug(), Name: req.GetName()})
	if err != nil {
		return nil, status.Error(codes.AlreadyExists, "tenant slug already taken")
	}
	if err := qtx.CreateMembership(ctx, db.CreateMembershipParams{UserID: uid, TenantID: t.ID}); err != nil {
		return nil, status.Error(codes.Internal, "could not enroll creator")
	}
	// The creator becomes the new tenant's admin so they can manage it (their
	// platform-level role does not carry over — RBAC is scoped per tenant).
	if err := qtx.AssignRoleInTenant(ctx, db.AssignRoleInTenantParams{UserID: uid, Name: "admin", TenantID: t.ID}); err != nil {
		return nil, status.Error(codes.Internal, "could not grant creator admin")
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, status.Error(codes.Internal, "could not commit tenant")
	}
	h.audit(ctx, "tenant.create", t.ID.String(), req.GetSlug())
	return &authv1.Tenant{Id: t.ID.String(), Slug: t.Slug, Name: t.Name, Status: t.Status}, nil
}

// ListTenants returns every tenant (platform op).
func (h *AuthHandler) ListTenants(ctx context.Context, _ *authv1.ListTenantsRequest) (*authv1.ListTenantsResponse, error) {
	if err := requirePerm(ctx, "tenant:read"); err != nil {
		return nil, err
	}
	rows, err := h.q.ListTenants(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to list tenants")
	}
	out := make([]*authv1.Tenant, 0, len(rows))
	for _, r := range rows {
		out = append(out, &authv1.Tenant{Id: r.ID.String(), Slug: r.Slug, Name: r.Name, Status: r.Status})
	}
	return &authv1.ListTenantsResponse{Tenants: out}, nil
}

// CreateProject creates a project within the caller's active tenant.
func (h *AuthHandler) CreateProject(ctx context.Context, req *authv1.CreateProjectRequest) (*authv1.Project, error) {
	if err := requirePerm(ctx, "project:write"); err != nil {
		return nil, err
	}
	if req.GetSlug() == "" || req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "slug and name are required")
	}
	tenant, err := activeTenant(ctx)
	if err != nil {
		return nil, err
	}
	p, err := h.q.CreateProject(ctx, db.CreateProjectParams{TenantID: tenant, Slug: req.GetSlug(), Name: req.GetName()})
	if err != nil {
		return nil, status.Error(codes.AlreadyExists, "project slug already taken in this tenant")
	}
	h.audit(ctx, "project.create", p.ID.String(), req.GetSlug())
	return &authv1.Project{Id: p.ID.String(), TenantId: p.TenantID.String(), Slug: p.Slug, Name: p.Name}, nil
}

// ListProjects returns the projects in the caller's active tenant.
func (h *AuthHandler) ListProjects(ctx context.Context, _ *authv1.ListProjectsRequest) (*authv1.ListProjectsResponse, error) {
	if err := requirePerm(ctx, "project:read"); err != nil {
		return nil, err
	}
	tenant, err := activeTenant(ctx)
	if err != nil {
		return nil, err
	}
	// Read under RLS (iam_rls + app.tenant_id) so the DB also enforces isolation.
	var rows []db.ListProjectsByTenantRow
	if err := h.withTenant(ctx, tenant, func(q *db.Queries) error {
		var e error
		rows, e = q.ListProjectsByTenant(ctx, tenant)
		return e
	}); err != nil {
		return nil, status.Error(codes.Internal, "failed to list projects")
	}
	out := make([]*authv1.Project, 0, len(rows))
	for _, r := range rows {
		out = append(out, &authv1.Project{Id: r.ID.String(), TenantId: r.TenantID.String(), Slug: r.Slug, Name: r.Name})
	}
	return &authv1.ListProjectsResponse{Projects: out}, nil
}

// AddMember enrolls an existing user (by email) into the caller's active tenant.
func (h *AuthHandler) AddMember(ctx context.Context, req *authv1.AddMemberRequest) (*authv1.Member, error) {
	if err := requirePerm(ctx, "member:write"); err != nil {
		return nil, err
	}
	tenant, err := activeTenant(ctx)
	if err != nil {
		return nil, err
	}
	user, err := h.q.GetUserByEmail(ctx, req.GetEmail())
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, status.Error(codes.NotFound, "no user with that email")
	}
	if err != nil {
		return nil, status.Error(codes.Internal, "user lookup failed")
	}
	if err := h.q.CreateMembership(ctx, db.CreateMembershipParams{UserID: user.ID, TenantID: tenant}); err != nil {
		return nil, status.Error(codes.Internal, "could not add member")
	}
	h.audit(ctx, "member.add", user.ID.String(), tenant.String())
	return &authv1.Member{UserId: user.ID.String(), Email: user.Email, Status: "active"}, nil
}

// RemoveMember removes a user from the caller's active tenant.
func (h *AuthHandler) RemoveMember(ctx context.Context, req *authv1.RemoveMemberRequest) (*authv1.RemoveMemberResponse, error) {
	if err := requirePerm(ctx, "member:write"); err != nil {
		return nil, err
	}
	tenant, err := activeTenant(ctx)
	if err != nil {
		return nil, err
	}
	uid, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}
	if err := h.q.RemoveMember(ctx, db.RemoveMemberParams{UserID: uid, TenantID: tenant}); err != nil {
		return nil, status.Error(codes.Internal, "could not remove member")
	}
	h.audit(ctx, "member.remove", req.GetUserId(), tenant.String())
	return &authv1.RemoveMemberResponse{Success: true}, nil
}

// ListMembers returns the members of the caller's active tenant.
func (h *AuthHandler) ListMembers(ctx context.Context, _ *authv1.ListMembersRequest) (*authv1.ListMembersResponse, error) {
	if err := requirePerm(ctx, "member:read"); err != nil {
		return nil, err
	}
	tenant, err := activeTenant(ctx)
	if err != nil {
		return nil, err
	}
	// Read under RLS (iam_rls + app.tenant_id) so the DB also enforces isolation.
	var rows []db.ListMembersByTenantRow
	if err := h.withTenant(ctx, tenant, func(q *db.Queries) error {
		var e error
		rows, e = q.ListMembersByTenant(ctx, tenant)
		return e
	}); err != nil {
		return nil, status.Error(codes.Internal, "failed to list members")
	}
	out := make([]*authv1.Member, 0, len(rows))
	for _, r := range rows {
		out = append(out, &authv1.Member{UserId: r.UserID.String(), Email: r.Email, Status: r.Status})
	}
	return &authv1.ListMembersResponse{Members: out}, nil
}

// GetUserRoleAssignments lists a user's role assignments in the caller's active
// tenant, each tagged with its project scope (empty = tenant-wide), so the admin
// console can show and revoke them precisely.
func (h *AuthHandler) GetUserRoleAssignments(ctx context.Context, req *authv1.GetUserRoleAssignmentsRequest) (*authv1.GetUserRoleAssignmentsResponse, error) {
	if err := requirePerm(ctx, "role:read"); err != nil {
		return nil, err
	}
	tenant, err := activeTenant(ctx)
	if err != nil {
		return nil, err
	}
	uid, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}
	rows, err := h.q.GetUserRoleAssignments(ctx, db.GetUserRoleAssignmentsParams{UserID: uid, TenantID: tenant})
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to load role assignments")
	}
	out := make([]*authv1.RoleAssignment, 0, len(rows))
	for _, r := range rows {
		ra := &authv1.RoleAssignment{Role: r.Role}
		if r.ProjectID.Valid {
			ra.ProjectId = uuid.UUID(r.ProjectID.Bytes).String()
		}
		if r.ProjectSlug != nil {
			ra.ProjectSlug = *r.ProjectSlug
		}
		out = append(out, ra)
	}
	return &authv1.GetUserRoleAssignmentsResponse{Assignments: out}, nil
}

// parseOptionalUUID converts an optional UUID string to a pgtype.UUID; an empty
// or unparseable string yields an invalid (SQL NULL) value.
func parseOptionalUUID(s string) pgtype.UUID {
	if s == "" {
		return pgtype.UUID{}
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: id, Valid: true}
}
