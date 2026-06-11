package handler

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/malvinpratama/iam-go-auth/internal/db"
	authv1 "github.com/malvinpratama/iam-go-contracts/gen/auth/v1"
)

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
	var project pgtype.UUID
	if p := req.GetProjectId(); p != "" {
		pid, perr := uuid.Parse(p)
		if perr != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid project id")
		}
		project = pgtype.UUID{Bytes: pid, Valid: true}
	}
	user, err := h.q.GetUserByID(ctx, uid)
	if err != nil {
		return nil, status.Error(codes.NotFound, "user not found")
	}
	h.audit(ctx, "tenant.switch", req.GetTenantId(), req.GetProjectId())
	return h.issueTokens(ctx, uid, user.Email, tid, project)
}
