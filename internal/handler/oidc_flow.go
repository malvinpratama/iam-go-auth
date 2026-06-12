package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/malvinpratama/iam-go-auth/internal/db"
	authv1 "github.com/malvinpratama/iam-go-contracts/gen/auth/v1"
	"github.com/malvinpratama/iam-go-libs/config"
)

// randCode returns a high-entropy URL-safe opaque token.
func randCode() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// GetClient returns a registered OAuth client (never the secret).
func (h *AuthHandler) GetClient(ctx context.Context, req *authv1.GetClientRequest) (*authv1.OAuthClient, error) {
	var c authv1.OAuthClient
	err := h.pool.QueryRow(ctx,
		`SELECT client_id, name, redirect_uris, scopes, grant_types, is_confidential
		   FROM oauth_clients WHERE client_id = $1`, req.GetClientId()).
		Scan(&c.ClientId, &c.Name, &c.RedirectUris, &c.Scopes, &c.GrantTypes, &c.IsConfidential)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, status.Error(codes.NotFound, "client not found")
	}
	if err != nil {
		return nil, status.Error(codes.Internal, "client lookup failed")
	}
	return &c, nil
}

// CreateAuthorizationCode issues a one-time code (stores its SHA-256 + PKCE
// challenge), valid for 5 minutes.
func (h *AuthHandler) CreateAuthorizationCode(ctx context.Context, req *authv1.CreateAuthorizationCodeRequest) (*authv1.CreateAuthorizationCodeResponse, error) {
	uid, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}
	// Only mint a code for a member of the client's organization. The token
	// exchange re-checks this, but gating at issuance means a non-member can't
	// drive the authorize/consent flow to a usable authorization code at all.
	var clientTenant uuid.UUID
	if err := h.pool.QueryRow(ctx,
		`SELECT tenant_id FROM oauth_clients WHERE client_id = $1`, req.GetClientId()).Scan(&clientTenant); err != nil {
		return nil, status.Error(codes.NotFound, "client not found")
	}
	member, merr := h.q.IsActiveMember(ctx, db.IsActiveMemberParams{UserID: uid, TenantID: clientTenant})
	if merr != nil || !member {
		return nil, status.Error(codes.PermissionDenied, "not a member of this client's organization")
	}
	code := randCode()
	sum := sha256.Sum256([]byte(code))
	if _, err := h.pool.Exec(ctx,
		`INSERT INTO oauth_authorization_codes
		   (code_hash, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, expires_at)
		 VALUES ($1,$2,$3,$4,$5, NULLIF($6,''), NULLIF($7,''), NULLIF($8,''), now() + interval '5 minutes')`,
		hex.EncodeToString(sum[:]), req.GetClientId(), uid, req.GetRedirectUri(), req.GetScope(),
		req.GetCodeChallenge(), req.GetCodeChallengeMethod(), req.GetNonce()); err != nil {
		return nil, status.Error(codes.Internal, "could not create authorization code")
	}
	return &authv1.CreateAuthorizationCodeResponse{Code: code}, nil
}

// GetConsent returns the scopes the user previously granted this client (empty if none).
func (h *AuthHandler) GetConsent(ctx context.Context, req *authv1.GetConsentRequest) (*authv1.GetConsentResponse, error) {
	uid, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}
	var scopes []string
	err = h.pool.QueryRow(ctx,
		`SELECT scopes FROM oauth_consents WHERE user_id = $1 AND client_id = $2`,
		uid, req.GetClientId()).Scan(&scopes)
	if errors.Is(err, pgx.ErrNoRows) {
		return &authv1.GetConsentResponse{}, nil
	}
	if err != nil {
		return nil, status.Error(codes.Internal, "consent lookup failed")
	}
	return &authv1.GetConsentResponse{Scopes: scopes}, nil
}

// SaveConsent records (or updates) the user's consent for a client.
func (h *AuthHandler) SaveConsent(ctx context.Context, req *authv1.SaveConsentRequest) (*authv1.SaveConsentResponse, error) {
	uid, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}
	if _, err := h.pool.Exec(ctx,
		`INSERT INTO oauth_consents (user_id, client_id, scopes) VALUES ($1,$2,$3)
		 ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = EXCLUDED.scopes, granted_at = now()`,
		uid, req.GetClientId(), req.GetScopes()); err != nil {
		return nil, status.Error(codes.Internal, "could not save consent")
	}
	return &authv1.SaveConsentResponse{Success: true}, nil
}

// ExchangeAuthorizationCode swaps a one-time code (with PKCE) for tokens.
func (h *AuthHandler) ExchangeAuthorizationCode(ctx context.Context, req *authv1.ExchangeAuthorizationCodeRequest) (*authv1.OidcTokenResponse, error) {
	sum := sha256.Sum256([]byte(req.GetCode()))
	codeHash := hex.EncodeToString(sum[:])

	var (
		clientID, redirectURI, scope string
		userID                       uuid.UUID
		challenge, method, nonce     pgtype.Text
		used, expired                bool
	)
	err := h.pool.QueryRow(ctx,
		`SELECT client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, used, (expires_at < now())
		   FROM oauth_authorization_codes WHERE code_hash = $1`, codeHash).
		Scan(&clientID, &userID, &redirectURI, &scope, &challenge, &method, &nonce, &used, &expired)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid_grant")
	}
	if used || expired || clientID != req.GetClientId() || redirectURI != req.GetRedirectUri() {
		return nil, status.Error(codes.InvalidArgument, "invalid_grant")
	}
	// Single-use: atomically claim the code (closes the check-then-set race).
	tag, err := h.pool.Exec(ctx, `UPDATE oauth_authorization_codes SET used = true WHERE code_hash = $1 AND used = false`, codeHash)
	if err != nil || tag.RowsAffected() != 1 {
		return nil, status.Error(codes.InvalidArgument, "invalid_grant")
	}

	hasPKCE := challenge.Valid && challenge.String != ""
	if hasPKCE && !verifyPKCE(challenge.String, method.String, req.GetCodeVerifier()) {
		return nil, status.Error(codes.InvalidArgument, "invalid_grant")
	}

	// Client authentication.
	var secretHash pgtype.Text
	var isConfidential bool
	if err := h.pool.QueryRow(ctx,
		`SELECT client_secret_hash, is_confidential FROM oauth_clients WHERE client_id = $1`, clientID).
		Scan(&secretHash, &isConfidential); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid_client")
	}
	if isConfidential {
		sh := sha256.Sum256([]byte(req.GetClientSecret()))
		if !secretHash.Valid || hex.EncodeToString(sh[:]) != secretHash.String {
			return nil, status.Error(codes.Unauthenticated, "invalid_client")
		}
	} else if !hasPKCE {
		return nil, status.Error(codes.InvalidArgument, "PKCE required for public clients")
	}

	var email string
	if err := h.pool.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, userID).Scan(&email); err != nil {
		return nil, status.Error(codes.Internal, "user lookup failed")
	}

	// M6.5: bind the session to the OIDC client's tenant — the client identifies
	// the organization this app serves, so logging in through it yields a token
	// scoped to that tenant. The user must be an active member of it.
	var clientTenant uuid.UUID
	if err := h.pool.QueryRow(ctx, `SELECT tenant_id FROM oauth_clients WHERE client_id = $1`, clientID).Scan(&clientTenant); err != nil {
		return nil, status.Error(codes.Internal, "client tenant lookup failed")
	}
	member, err := h.q.IsActiveMember(ctx, db.IsActiveMemberParams{UserID: userID, TenantID: clientTenant})
	if err != nil {
		return nil, status.Error(codes.Internal, "membership check failed")
	}
	if !member {
		return nil, status.Error(codes.PermissionDenied, "not a member of this organization")
	}
	tp, err := h.issueTokens(ctx, userID, email, clientTenant, pgtype.UUID{})
	if err != nil {
		return nil, err
	}
	issuer := config.Getenv("OIDC_ISSUER", "http://localhost:8080")
	idToken, err := h.jwt.IssueIDToken(userID.String(), email, clientID, nonce.String, issuer)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to sign id_token")
	}
	return &authv1.OidcTokenResponse{
		AccessToken:  tp.AccessToken,
		IdToken:      idToken,
		RefreshToken: tp.RefreshToken,
		ExpiresIn:    tp.ExpiresIn,
		TokenType:    "Bearer",
		Scope:        scope,
	}, nil
}

// RegisterClient creates a new OAuth client; the secret is returned once (plaintext).
func (h *AuthHandler) RegisterClient(ctx context.Context, req *authv1.RegisterClientRequest) (*authv1.RegisterClientResponse, error) {
	if err := requirePerm(ctx, "role:write"); err != nil { // defense-in-depth (gateway also gates)
		return nil, err
	}
	// M6.5: the new client belongs to the caller's active tenant (the org it
	// serves), so logins through it bind users to that tenant.
	tenant, err := activeTenant(ctx)
	if err != nil {
		return nil, err
	}
	clientID := uuid.NewString()
	var secret string
	var secretHash *string
	if req.GetIsConfidential() {
		secret = randCode()
		sum := sha256.Sum256([]byte(secret))
		enc := hex.EncodeToString(sum[:])
		secretHash = &enc
	}
	scopes := req.GetScopes()
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	if _, err := h.pool.Exec(ctx,
		`INSERT INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris, scopes, grant_types, is_confidential, tenant_id)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		clientID, secretHash, req.GetName(), req.GetRedirectUris(), scopes,
		[]string{"authorization_code", "refresh_token"}, req.GetIsConfidential(), tenant); err != nil {
		return nil, status.Error(codes.Internal, "could not register client")
	}
	return &authv1.RegisterClientResponse{ClientId: clientID, ClientSecret: secret}, nil
}

// BootstrapOIDCClient seeds a demo confidential client (the admin console) on
// first boot, configurable via env. Idempotent.
func BootstrapOIDCClient(ctx context.Context, pool *pgxpool.Pool) error {
	clientID := config.Getenv("OIDC_CONSOLE_CLIENT_ID", "iam-admin-console")
	secret := config.Getenv("OIDC_CONSOLE_SECRET", "console-demo-secret-change-me")
	redirects := strings.Split(config.Getenv("OIDC_CONSOLE_REDIRECT_URIS", "http://localhost:3000/api/auth/callback/iam"), ",")
	sum := sha256.Sum256([]byte(secret))
	_, err := pool.Exec(ctx,
		`INSERT INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris, scopes, grant_types, is_confidential)
		 VALUES ($1,$2,'IAM Admin Console',$3, ARRAY['openid','profile','email'], ARRAY['authorization_code','refresh_token'], true)
		 ON CONFLICT (client_id) DO NOTHING`,
		clientID, hex.EncodeToString(sum[:]), redirects)
	return err
}

// verifyPKCE checks an RFC 7636 code_verifier against the stored challenge.
func verifyPKCE(challenge, method, verifier string) bool {
	switch method {
	case "S256":
		sum := sha256.Sum256([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(sum[:]) == challenge
	case "plain", "": // RFC 7636: default method is "plain"
		return verifier == challenge
	default:
		return false
	}
}
