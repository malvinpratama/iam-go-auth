package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/malvinpratama/iam-go-contracts/gen/auth/v1"
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
