// Package jwt issues and verifies RS256 access tokens. The signing key is an
// RSA keypair (see keys.go); public keys are exposed via JWKS so external OIDC
// relying parties can verify tokens without a shared secret.
package jwt

import (
	"crypto/rsa"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// tokenUseAccess marks a token as an access token (the only kind ValidateToken
// accepts). It gives access tokens a positive type marker so an OIDC ID token —
// which is signed by the same key and shares the issuer — can never be replayed
// on the access-token path.
const tokenUseAccess = "access"

// clockSkewLeeway tolerates small clock differences between the signing service
// and verifiers when checking exp/iat/nbf, so a freshly issued token isn't
// rejected by a verifier whose clock runs slightly behind.
const clockSkewLeeway = 60 * time.Second

// Claims is the JWT payload for an access token.
type Claims struct {
	Email string `json:"email"`
	// TokenUse is "access" for a normal access token (see tokenUseAccess). ID
	// tokens omit it; checked by ParseAccess so the two can't be confused.
	TokenUse string `json:"token_use,omitempty"`
	// Purpose distinguishes token kinds. Empty for a normal access token;
	// "mfa" for the short-lived token issued between the password step and the
	// TOTP step of a 2FA login (it must NOT be accepted as an access token).
	Purpose string `json:"purpose,omitempty"`
	// M6: the tenant/project the access token is bound to (empty project =
	// tenant-wide). Carried so the gateway can scope every request.
	TenantID  string `json:"tenant_id,omitempty"`
	ProjectID string `json:"project_id,omitempty"`
	jwt.RegisteredClaims
}

// Manager signs and parses access tokens with RS256.
type Manager struct {
	active    SigningKey
	verifiers map[string]*rsa.PublicKey // kid -> public key (active + rotated)
	issuer    string
	accessTTL time.Duration
}

// NewManager builds a Manager from a loaded key set and token settings.
func NewManager(keys KeySet, issuer string, accessTTL time.Duration) *Manager {
	return &Manager{
		active:    keys.Active,
		verifiers: keys.Verifiers,
		issuer:    issuer,
		accessTTL: accessTTL,
	}
}

// AccessTTL exposes the configured access-token lifetime.
func (m *Manager) AccessTTL() time.Duration { return m.accessTTL }

// PublicKeys returns kid -> public key for building a JWKS document.
func (m *Manager) PublicKeys() map[string]*rsa.PublicKey { return m.verifiers }

// Issue creates a signed access token for the given user, bound to a tenant
// (and optionally a project; empty projectID = tenant-wide).
func (m *Manager) Issue(userID, email, tenantID, projectID string) (string, error) {
	now := time.Now()
	claims := Claims{
		Email:     email,
		TokenUse:  tokenUseAccess,
		TenantID:  tenantID,
		ProjectID: projectID,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(), // jti — used for access-token revocation
			Subject:   userID,
			Issuer:    m.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.accessTTL)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = m.active.Kid
	return tok.SignedString(m.active.Private)
}

// IssueMFA signs a short-lived token proving the password step of a 2FA login
// passed. It carries purpose="mfa" and no jti (not revocable, not an access
// token); LoginTotp exchanges it + a TOTP/recovery code for a real token pair.
func (m *Manager) IssueMFA(userID string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := Claims{
		Purpose: "mfa",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    m.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = m.active.Kid
	return tok.SignedString(m.active.Private)
}

// IssueIDToken signs an OIDC ID token (RS256) for the given subject, audience
// (client_id) and optional nonce. `issuer` is the public OIDC issuer URL so
// relying parties' issuer check passes.
func (m *Manager) IssueIDToken(sub, email, audience, nonce, issuer string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   issuer,
		"sub":   sub,
		"aud":   audience,
		"iat":   now.Unix(),
		"exp":   now.Add(m.accessTTL).Unix(),
		"email": email,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = m.active.Kid
	return tok.SignedString(m.active.Private)
}

// Parse validates a token string and returns its claims. The signing key is
// selected by the token's `kid` header so rotated keys still verify.
func (m *Manager) Parse(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		kid, _ := t.Header["kid"].(string)
		pub, ok := m.verifiers[kid]
		if !ok {
			return nil, errors.New("unknown key id")
		}
		return pub, nil
	}, jwt.WithIssuer(m.issuer), jwt.WithLeeway(clockSkewLeeway))
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

// ParseAccess validates a token AND asserts it is a bearer access token — not an
// MFA token and not an OIDC ID token. Access tokens always carry a jti and (for
// tokens minted after this change) token_use="access"; ID tokens carry neither.
// Without this, an ID token (same key + issuer, empty purpose, no jti) would
// validate on the access-token path with the holder's global permissions.
func (m *Manager) ParseAccess(tokenStr string) (*Claims, error) {
	claims, err := m.Parse(tokenStr)
	if err != nil {
		return nil, err
	}
	if claims.Purpose != "" {
		return nil, errors.New("not an access token")
	}
	// jti is mandatory on access tokens (used for revocation); ID tokens omit it.
	if claims.ID == "" {
		return nil, errors.New("not an access token")
	}
	// Reject any token explicitly typed as something else (forward-looking).
	if claims.TokenUse != "" && claims.TokenUse != tokenUseAccess {
		return nil, errors.New("not an access token")
	}
	return claims, nil
}
