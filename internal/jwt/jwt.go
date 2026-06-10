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

// Claims is the JWT payload for an access token.
type Claims struct {
	Email string `json:"email"`
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

// Issue creates a signed access token for the given user.
func (m *Manager) Issue(userID, email string) (string, error) {
	now := time.Now()
	claims := Claims{
		Email: email,
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
	}, jwt.WithIssuer(m.issuer))
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}
