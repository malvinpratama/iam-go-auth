// Package jwt issues and verifies HS256 access tokens.
package jwt

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/malvinpratama/iam-go-libs/config"
)

// Claims is the JWT payload for an access token.
type Claims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

// Manager signs and parses access tokens.
type Manager struct {
	secret    []byte
	issuer    string
	accessTTL time.Duration
}

// NewManager builds a Manager from JWT config.
func NewManager(cfg config.JWTConfig) *Manager {
	return &Manager{
		secret:    []byte(cfg.Secret),
		issuer:    cfg.Issuer,
		accessTTL: cfg.AccessTTL,
	}
}

// AccessTTL exposes the configured access-token lifetime.
func (m *Manager) AccessTTL() time.Duration { return m.accessTTL }

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
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.secret)
}

// Parse validates a token string and returns its claims.
func (m *Manager) Parse(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return m.secret, nil
	}, jwt.WithIssuer(m.issuer))
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}
