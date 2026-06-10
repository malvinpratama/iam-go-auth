package handler

import (
	"context"
	"encoding/base64"
	"math/big"

	authv1 "github.com/malvinpratama/iam-go-contracts/gen/auth/v1"
)

// GetJwks returns the active + rotated public RS256 signing keys as a JWKS
// (RFC 7517), so OIDC relying parties can verify tokens without a shared secret.
func (h *AuthHandler) GetJwks(_ context.Context, _ *authv1.GetJwksRequest) (*authv1.GetJwksResponse, error) {
	pubs := h.jwt.PublicKeys()
	keys := make([]*authv1.Jwk, 0, len(pubs))
	for kid, pub := range pubs {
		keys = append(keys, &authv1.Jwk{
			Kid: kid,
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		})
	}
	return &authv1.GetJwksResponse{Keys: keys}, nil
}
