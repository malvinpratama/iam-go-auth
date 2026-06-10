package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SigningKey is the active RS256 key used to sign tokens.
type SigningKey struct {
	Kid     string
	Private *rsa.PrivateKey
}

// KeySet is the result of loading keys: the active signer plus every public key
// (active + rotated) indexed by kid, for verification and JWKS.
type KeySet struct {
	Active    SigningKey
	Verifiers map[string]*rsa.PublicKey
}

// LoadKeys loads all signing keys from the database, generating an initial
// RS256 keypair on first boot if none exist. The active key signs new tokens;
// every public key is kept for verification so tokens survive key rotation.
func LoadKeys(ctx context.Context, pool *pgxpool.Pool) (KeySet, error) {
	ks := KeySet{Verifiers: map[string]*rsa.PublicKey{}}

	rows, err := pool.Query(ctx, `SELECT kid, private_pem, public_pem, active FROM oidc_signing_keys`)
	if err != nil {
		return ks, err
	}
	type rec struct {
		kid, priv, pub string
		active         bool
	}
	var found []rec
	for rows.Next() {
		var r rec
		if err := rows.Scan(&r.kid, &r.priv, &r.pub, &r.active); err != nil {
			rows.Close()
			return ks, err
		}
		found = append(found, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return ks, err
	}

	if len(found) == 0 {
		key, kid, privPEM, pubPEM, err := generateRSA()
		if err != nil {
			return ks, err
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO oidc_signing_keys (kid, private_pem, public_pem, alg, active) VALUES ($1,$2,$3,'RS256',true)`,
			kid, privPEM, pubPEM); err != nil {
			return ks, err
		}
		ks.Active = SigningKey{Kid: kid, Private: key}
		ks.Verifiers[kid] = &key.PublicKey
		return ks, nil
	}

	for _, r := range found {
		pub, err := parsePublicPEM(r.pub)
		if err != nil {
			return ks, err
		}
		ks.Verifiers[r.kid] = pub
		if r.active {
			priv, err := parsePrivatePEM(r.priv)
			if err != nil {
				return ks, err
			}
			ks.Active = SigningKey{Kid: r.kid, Private: priv}
		}
	}
	if ks.Active.Private == nil {
		return ks, errors.New("no active signing key")
	}
	return ks, nil
}

// generateRSA creates a 2048-bit RSA keypair and its PEM encodings + a kid.
func generateRSA() (key *rsa.PrivateKey, kid, privPEM, pubPEM string, err error) {
	key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", "", "", err
	}
	kid = uuid.NewString()
	privPEM = string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, "", "", "", err
	}
	pubPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	return key, kid, privPEM, pubPEM, nil
}

func parsePrivatePEM(s string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("invalid private key PEM")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func parsePublicPEM(s string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("invalid public key PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not RSA")
	}
	return rsaPub, nil
}
