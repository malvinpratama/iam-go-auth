// Package totp wraps TOTP (RFC 6238) secret generation, code validation, and
// one-time recovery-code generation for the 2FA flow.
package totp

import (
	"crypto/rand"
	"fmt"

	"github.com/pquerna/otp/totp"
)

const issuer = "IAM"

// Secret holds a freshly generated TOTP secret plus its provisioning URI.
type Secret struct {
	Base32     string // for manual entry into an authenticator app
	OtpauthURI string // otpauth://totp/... (render as a QR code)
}

// Generate creates a new TOTP secret for the given account (email).
func Generate(account string) (Secret, error) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: issuer, AccountName: account})
	if err != nil {
		return Secret{}, err
	}
	return Secret{Base32: key.Secret(), OtpauthURI: key.URL()}, nil
}

// Validate reports whether code is a currently-valid TOTP for secret.
func Validate(code, secret string) bool {
	return totp.Validate(code, secret)
}

// GenerateRecoveryCodes returns n random, human-typable recovery codes
// (format xxxx-xxxx). They are shown to the user once; only hashes are stored.
func GenerateRecoveryCodes(n int) ([]string, error) {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789" // no ambiguous chars
	codes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		buf := make([]byte, 8)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		out := make([]byte, 8)
		for j, b := range buf {
			out[j] = alphabet[int(b)%len(alphabet)]
		}
		codes = append(codes, fmt.Sprintf("%s-%s", out[:4], out[4:]))
	}
	return codes, nil
}
