// Package totpsecret provides envelope encryption for TOTP shared secrets at
// rest (TS3). Unlike passwords or recovery codes — which are hashed one-way —
// a TOTP shared secret must be recoverable to compute the rolling code, so it
// cannot be hashed; instead it is encrypted with AES-256-GCM under a key derived
// from the TOTP_ENC_KEY env value.
//
// Stored values are tagged "enc:v1:". A value without that prefix is treated as
// legacy plaintext and returned as-is on decrypt, so turning encryption on needs
// no data migration: existing secrets keep working and are re-encrypted the next
// time they're written (re-enroll). The "v1" tag leaves room to rotate the
// scheme later.
package totpsecret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const prefix = "enc:v1:"

// Encryptor encrypts and decrypts TOTP secrets. A nil-cipher Encryptor (no key
// configured) is a passthrough: Encrypt returns plaintext and Decrypt reads
// plaintext, so local/dev runs without a key keep working. Production should set
// TOTP_ENC_KEY so secrets are encrypted at rest.
type Encryptor struct {
	gcm cipher.AEAD // nil = passthrough (no key configured)
}

// New builds an Encryptor from the raw TOTP_ENC_KEY value. An empty key yields a
// passthrough encryptor. A value that base64-decodes to exactly 32 bytes is used
// directly as the AES-256 key; any other non-empty value is normalised to 32
// bytes via SHA-256 (so any sufficiently random string works as a key).
func New(key string) (*Encryptor, error) {
	if key == "" {
		return &Encryptor{}, nil
	}
	block, err := aes.NewCipher(deriveKey(key))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Encryptor{gcm: gcm}, nil
}

// deriveKey returns a 32-byte AES-256 key. A base64 value of exactly 32 raw
// bytes is used verbatim; otherwise the key material is SHA-256-derived.
func deriveKey(key string) []byte {
	if b, err := base64.StdEncoding.DecodeString(key); err == nil && len(b) == 32 {
		return b
	}
	sum := sha256.Sum256([]byte(key))
	return sum[:]
}

// Enabled reports whether encryption is active (a key was configured).
func (e *Encryptor) Enabled() bool { return e.gcm != nil }

// Encrypt returns the at-rest form of a plaintext TOTP secret. With no key
// configured it returns the plaintext unchanged.
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	if e.gcm == nil {
		return plaintext, nil
	}
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := e.gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return prefix + base64.StdEncoding.EncodeToString(ct), nil
}

// Decrypt reverses Encrypt. A value without the enc:v1: prefix is legacy
// plaintext and is returned unchanged (no migration needed). An encrypted value
// with no key configured is an error rather than a silent bypass.
func (e *Encryptor) Decrypt(stored string) (string, error) {
	if !strings.HasPrefix(stored, prefix) {
		return stored, nil // legacy plaintext
	}
	if e.gcm == nil {
		return "", errors.New("totp secret is encrypted but TOTP_ENC_KEY is not set")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, prefix))
	if err != nil {
		return "", fmt.Errorf("decode totp secret: %w", err)
	}
	ns := e.gcm.NonceSize()
	if len(raw) < ns {
		return "", errors.New("totp secret ciphertext too short")
	}
	pt, err := e.gcm.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("decrypt totp secret: %w", err)
	}
	return string(pt), nil
}
