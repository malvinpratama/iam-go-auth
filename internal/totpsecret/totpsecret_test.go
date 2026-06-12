package totpsecret

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func key32() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func TestRoundTrip(t *testing.T) {
	e, err := New(key32())
	if err != nil {
		t.Fatal(err)
	}
	const secret = "JBSWY3DPEHPK3PXP"
	stored, err := e.Encrypt(secret)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored, prefix) {
		t.Fatalf("ciphertext missing %q prefix: %q", prefix, stored)
	}
	if strings.Contains(stored, secret) {
		t.Fatal("plaintext secret leaked into ciphertext")
	}
	got, err := e.Decrypt(stored)
	if err != nil {
		t.Fatal(err)
	}
	if got != secret {
		t.Fatalf("round-trip mismatch: got %q want %q", got, secret)
	}
}

func TestNonceIsRandom(t *testing.T) {
	e, _ := New(key32())
	a, _ := e.Encrypt("same")
	b, _ := e.Encrypt("same")
	if a == b {
		t.Fatal("identical ciphertext for repeated plaintext — nonce not random")
	}
}

func TestLegacyPlaintextPassesThrough(t *testing.T) {
	e, _ := New(key32())
	// A stored value with no enc:v1: prefix is a pre-encryption secret.
	got, err := e.Decrypt("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	if got != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("legacy plaintext not returned verbatim: %q", got)
	}
}

func TestPassthroughWhenNoKey(t *testing.T) {
	e, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	if e.Enabled() {
		t.Fatal("expected passthrough (disabled) with empty key")
	}
	stored, _ := e.Encrypt("JBSWY3DPEHPK3PXP")
	if stored != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("passthrough Encrypt changed the value: %q", stored)
	}
}

func TestEncryptedValueWithoutKeyErrors(t *testing.T) {
	enc, _ := New(key32())
	stored, _ := enc.Encrypt("JBSWY3DPEHPK3PXP")

	none, _ := New("")
	if _, err := none.Decrypt(stored); err == nil {
		t.Fatal("expected error decrypting an enc:v1: value with no key, got nil")
	}
}

func TestWrongKeyFails(t *testing.T) {
	a, _ := New(key32())
	b, _ := New(key32())
	stored, _ := a.Encrypt("JBSWY3DPEHPK3PXP")
	if _, err := b.Decrypt(stored); err == nil {
		t.Fatal("expected GCM auth failure with the wrong key, got nil")
	}
}

func TestShortStringKeyIsAccepted(t *testing.T) {
	// A non-base64-32 value is SHA-256-derived, so any string works as a key.
	e, err := New("a-short-passphrase-not-32-bytes")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := e.Encrypt("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := e.Decrypt(stored)
	if got != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("round-trip with derived key failed: %q", got)
	}
}
