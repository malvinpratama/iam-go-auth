package jwt

import (
	"crypto/rsa"
	"testing"
	"time"
)

func newTestManager(ttl time.Duration) *Manager {
	key, kid, _, _, err := generateRSA()
	if err != nil {
		panic(err)
	}
	ks := KeySet{
		Active:    SigningKey{Kid: kid, Private: key},
		Verifiers: map[string]*rsa.PublicKey{kid: &key.PublicKey},
	}
	return NewManager(ks, "iam-auth", ttl)
}

func TestIssueAndParse(t *testing.T) {
	m := newTestManager(time.Minute)
	tok, err := m.Issue("user-123", "a@b.com", "", "")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, err := m.Parse(tok)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if claims.Subject != "user-123" {
		t.Errorf("subject = %q, want user-123", claims.Subject)
	}
	if claims.Email != "a@b.com" {
		t.Errorf("email = %q, want a@b.com", claims.Email)
	}
}

func TestParseRejectsTampered(t *testing.T) {
	m := newTestManager(time.Minute)
	tok, _ := m.Issue("user-123", "a@b.com", "", "")
	if _, err := m.Parse(tok + "x"); err == nil {
		t.Error("expected error for tampered token")
	}
}

func TestParseRejectsExpired(t *testing.T) {
	m := newTestManager(-time.Minute)
	tok, _ := m.Issue("user-123", "a@b.com", "", "")
	if _, err := m.Parse(tok); err == nil {
		t.Error("expected error for expired token")
	}
}

func TestParseRejectsUnknownKid(t *testing.T) {
	m := newTestManager(time.Minute)
	tok, _ := m.Issue("user-123", "a@b.com", "", "")
	// A manager with a different key set must reject a token signed elsewhere.
	other := newTestManager(time.Minute)
	if _, err := other.Parse(tok); err == nil {
		t.Error("expected error verifying token from a different key")
	}
}
