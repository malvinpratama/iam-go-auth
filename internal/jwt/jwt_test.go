package jwt

import (
	"testing"
	"time"

	"github.com/malvinpratama/iam-go-libs/config"
)

func newTestManager() *Manager {
	return NewManager(config.JWTConfig{
		Secret:    "test-secret-which-is-long-enough-32b",
		Issuer:    "iam-auth",
		AccessTTL: time.Minute,
	})
}

func TestIssueAndParse(t *testing.T) {
	m := newTestManager()
	tok, err := m.Issue("user-123", "a@b.com")
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
	m := newTestManager()
	tok, _ := m.Issue("user-123", "a@b.com")
	if _, err := m.Parse(tok + "x"); err == nil {
		t.Error("expected error for tampered token")
	}
}

func TestParseRejectsExpired(t *testing.T) {
	m := NewManager(config.JWTConfig{Secret: "test-secret-which-is-long-enough-32b", Issuer: "iam-auth", AccessTTL: -time.Minute})
	tok, _ := m.Issue("user-123", "a@b.com")
	if _, err := m.Parse(tok); err == nil {
		t.Error("expected error for expired token")
	}
}
