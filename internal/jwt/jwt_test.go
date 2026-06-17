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
	// Beyond the clock-skew leeway so it's unambiguously expired.
	m := newTestManager(-5 * time.Minute)
	tok, _ := m.Issue("user-123", "a@b.com", "", "")
	if _, err := m.Parse(tok); err == nil {
		t.Error("expected error for expired token")
	}
}

// A token expired by less than the leeway is still accepted (tolerates skew);
// one expired beyond it is rejected.
func TestParseClockSkewLeeway(t *testing.T) {
	within := newTestManager(-clockSkewLeeway / 2)
	tok, _ := within.Issue("user-123", "a@b.com", "", "")
	if _, err := within.Parse(tok); err != nil {
		t.Errorf("token within leeway should validate, got %v", err)
	}

	beyond := newTestManager(-2 * clockSkewLeeway)
	tok2, _ := beyond.Issue("user-123", "a@b.com", "", "")
	if _, err := beyond.Parse(tok2); err == nil {
		t.Error("token expired beyond leeway should be rejected")
	}
}

// An OIDC ID token shares the signing key and issuer with access tokens but has
// no jti and no token_use="access"; ParseAccess must reject it so it can't be
// replayed as a bearer token (regression for the token-confusion gap).
func TestParseAccessRejectsIDToken(t *testing.T) {
	m := newTestManager(time.Minute)
	// Issue the ID token with the manager's own issuer so the issuer check passes
	// — the ONLY thing that may reject it is the access-token type guard.
	idTok, err := m.IssueIDToken("user-123", "a@b.com", "some-client", "nonce-1", "iam-auth")
	if err != nil {
		t.Fatalf("issue id token: %v", err)
	}
	if _, err := m.Parse(idTok); err != nil {
		t.Fatalf("id token should still pass plain Parse (issuer matches): %v", err)
	}
	if _, err := m.ParseAccess(idTok); err == nil {
		t.Error("ParseAccess must reject an ID token")
	}
}

func TestParseAccessRejectsMFAToken(t *testing.T) {
	m := newTestManager(time.Minute)
	mfaTok, err := m.IssueMFA("user-123", time.Minute)
	if err != nil {
		t.Fatalf("issue mfa: %v", err)
	}
	if _, err := m.ParseAccess(mfaTok); err == nil {
		t.Error("ParseAccess must reject an MFA token")
	}
}

func TestParseAccessAcceptsAccessToken(t *testing.T) {
	m := newTestManager(time.Minute)
	tok, _ := m.Issue("user-123", "a@b.com", "tenant-1", "")
	claims, err := m.ParseAccess(tok)
	if err != nil {
		t.Fatalf("ParseAccess on a real access token: %v", err)
	}
	if claims.TokenUse != "access" {
		t.Errorf("token_use = %q, want access", claims.TokenUse)
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
