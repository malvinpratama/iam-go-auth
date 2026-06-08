package password

import "testing"

func TestHashAndVerify(t *testing.T) {
	h, err := Hash("secret123")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !Verify(h, "secret123") {
		t.Error("expected verify to succeed for correct password")
	}
	if Verify(h, "wrong") {
		t.Error("expected verify to fail for wrong password")
	}
}

func TestHashIsArgon2idAndSalted(t *testing.T) {
	h1, _ := Hash("samepw")
	h2, _ := Hash("samepw")
	if h1 == h2 {
		t.Error("hashes should differ due to random salt")
	}
	if h1[:9] != "$argon2id" {
		t.Errorf("expected argon2id PHC format, got %q", h1[:9])
	}
}

func TestVerifyRejectsGarbage(t *testing.T) {
	if Verify("not-a-valid-hash", "x") {
		t.Error("expected verify to reject malformed hash")
	}
}
