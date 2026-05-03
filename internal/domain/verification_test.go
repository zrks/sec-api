package domain

import "testing"

func TestGenerateVerificationToken(t *testing.T) {
	token := GenerateVerificationToken()
	if token == "" {
		t.Fatal("expected token to be generated")
	}
	if len(token) < 16 {
		t.Fatalf("expected token length >= 16, got %d", len(token))
	}
	if VerificationRecordValue(token) == token {
		t.Fatal("expected record value to include verification prefix")
	}
}

func TestHasVerificationTXT(t *testing.T) {
	token := "abc123"
	records := []string{"v=spf1 include:_spf.example.com ~all", "drd-verify-abc123"}
	if !HasVerificationTXT(records, token) {
		t.Fatal("expected verification TXT record to match")
	}
	if HasVerificationTXT(records, "wrong") {
		t.Fatal("expected mismatched token to fail")
	}
}
