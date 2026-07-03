package auth

import (
	"testing"
	"time"
)

func TestIssueAndVerifyAccessToken(t *testing.T) {
	priv, pub, err := LoadOrGenerateKeys(t.TempDir()+"/priv.pem", t.TempDir()+"/pub.pem")
	if err != nil {
		t.Fatalf("keys: %v", err)
	}

	issuer := NewJWTIssuer(priv, pub, 10*time.Minute)

	token, err := issuer.IssueAccessToken("76561198000000001")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	steamID, err := issuer.VerifyAccessToken(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if steamID != "76561198000000001" {
		t.Errorf("got steamID %s, want 76561198000000001", steamID)
	}
}

func TestVerifyAccessToken_RejectsExpired(t *testing.T) {
	priv, pub, err := LoadOrGenerateKeys(t.TempDir()+"/priv.pem", t.TempDir()+"/pub.pem")
	if err != nil {
		t.Fatalf("keys: %v", err)
	}

	issuer := NewJWTIssuer(priv, pub, -1*time.Minute) // уже истёкший
	token, err := issuer.IssueAccessToken("76561198000000001")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	if _, err := issuer.VerifyAccessToken(token); err == nil {
		t.Error("expected error for expired token, got nil")
	}
}
