package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRequireAuth_ValidTokenPassesThrough(t *testing.T) {
	priv, pub, err := LoadOrGenerateKeys(t.TempDir()+"/priv.pem", t.TempDir()+"/pub.pem")
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	issuer := NewJWTIssuer(priv, pub, 10*time.Minute)
	token, _ := issuer.IssueAccessToken("76561198000000001")

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		steamID, ok := SteamIDFromContext(r.Context())
		if !ok || steamID != "76561198000000001" {
			t.Errorf("expected steamID in context, got %q, ok=%v", steamID, ok)
		}
		w.WriteHeader(http.StatusOK)
	})

	mw := RequireAuth(issuer)(next)

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if !called {
		t.Error("expected next handler to be called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestRequireAuth_MissingTokenReturns401WithRefreshHint(t *testing.T) {
	priv, pub, err := LoadOrGenerateKeys(t.TempDir()+"/priv.pem", t.TempDir()+"/pub.pem")
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	issuer := NewJWTIssuer(priv, pub, 10*time.Minute)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	mw := RequireAuth(issuer)(next)

	req := httptest.NewRequest("GET", "/protected", nil)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if called {
		t.Error("next handler must not be called without valid token")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
	if rec.Header().Get("X-Token-Refresh-Required") != "true" {
		t.Error("expected X-Token-Refresh-Required header so client knows to call /auth/refresh")
	}
}

func TestRequireAuth_ExpiredTokenReturns401WithRefreshHint(t *testing.T) {
	priv, pub, err := LoadOrGenerateKeys(t.TempDir()+"/priv.pem", t.TempDir()+"/pub.pem")
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	expiredIssuer := NewJWTIssuer(priv, pub, -1*time.Minute)
	token, _ := expiredIssuer.IssueAccessToken("76561198000000001")

	validIssuer := NewJWTIssuer(priv, pub, 10*time.Minute) // тот же ключ, проверяем только истёкший token
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	mw := RequireAuth(validIssuer)(next)

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
	if rec.Header().Get("X-Token-Refresh-Required") != "true" {
		t.Error("expected refresh hint header")
	}
}
