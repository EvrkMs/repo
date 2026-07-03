package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"intact-cs-map/internal/config"
)

func testCfg() *config.Config {
	return &config.Config{
		RootSteamID:   "76561198000000001",
		AdminSteamIDs: map[string]struct{}{"76561198000000002": {}},
	}
}

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

	mw := RequireAuth(issuer, testCfg())(next)

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

	mw := RequireAuth(issuer, testCfg())(next)

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
	mw := RequireAuth(validIssuer, testCfg())(next)

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

// Регрессионный тест на пробел из design doc: SteamID убрали из allow-list,
// но у клиента ещё есть валидный (не истёкший) access token, выданный раньше.
// Должен получить 403, а не пройти проверку только на основании валидности JWT.
func TestRequireAuth_ValidTokenButRemovedFromAllowListReturns403(t *testing.T) {
	priv, pub, err := LoadOrGenerateKeys(t.TempDir()+"/priv.pem", t.TempDir()+"/pub.pem")
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	issuer := NewJWTIssuer(priv, pub, 10*time.Minute)
	token, _ := issuer.IssueAccessToken("76561198000000099") // не в allow-list

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	mw := RequireAuth(issuer, testCfg())(next)

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if called {
		t.Error("next handler must not be called for a steamID no longer in the allow-list")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
	if rec.Header().Get("X-Token-Refresh-Required") == "true" {
		t.Error("403 must NOT carry refresh hint — refreshing won't fix a revoked allow-list entry")
	}
}
