package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"intact-cs-map/internal/config"
	"intact-cs-map/internal/db"
)

func newTestHandlers(t *testing.T) (*Handlers, string) {
	t.Helper()
	database, err := db.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	priv, pub, err := LoadOrGenerateKeys(t.TempDir()+"/priv.pem", t.TempDir()+"/pub.pem")
	if err != nil {
		t.Fatalf("keys: %v", err)
	}

	mockSteam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("is_valid:true\n"))
	}))
	t.Cleanup(mockSteam.Close)

	cfg := &config.Config{RootSteamID: "76561198000000001", CallbackBaseURL: "http://localhost:8080"}
	issuer := NewJWTIssuer(priv, pub, 10*time.Minute)
	refreshStore := NewRefreshStore(database, 24*time.Hour)
	verifier := &SteamOpenIDVerifier{steamEndpoint: mockSteam.URL}

	h := NewHandlers(cfg, issuer, refreshStore, verifier, nil)
	return h, mockSteam.URL
}

func TestCallbackHandler_AllowedUserGetsTokens(t *testing.T) {
	h, _ := newTestHandlers(t)

	req := httptest.NewRequest("GET", "/auth/callback?openid.claimed_id=https://steamcommunity.com/openid/id/76561198000000001", nil)
	rec := httptest.NewRecorder()

	h.HandleCallback(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected redirect, got status %d, body: %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected refresh cookie to be set")
	}
}

func TestCallbackHandler_DisallowedUserGetsNoAccess(t *testing.T) {
	h, _ := newTestHandlers(t)

	req := httptest.NewRequest("GET", "/auth/callback?openid.claimed_id=https://steamcommunity.com/openid/id/99999999999999999", nil)
	rec := httptest.NewRecorder()

	h.HandleCallback(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for user not in allow-list, got %d", rec.Code)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Error("expected no cookie set for disallowed user")
	}
}

func TestMeHandler_ReturnsSteamIDFromContext(t *testing.T) {
	h, _ := newTestHandlers(t)

	req := httptest.NewRequest("GET", "/auth/me", nil)
	ctx := context.WithValue(req.Context(), steamIDContextKey, "76561198000000001")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	h.HandleMe(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d, body: %s", rec.Code, rec.Body.String())
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["steam_id"] != "76561198000000001" {
		t.Errorf("got steam_id=%s, want 76561198000000001", body["steam_id"])
	}
}
