package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
	proxyIPStore, err := NewProxyIPStore(database)
	if err != nil {
		t.Fatalf("proxy ip store: %v", err)
	}

	h := NewHandlers(cfg, issuer, refreshStore, verifier, proxyIPStore)
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

func TestMeHandler_ReturnsSteamIDAndIsRoot(t *testing.T) {
	h, _ := newTestHandlers(t)

	req := httptest.NewRequest("GET", "/auth/me", nil)
	ctx := context.WithValue(req.Context(), steamIDContextKey, "76561198000000001") // == cfg.RootSteamID
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	h.HandleMe(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d, body: %s", rec.Code, rec.Body.String())
	}

	var body struct {
		SteamID string `json:"steam_id"`
		IsRoot  bool   `json:"is_root"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.SteamID != "76561198000000001" {
		t.Errorf("got steam_id=%s, want 76561198000000001", body.SteamID)
	}
	if !body.IsRoot {
		t.Error("expected is_root=true for ROOT_STEAM_ID")
	}
}

func TestMeHandler_NonRootUserIsRootFalse(t *testing.T) {
	h, _ := newTestHandlers(t)

	req := httptest.NewRequest("GET", "/auth/me", nil)
	ctx := context.WithValue(req.Context(), steamIDContextKey, "76561198000000002")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	h.HandleMe(rec, req)

	var body struct {
		IsRoot bool `json:"is_root"`
	}
	json.NewDecoder(rec.Body).Decode(&body)
	if body.IsRoot {
		t.Error("expected is_root=false for a non-root steamID")
	}
}

func TestAdminConfigHandlers_SetAndGetRoundTrip(t *testing.T) {
	h, _ := newTestHandlers(t)

	setReq := httptest.NewRequest("POST", "/admin/config", strings.NewReader(`{"allowed_proxy_ip":["10.0.0.5","10.0.0.6"]}`))
	setRec := httptest.NewRecorder()
	h.HandleSetAdminConfig(setRec, setReq)
	if setRec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d, body: %s", setRec.Code, setRec.Body.String())
	}

	getReq := httptest.NewRequest("GET", "/admin/config", nil)
	getRec := httptest.NewRecorder()
	h.HandleGetAdminConfig(getRec, getReq)

	var body struct {
		AllowedProxyIP []string `json:"allowed_proxy_ip"`
	}
	if err := json.NewDecoder(getRec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.AllowedProxyIP) != 2 {
		t.Errorf("expected 2 IPs, got %v", body.AllowedProxyIP)
	}
}
