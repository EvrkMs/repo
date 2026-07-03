package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuildSteamLoginURL(t *testing.T) {
	url := BuildSteamLoginURL("http://localhost:8080/auth/callback")
	if !strings.Contains(url, "steamcommunity.com/openid/login") {
		t.Errorf("expected Steam OpenID endpoint in URL, got: %s", url)
	}
	if !strings.Contains(url, "return_to=http%3A%2F%2Flocalhost%3A8080%2Fauth%2Fcallback") {
		t.Errorf("expected encoded return_to param, got: %s", url)
	}
}

func TestExtractSteamID(t *testing.T) {
	claimedID := "https://steamcommunity.com/openid/id/76561198000000001"
	id, err := extractSteamID(claimedID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "76561198000000001" {
		t.Errorf("got %s, want 76561198000000001", id)
	}
}

func TestExtractSteamID_RejectsMalformed(t *testing.T) {
	if _, err := extractSteamID("not-a-valid-claimed-id"); err == nil {
		t.Error("expected error for malformed claimed_id")
	}
}

func TestVerifyCallback_ChecksAuthenticationWithSteam(t *testing.T) {
	// Мокаем Steam-сервер: отвечаем "is_valid:true" на check_authentication
	mockSteam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ns:http://specs.openid.net/auth/2.0\nis_valid:true\n"))
	}))
	defer mockSteam.Close()

	verifier := &SteamOpenIDVerifier{steamEndpoint: mockSteam.URL}

	values := map[string][]string{
		"openid.claimed_id": {"https://steamcommunity.com/openid/id/76561198000000001"},
	}
	steamID, err := verifier.Verify(values)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if steamID != "76561198000000001" {
		t.Errorf("got %s", steamID)
	}
}

func TestVerifyCallback_RejectsInvalid(t *testing.T) {
	mockSteam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ns:http://specs.openid.net/auth/2.0\nis_valid:false\n"))
	}))
	defer mockSteam.Close()

	verifier := &SteamOpenIDVerifier{steamEndpoint: mockSteam.URL}
	values := map[string][]string{
		"openid.claimed_id": {"https://steamcommunity.com/openid/id/76561198000000001"},
	}
	if _, err := verifier.Verify(values); err == nil {
		t.Error("expected error when Steam reports is_valid:false")
	}
}
