package auth

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSetRefreshCookie_SecureWhenTLS(t *testing.T) {
	req := httptest.NewRequest("GET", "https://example.com/", nil)
	req.TLS = &tls.ConnectionState{} // симулируем реальный TLS-хендшейк

	rec := httptest.NewRecorder()
	SetRefreshCookie(rec, req, "sometoken", nil)

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if !c.Secure {
		t.Error("expected Secure=true when r.TLS != nil")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("expected SameSite=Strict, got %v", c.SameSite)
	}
}

func TestSetRefreshCookie_InsecureOnPlainHTTP(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	rec := httptest.NewRecorder()

	SetRefreshCookie(rec, req, "sometoken", nil)

	c := rec.Result().Cookies()[0]
	if c.Secure {
		t.Error("expected Secure=false on plain HTTP without trusted proxy")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected SameSite=Lax, got %v", c.SameSite)
	}
}

func TestSetRefreshCookie_TrustsForwardedProtoFromAllowedProxyIP(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "10.0.0.5:12345"
	req.Header.Set("X-Forwarded-Proto", "https")

	rec := httptest.NewRecorder()
	SetRefreshCookie(rec, req, "sometoken", map[string]struct{}{"10.0.0.5": {}})

	c := rec.Result().Cookies()[0]
	if !c.Secure {
		t.Error("expected Secure=true when trusted proxy reports https")
	}
}

func TestSetRefreshCookie_IgnoresForwardedProtoFromUntrustedIP(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	req.Header.Set("X-Forwarded-Proto", "https") // подделка от недоверенного источника

	rec := httptest.NewRecorder()
	SetRefreshCookie(rec, req, "sometoken", map[string]struct{}{"10.0.0.5": {}})

	c := rec.Result().Cookies()[0]
	if c.Secure {
		t.Error("expected Secure=false: X-Forwarded-Proto from untrusted IP must be ignored")
	}
}
