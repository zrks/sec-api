package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestHealthz(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	newRouter(nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) != "ok" {
		t.Fatalf("expected ok body, got %q", rec.Body.String())
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("expected nosniff header")
	}
}

func TestVersionEndpoint(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	rec := httptest.NewRecorder()

	newRouter(nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("expected application/json content type, got %q", rec.Header().Get("Content-Type"))
	}
	var payload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected valid json: %v", err)
	}
	if payload["version"] != "mvp" {
		t.Fatalf("expected version mvp, got %q", payload["version"])
	}
}

func TestCORSAllowsLocalhostOrigin(t *testing.T) {
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/version", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	rec := httptest.NewRecorder()

	newRouter(nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "http://localhost:5173" {
		t.Fatalf("expected allowed origin to be reflected, got %q", rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCORSBlocksForeignOrigin(t *testing.T) {
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/version", nil)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()

	newRouter(nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("expected no CORS origin for foreign site, got %q", got)
	}
}

func TestVerifyAliasReturnsGone(t *testing.T) {
	id := uuid.NewString()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domains/"+id+"/verify", nil)
	rec := httptest.NewRecorder()

	newRouter(nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusGone {
		t.Fatalf("expected 410, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "verify-ownership") {
		t.Fatalf("expected verify-ownership guidance, got %q", rec.Body.String())
	}
}

func TestRootSetsSecurityHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	newRouter(nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("expected DENY frame header")
	}
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("expected restrictive CSP, got %q", rec.Header().Get("Content-Security-Policy"))
	}
}
