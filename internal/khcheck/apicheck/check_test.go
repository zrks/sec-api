package apicheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRunPassesAgainstHealthyAPI(t *testing.T) {
	server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		if handleCORS(w, r) {
			return
		}
		switch r.URL.Path {
		case "/healthz":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		case "/api/v1/version":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"version":"mvp"}`))
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html></html>"))
		default:
			http.NotFound(w, r)
		}
	})

	failures := Run(context.Background(), Config{BaseURL: server.URL, CheckRootHeaders: true, Timeout: time.Second})
	if len(failures) != 0 {
		t.Fatalf("expected no failures, got %v", failures)
	}
}

func TestRunFailsWhenHealthzIsBroken(t *testing.T) {
	server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		if handleCORS(w, r) {
			return
		}
		if r.URL.Path == "/healthz" {
			http.Error(w, "nope", http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/api/v1/version" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":"mvp"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	failures := Run(context.Background(), Config{BaseURL: server.URL, CheckRootHeaders: false, Timeout: time.Second})
	assertFailureContains(t, failures, "health endpoint returned 503")
}

func TestRunFailsWhenVersionJSONIsInvalid(t *testing.T) {
	server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		if handleCORS(w, r) {
			return
		}
		switch r.URL.Path {
		case "/healthz":
			_, _ = w.Write([]byte("ok"))
		case "/api/v1/version":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	})

	failures := Run(context.Background(), Config{BaseURL: server.URL, CheckRootHeaders: false, Timeout: time.Second})
	assertFailureContains(t, failures, "version endpoint returned invalid JSON")
}

func TestRunFailsWhenSecurityHeadersAreMissing(t *testing.T) {
	server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if handleCORS(w, r) {
			return
		}
		switch r.URL.Path {
		case "/healthz":
			_, _ = w.Write([]byte("ok"))
		case "/api/v1/version":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":"mvp"}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	})

	failures := Run(context.Background(), Config{BaseURL: server.URL, CheckRootHeaders: true, Timeout: time.Second})
	assertFailureContains(t, failures, "missing Content-Security-Policy")
	assertFailureContains(t, failures, "X-Content-Type-Options: nosniff")
	assertFailureContains(t, failures, "X-Frame-Options: DENY")
}

func TestRunFailsWhenBlockedOriginIsAllowed(t *testing.T) {
	server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			w.WriteHeader(http.StatusNoContent)
			return
		}
		switch r.URL.Path {
		case "/healthz":
			_, _ = w.Write([]byte("ok"))
		case "/api/v1/version":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":"mvp"}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	})

	failures := Run(context.Background(), Config{BaseURL: server.URL, CheckRootHeaders: false, Timeout: time.Second})
	assertFailureContains(t, failures, "blocked origin should not be reflected")
}

func TestRunFailsWhenHTTPSIsRequired(t *testing.T) {
	server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		if handleCORS(w, r) {
			return
		}
		switch r.URL.Path {
		case "/healthz":
			_, _ = w.Write([]byte("ok"))
		case "/api/v1/version":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":"mvp"}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	})

	failures := Run(context.Background(), Config{BaseURL: server.URL, CheckRootHeaders: false, RequireHTTPS: true, Timeout: time.Second})
	assertFailureContains(t, failures, "must use https")
}

func TestRunFailsOnTimeout(t *testing.T) {
	server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		setSecurityHeaders(w)
		if handleCORS(w, r) {
			return
		}
		if r.URL.Path == "/api/v1/version" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":"mvp"}`))
			return
		}
		_, _ = w.Write([]byte("ok"))
	})

	failures := Run(context.Background(), Config{BaseURL: server.URL, CheckRootHeaders: false, Timeout: 10 * time.Millisecond})
	assertFailureContains(t, failures, "health endpoint check failed")
}

func newTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
}

func handleCORS(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "http://localhost:5173" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

func assertFailureContains(t *testing.T, failures []string, want string) {
	t.Helper()
	for _, failure := range failures {
		if strings.Contains(failure, want) {
			return
		}
	}
	t.Fatalf("expected failure containing %q, got %v", want, failures)
}

func TestRunRequiresBaseURL(t *testing.T) {
	failures := Run(context.Background(), Config{})
	if len(failures) != 1 || failures[0] != "API_BASE_URL is required" {
		t.Fatalf("unexpected failures: %v", failures)
	}
}
