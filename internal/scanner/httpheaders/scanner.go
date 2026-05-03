package httpheaders

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/zrks/sec-api/internal/scanner"
)

// Scanner implements an HTTP security header scanner. It issues a HEAD request
// to the target domain over HTTPS (falling back to HTTP on failure) and
// records the presence of various security-related headers. If the request
// fails, a single observation is returned describing the failure.
type Scanner struct{}

// New returns a new HTTP header scanner.
func New() *Scanner {
	return &Scanner{}
}

// Name returns the scanner name.
func (s *Scanner) Name() string {
	return "httpheaders"
}

// Scan performs the HTTP header scan for the given target. It attempts a
// HEAD request first; if HEAD is not allowed, it falls back to GET. The
// result includes observations for each relevant security header.
func (s *Scanner) Scan(ctx context.Context, target scanner.Target) ([]scanner.Observation, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var obs []scanner.Observation
	client := &http.Client{Timeout: 10 * time.Second}
	targets := []string{target.Domain}
	if !strings.HasPrefix(target.Domain, "www.") {
		targets = append(targets, "www."+target.Domain)
	}
	for _, hostname := range targets {
		obs = append(obs, scanHTTP(ctx, client, hostname)...)
	}

	return obs, nil
}

func scanHTTP(ctx context.Context, client *http.Client, hostname string) []scanner.Observation {
	url := "https://" + hostname
	resp, err := requestWithFallback(ctx, client, url)
	if err != nil {
		return []scanner.Observation{{Category: "http", Subject: hostname, Key: "https_error", Value: map[string]any{"error": err.Error()}}}
	}
	defer resp.Body.Close()

	var obs []scanner.Observation
	obs = append(obs, scanner.Observation{Category: "http", Subject: hostname, Key: "status", Value: map[string]any{"code": resp.StatusCode, "final_url": resp.Request.URL.String(), "final_scheme": resp.Request.URL.Scheme}})
	headers := resp.Header
	obs = append(obs, scanner.Observation{Category: "http", Subject: hostname, Key: "headers", Value: map[string]any{"header_count": len(headers)}})
	obs = append(obs, scanner.Observation{Category: "http", Subject: hostname, Key: "hsts", Value: map[string]any{"value": headers.Get("Strict-Transport-Security"), "present": headers.Get("Strict-Transport-Security") != ""}})
	obs = append(obs, scanner.Observation{Category: "http", Subject: hostname, Key: "csp", Value: map[string]any{"value": headers.Get("Content-Security-Policy"), "present": headers.Get("Content-Security-Policy") != ""}})
	obs = append(obs, scanner.Observation{Category: "http", Subject: hostname, Key: "x_frame_options", Value: map[string]any{"value": headers.Get("X-Frame-Options"), "present": headers.Get("X-Frame-Options") != ""}})
	obs = append(obs, scanner.Observation{Category: "http", Subject: hostname, Key: "x_content_type_options", Value: map[string]any{"value": headers.Get("X-Content-Type-Options"), "present": headers.Get("X-Content-Type-Options") != ""}})
	obs = append(obs, scanner.Observation{Category: "http", Subject: hostname, Key: "referrer_policy", Value: map[string]any{"value": headers.Get("Referrer-Policy"), "present": headers.Get("Referrer-Policy") != ""}})
	permissionsPolicy := headers.Get("Permissions-Policy")
	if permissionsPolicy == "" {
		permissionsPolicy = headers.Get("Feature-Policy")
	}
	obs = append(obs, scanner.Observation{Category: "http", Subject: hostname, Key: "permissions_policy", Value: map[string]any{"value": permissionsPolicy, "present": permissionsPolicy != ""}})
	server := headers.Get("Server")
	trimmed := server
	if len(trimmed) > 64 {
		trimmed = trimmed[:64]
	}
	obs = append(obs, scanner.Observation{Category: "http", Subject: hostname, Key: "server_header", Value: map[string]any{"value": trimmed, "present": server != ""}})
	obs = append(obs, scanner.Observation{Category: "http", Subject: hostname, Key: "final_scheme", Value: map[string]any{"scheme": strings.Split(resp.Request.URL.Scheme, ":")[0]}})
	return obs
}

func requestWithFallback(ctx context.Context, client *http.Client, url string) (*http.Response, error) {
	headReq, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(headReq)
	if err == nil && resp.StatusCode != http.StatusMethodNotAllowed {
		return resp, nil
	}
	if resp != nil {
		resp.Body.Close()
	}
	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(getReq)
}
