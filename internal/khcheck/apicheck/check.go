package apicheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	BaseURL           string
	CheckRootHeaders  bool
	RequireHTTPS      bool
	AllowedCORSOrigin string
	BlockedCORSOrigin string
	Timeout           time.Duration
}

type versionResponse struct {
	Version string `json:"version"`
}

func Run(ctx context.Context, cfg Config) []string {
	var failures []string

	if cfg.BaseURL == "" {
		return []string{"API_BASE_URL is required"}
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.AllowedCORSOrigin == "" {
		cfg.AllowedCORSOrigin = "http://localhost:5173"
	}
	if cfg.BlockedCORSOrigin == "" {
		cfg.BlockedCORSOrigin = "https://example.com"
	}

	baseURL, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return []string{fmt.Sprintf("API_BASE_URL is invalid: %v", err)}
	}
	if cfg.RequireHTTPS && baseURL.Scheme != "https" {
		failures = append(failures, fmt.Sprintf("API_BASE_URL must use https when REQUIRE_HTTPS is enabled: %s", cfg.BaseURL))
	}

	client := &http.Client{Timeout: cfg.Timeout}

	if err := checkHealth(ctx, client, baseURL); err != nil {
		failures = append(failures, err.Error())
	}
	if err := checkVersion(ctx, client, baseURL); err != nil {
		failures = append(failures, err.Error())
	}
	if err := checkCORS(ctx, client, baseURL, cfg.AllowedCORSOrigin, cfg.BlockedCORSOrigin); err != nil {
		failures = append(failures, err.Error())
	}
	if cfg.CheckRootHeaders {
		if err := checkRootHeaders(ctx, client, baseURL); err != nil {
			failures = append(failures, err.Error())
		}
	}

	return failures
}

func checkHealth(ctx context.Context, client *http.Client, baseURL *url.URL) error {
	body, headers, statusCode, err := doRequest(ctx, client, baseURL, http.MethodGet, "/healthz", "")
	if err != nil {
		return fmt.Errorf("health endpoint check failed: %w", err)
	}
	if statusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned %d", statusCode)
	}
	if strings.TrimSpace(string(body)) != "ok" {
		return fmt.Errorf("health endpoint returned unexpected body: %q", strings.TrimSpace(string(body)))
	}
	if !strings.Contains(headers.Get("Content-Security-Policy"), "default-src 'self'") {
		return fmt.Errorf("health endpoint is missing Content-Security-Policy")
	}
	return nil
}

func checkVersion(ctx context.Context, client *http.Client, baseURL *url.URL) error {
	body, headers, statusCode, err := doRequest(ctx, client, baseURL, http.MethodGet, "/api/v1/version", "")
	if err != nil {
		return fmt.Errorf("version endpoint check failed: %w", err)
	}
	if statusCode != http.StatusOK {
		return fmt.Errorf("version endpoint returned %d", statusCode)
	}
	if !strings.Contains(headers.Get("Content-Type"), "application/json") {
		return fmt.Errorf("version endpoint returned unexpected Content-Type: %q", headers.Get("Content-Type"))
	}
	var payload versionResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("version endpoint returned invalid JSON: %w", err)
	}
	if strings.TrimSpace(payload.Version) == "" {
		return fmt.Errorf("version endpoint returned an empty version")
	}
	return nil
}

func checkCORS(ctx context.Context, client *http.Client, baseURL *url.URL, allowedOrigin, blockedOrigin string) error {
	_, headers, statusCode, err := doRequest(ctx, client, baseURL, http.MethodOptions, "/api/v1/version", allowedOrigin)
	if err != nil {
		return fmt.Errorf("allowed origin CORS check failed: %w", err)
	}
	if statusCode != http.StatusNoContent {
		return fmt.Errorf("allowed origin preflight returned %d", statusCode)
	}
	if headers.Get("Access-Control-Allow-Origin") != allowedOrigin {
		return fmt.Errorf("allowed origin was not reflected in Access-Control-Allow-Origin")
	}

	_, headers, statusCode, err = doRequest(ctx, client, baseURL, http.MethodOptions, "/api/v1/version", blockedOrigin)
	if err != nil {
		return fmt.Errorf("blocked origin CORS check failed: %w", err)
	}
	if statusCode != http.StatusNoContent {
		return fmt.Errorf("blocked origin preflight returned %d", statusCode)
	}
	if headers.Get("Access-Control-Allow-Origin") != "" {
		return fmt.Errorf("blocked origin should not be reflected in Access-Control-Allow-Origin")
	}
	return nil
}

func checkRootHeaders(ctx context.Context, client *http.Client, baseURL *url.URL) error {
	_, headers, statusCode, err := doRequest(ctx, client, baseURL, http.MethodGet, "/", "")
	if err != nil {
		return fmt.Errorf("root page check failed: %w", err)
	}
	if statusCode != http.StatusOK {
		return fmt.Errorf("root page returned %d", statusCode)
	}
	var problems []string
	if !strings.Contains(headers.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		problems = append(problems, "restrictive Content-Security-Policy")
	}
	if headers.Get("X-Content-Type-Options") != "nosniff" {
		problems = append(problems, "X-Content-Type-Options: nosniff")
	}
	if headers.Get("X-Frame-Options") != "DENY" {
		problems = append(problems, "X-Frame-Options: DENY")
	}
	if len(problems) > 0 {
		return fmt.Errorf("root page is missing %s", strings.Join(problems, ", "))
	}
	return nil
}

func doRequest(ctx context.Context, client *http.Client, baseURL *url.URL, method, path, origin string) ([]byte, http.Header, int, error) {
	requestURL := *baseURL
	requestURL.Path = path
	requestURL.RawQuery = ""

	req, err := http.NewRequestWithContext(ctx, method, requestURL.String(), nil)
	if err != nil {
		return nil, nil, 0, err
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", http.MethodGet)
		if method == http.MethodOptions {
			req.Header.Set("Access-Control-Request-Headers", "Content-Type")
		}
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, nil, 0, err
	}

	body, err := ioReadAll(res.Body)
	if err != nil {
		return nil, nil, 0, err
	}
	return body, res.Header.Clone(), res.StatusCode, nil
}

func ioReadAll(body io.ReadCloser) ([]byte, error) {
	defer body.Close()
	return io.ReadAll(body)
}
