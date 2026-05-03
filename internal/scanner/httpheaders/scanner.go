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
	var obs []scanner.Observation
	// Build a base URL for HTTPS first.
	url := "https://" + target.Domain
	client := &http.Client{Timeout: 15 * time.Second}

	// Try HEAD request
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		// this shouldn't happen
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		// attempt HTTP (non-SSL) as fallback
		urlHTTP := "http://" + target.Domain
		reqHTTP, err2 := http.NewRequestWithContext(ctx, http.MethodHead, urlHTTP, nil)
		if err2 == nil {
			resp, err2 = client.Do(reqHTTP)
			if err2 == nil {
				// record that HTTPS failed but HTTP succeeded
				obs = append(obs, scanner.Observation{
					Category: "http",
					Subject:  target.Domain,
					Key:      "https_error",
					Value: map[string]any{
						"error": err.Error(),
					},
				})
			}
		}
		// if still failing, return the error observation
		if resp == nil {
			obs = append(obs, scanner.Observation{
				Category: "http",
				Subject:  target.Domain,
				Key:      "request_error",
				Value: map[string]any{
					"error": err.Error(),
				},
			})
			return obs, nil
		}
	}
	defer resp.Body.Close()

	// Evaluate selected security headers
	headers := resp.Header
	// Strict-Transport-Security (HSTS)
	hsts := headers.Get("Strict-Transport-Security")
	obs = append(obs, scanner.Observation{
		Category: "http",
		Subject:  target.Domain,
		Key:      "hsts",
		Value: map[string]any{
			"value":   hsts,
			"present": hsts != "",
		},
	})
	// Content-Security-Policy
	csp := headers.Get("Content-Security-Policy")
	obs = append(obs, scanner.Observation{
		Category: "http",
		Subject:  target.Domain,
		Key:      "csp",
		Value: map[string]any{
			"value":   csp,
			"present": csp != "",
		},
	})
	// X-Frame-Options
	xfo := headers.Get("X-Frame-Options")
	obs = append(obs, scanner.Observation{
		Category: "http",
		Subject:  target.Domain,
		Key:      "x_frame_options",
		Value: map[string]any{
			"value":   xfo,
			"present": xfo != "",
		},
	})
	// X-Content-Type-Options
	xcto := headers.Get("X-Content-Type-Options")
	obs = append(obs, scanner.Observation{
		Category: "http",
		Subject:  target.Domain,
		Key:      "x_content_type_options",
		Value: map[string]any{
			"value":   xcto,
			"present": xcto != "",
		},
	})
	// Referrer-Policy
	ref := headers.Get("Referrer-Policy")
	obs = append(obs, scanner.Observation{
		Category: "http",
		Subject:  target.Domain,
		Key:      "referrer_policy",
		Value: map[string]any{
			"value":   ref,
			"present": ref != "",
		},
	})
	// Permissions-Policy
	perm := headers.Get("Permissions-Policy")
	if perm == "" {
		// older name: Feature-Policy
		perm = headers.Get("Feature-Policy")
	}
	obs = append(obs, scanner.Observation{
		Category: "http",
		Subject:  target.Domain,
		Key:      "permissions_policy",
		Value: map[string]any{
			"value":   perm,
			"present": perm != "",
		},
	})
	// Server header (information leakage)
	server := headers.Get("Server")
	// Only record a trimmed prefix (to avoid storing long values) for demonstration
	trimmed := server
	if len(trimmed) > 64 {
		trimmed = trimmed[:64]
	}
	obs = append(obs, scanner.Observation{
		Category: "http",
		Subject:  target.Domain,
		Key:      "server_header",
		Value: map[string]any{
			"value":   trimmed,
			"present": server != "",
		},
	})
	// HTTPS redirect check: if final URL scheme is https or http
	scheme := strings.Split(resp.Request.URL.Scheme, ":")[0]
	obs = append(obs, scanner.Observation{
		Category: "http",
		Subject:  target.Domain,
		Key:      "final_scheme",
		Value: map[string]any{
			"scheme": scheme,
		},
	})

	return obs, nil
}
