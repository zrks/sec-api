package subdomains

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/zrks/sec-api/internal/scanner"
)

type Scanner struct {
	client *http.Client
}

func New() *Scanner {
	return &Scanner{client: &http.Client{Timeout: 10 * time.Second}}
}

func (s *Scanner) Name() string {
	return "subdomains"
}

func (s *Scanner) Scan(ctx context.Context, target scanner.Target) ([]scanner.Observation, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", target.Domain), nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return []scanner.Observation{{Category: "subdomain", Subject: target.Domain, Key: "provider_error", Value: map[string]any{"provider": "crtsh", "error": err.Error()}}}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return []scanner.Observation{{Category: "subdomain", Subject: target.Domain, Key: "provider_error", Value: map[string]any{"provider": "crtsh", "status": resp.StatusCode}}}, nil
	}

	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return []scanner.Observation{{Category: "subdomain", Subject: target.Domain, Key: "provider_error", Value: map[string]any{"provider": "crtsh", "error": err.Error()}}}, nil
	}

	unique := map[string]struct{}{}
	var observations []scanner.Observation
	for _, row := range rows {
		for _, candidate := range strings.Split(row.NameValue, "\n") {
			hostname := normalizeHostname(candidate, target.Domain)
			if hostname == "" {
				continue
			}
			if _, exists := unique[hostname]; exists {
				continue
			}
			unique[hostname] = struct{}{}
			observations = append(observations, scanner.Observation{
				Category: "subdomain",
				Subject:  hostname,
				Key:      "discovered",
				Value: map[string]any{
					"hostname":    hostname,
					"root_domain": target.Domain,
					"source":      "crtsh",
				},
			})
		}
	}

	return observations, nil
}

func normalizeHostname(value, rootDomain string) string {
	hostname := strings.TrimSpace(strings.ToLower(value))
	hostname = strings.TrimPrefix(hostname, "*.")
	hostname = strings.TrimSuffix(hostname, ".")
	if hostname == "" || hostname == rootDomain {
		return ""
	}
	if !strings.HasSuffix(hostname, "."+rootDomain) {
		return ""
	}
	return hostname
}
