package rdap

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
	return "rdap"
}

func (s *Scanner) Scan(ctx context.Context, target scanner.Target) ([]scanner.Observation, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://rdap.org/domain/%s", target.Domain), nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return []scanner.Observation{{Category: "whois", Subject: target.Domain, Key: "provider_error", Value: map[string]any{"provider": "rdap", "error": err.Error()}}}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return []scanner.Observation{{Category: "whois", Subject: target.Domain, Key: "provider_error", Value: map[string]any{"provider": "rdap", "status": resp.StatusCode}}}, nil
	}

	var payload struct {
		Status      []string `json:"status"`
		Nameservers []struct {
			LDHName string `json:"ldhName"`
		} `json:"nameservers"`
		Events []struct {
			EventAction string `json:"eventAction"`
			EventDate   string `json:"eventDate"`
		} `json:"events"`
		Entities []struct {
			Roles      []string `json:"roles"`
			VCardArray []any    `json:"vcardArray"`
		} `json:"entities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return []scanner.Observation{{Category: "whois", Subject: target.Domain, Key: "provider_error", Value: map[string]any{"provider": "rdap", "error": err.Error()}}}, nil
	}

	var observations []scanner.Observation
	if len(payload.Status) > 0 {
		observations = append(observations, scanner.Observation{Category: "whois", Subject: target.Domain, Key: "status", Value: map[string]any{"values": payload.Status}})
	}
	observations = append(observations, scanner.Observation{Category: "whois", Subject: target.Domain, Key: "source_url", Value: map[string]any{"url": req.URL.String()}})

	var nameservers []string
	for _, nameserver := range payload.Nameservers {
		if strings.TrimSpace(nameserver.LDHName) != "" {
			nameservers = append(nameservers, strings.ToLower(strings.TrimSuffix(nameserver.LDHName, ".")))
		}
	}
	if len(nameservers) > 0 {
		observations = append(observations, scanner.Observation{Category: "whois", Subject: target.Domain, Key: "nameservers", Value: map[string]any{"servers": nameservers}})
	}

	if registered := findEventDate(payload.Events, "registration"); registered != "" {
		observations = append(observations, scanner.Observation{Category: "whois", Subject: target.Domain, Key: "registration_date", Value: map[string]any{"date": registered}})
	}
	if expiry := findEventDate(payload.Events, "expiration"); expiry != "" {
		observations = append(observations, scanner.Observation{Category: "whois", Subject: target.Domain, Key: "expiry", Value: map[string]any{"date": expiry, "days_remaining": daysUntil(expiry)}})
	}
	if updated := findEventDate(payload.Events, "last changed"); updated != "" {
		observations = append(observations, scanner.Observation{Category: "whois", Subject: target.Domain, Key: "updated_date", Value: map[string]any{"date": updated}})
	}

	if registrar := findRegistrar(payload.Entities); registrar != "" {
		observations = append(observations, scanner.Observation{Category: "whois", Subject: target.Domain, Key: "registrar", Value: map[string]any{"name": registrar}})
	}

	return observations, nil
}

func findEventDate(events []struct {
	EventAction string `json:"eventAction"`
	EventDate   string `json:"eventDate"`
}, contains string) string {
	for _, event := range events {
		if strings.Contains(strings.ToLower(event.EventAction), contains) {
			return event.EventDate
		}
	}
	return ""
}

func daysUntil(value string) int {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return 0
	}
	return int(time.Until(parsed).Hours() / 24)
}

func findRegistrar(entities []struct {
	Roles      []string `json:"roles"`
	VCardArray []any    `json:"vcardArray"`
}) string {
	for _, entity := range entities {
		for _, role := range entity.Roles {
			if role != "registrar" {
				continue
			}
			if len(entity.VCardArray) < 2 {
				return ""
			}
			rows, ok := entity.VCardArray[1].([]any)
			if !ok {
				return ""
			}
			for _, row := range rows {
				parts, ok := row.([]any)
				if !ok || len(parts) < 4 {
					continue
				}
				name, _ := parts[0].(string)
				if name != "fn" {
					continue
				}
				value, _ := parts[3].(string)
				return value
			}
		}
	}
	return ""
}
