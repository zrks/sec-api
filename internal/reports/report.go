package reports

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/zrks/sec-api/internal/diff"
	"github.com/zrks/sec-api/internal/scanner"
	"github.com/zrks/sec-api/internal/scanner/findings"
)

// Report is the JSON payload returned by the latest-report endpoint and stored in the DB.
type Report struct {
	Domain             string                        `json:"domain"`
	ScanRunID          string                        `json:"scan_run_id"`
	Score              int                           `json:"score"`
	GeneratedAt        time.Time                     `json:"generated_at"`
	Findings           map[string][]findings.Finding `json:"findings"`
	FixFirst           []findings.Finding            `json:"fix_first"`
	Changes            []Change                      `json:"changes"`
	Sections           Sections                      `json:"sections"`
	ObservationSummary ObservationSummary            `json:"observation_summary"`
	Observations       []scanner.Observation         `json:"observations"`
}

type ObservationSummary struct {
	Total      int            `json:"total"`
	ByCategory map[string]int `json:"by_category"`
}

type Change struct {
	ChangeType string `json:"change_type"`
	Category   string `json:"category"`
	Subject    string `json:"subject"`
	Key        string `json:"key"`
	OldValue   any    `json:"old_value,omitempty"`
	NewValue   any    `json:"new_value,omitempty"`
}

type Sections struct {
	Subdomains         []scanner.Observation `json:"subdomains"`
	DNS                []scanner.Observation `json:"dns"`
	Whois              []scanner.Observation `json:"whois"`
	TLS                []scanner.Observation `json:"tls"`
	HTTP               []scanner.Observation `json:"http"`
	PublicServices     []scanner.Observation `json:"public_services"`
	VulnerabilityWatch []scanner.Observation `json:"vulnerability_watch"`
}

// Build creates a report payload from a completed scan run.
func Build(domain string, scanRunID uuid.UUID, score int, obs []scanner.Observation, diffs []diff.ObservationDiff, f []findings.Finding, generatedAt time.Time) Report {
	byCategory := map[string]int{}
	sections := Sections{}
	for _, observation := range obs {
		byCategory[observation.Category]++
		switch observation.Category {
		case "subdomain":
			sections.Subdomains = append(sections.Subdomains, observation)
		case "dns":
			sections.DNS = append(sections.DNS, observation)
		case "whois":
			sections.Whois = append(sections.Whois, observation)
		case "tls":
			sections.TLS = append(sections.TLS, observation)
		case "http":
			sections.HTTP = append(sections.HTTP, observation)
		}
	}

	fixFirst := findings.FixFirst(f)
	changes := make([]Change, 0, len(diffs))
	for _, item := range diffs {
		if item.ChangeType == diff.ChangeUnchanged {
			continue
		}
		changes = append(changes, Change{
			ChangeType: string(item.ChangeType),
			Category:   item.Category,
			Subject:    item.Subject,
			Key:        item.Key,
			OldValue:   normalizeJSON(item.OldValue),
			NewValue:   normalizeJSON(item.NewValue),
		})
	}

	return Report{
		Domain:      domain,
		ScanRunID:   scanRunID.String(),
		Score:       score,
		GeneratedAt: generatedAt.UTC(),
		Findings:    findings.GroupBySeverity(f),
		FixFirst:    fixFirst,
		Changes:     changes,
		Sections:    sections,
		ObservationSummary: ObservationSummary{
			Total:      len(obs),
			ByCategory: byCategory,
		},
		Observations: obs,
	}
}

func normalizeJSON(value any) any {
	bytes, err := json.Marshal(value)
	if err != nil {
		return value
	}
	var decoded any
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		return value
	}
	return decoded
}
