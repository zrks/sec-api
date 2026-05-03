package findings

import (
	"testing"
	"time"

	"github.com/zrks/sec-api/internal/scanner"
)

func TestBuildFindings(t *testing.T) {
	observations := []scanner.Observation{
		{Category: "dns", Key: "SPF", Value: map[string]any{"records": []string{"v=spf1 +all"}}},
		{Category: "http", Key: "hsts", Value: map[string]any{"present": false}},
		{Category: "http", Key: "csp", Value: map[string]any{"present": false}},
		{Category: "http", Key: "x_frame_options", Value: map[string]any{"present": false}},
		{Category: "http", Key: "x_content_type_options", Value: map[string]any{"present": false}},
		{Category: "http", Key: "server_header", Value: map[string]any{"present": true, "value": "nginx"}},
		{Category: "tls", Key: "expiry", Value: map[string]any{"days_remaining": 7, "not_after": time.Now().Add(7 * 24 * time.Hour).Format(time.RFC3339)}},
	}

	findings := Build("example.com", observations)
	if len(findings) == 0 {
		t.Fatal("expected findings to be generated")
	}
	if Score(findings) >= 100 {
		t.Fatal("expected score to decrease from 100")
	}
	if len(GroupBySeverity(findings)[string(SeverityHigh)]) == 0 {
		t.Fatal("expected at least one high severity finding")
	}
}

func TestBuildFindingsDetectsMissingDMARC(t *testing.T) {
	findings := Build("example.org", []scanner.Observation{{Category: "dns", Key: "SPF", Value: map[string]any{"records": []string{"v=spf1 -all"}}}})
	grouped := GroupBySeverity(findings)
	if len(grouped[string(SeverityHigh)]) == 0 {
		t.Fatal("expected a high-severity finding for missing DMARC")
	}
}

func TestBuildFindingsDetectsSPFAll(t *testing.T) {
	findings := Build("example.org", []scanner.Observation{{Category: "dns", Key: "SPF", Value: map[string]any{"records": []string{"v=spf1 +all"}}}, {Category: "dns", Key: "DMARC", Value: map[string]any{"records": []string{"v=DMARC1; p=reject"}}}, {Category: "dns", Key: "CAA", Value: map[string]any{"records": []string{"0 issue \"letsencrypt.org\""}}}})
	found := false
	for _, finding := range findings {
		if finding.Title == "SPF allows +all" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected SPF +all finding")
	}
}

func TestScoreClampsToZero(t *testing.T) {
	findings := make([]Finding, 0, 10)
	for i := 0; i < 10; i++ {
		findings = append(findings, Finding{Severity: SeverityCritical})
	}
	if score := Score(findings); score != 0 {
		t.Fatalf("expected score to clamp at 0, got %d", score)
	}
}

func TestFixFirstPrioritizesCertificateFailure(t *testing.T) {
	ordered := FixFirst([]Finding{
		{Severity: SeverityMedium, Title: "CSP missing"},
		{Severity: SeverityCritical, Title: "TLS certificate expired"},
		{Severity: SeverityHigh, Title: "DMARC missing"},
	})
	if len(ordered) < 2 {
		t.Fatalf("expected multiple findings in fix-first list")
	}
	if ordered[0].Title != "TLS certificate expired" {
		t.Fatalf("expected certificate finding first, got %q", ordered[0].Title)
	}
}
