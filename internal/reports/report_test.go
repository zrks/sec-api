package reports

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/zrks/sec-api/internal/diff"
	"github.com/zrks/sec-api/internal/scanner"
	"github.com/zrks/sec-api/internal/scanner/findings"
)

func TestBuildIncludesFixFirst(t *testing.T) {
	report := Build(
		"example.org",
		uuid.New(),
		72,
		[]scanner.Observation{{Category: "dns", Subject: "example.org", Key: "MX", Value: map[string]any{"records": []string{"mx1.example.org"}}}},
		[]diff.ObservationDiff{{ChangeType: diff.ChangeAdded, Category: "dns", Subject: "example.org", Key: "MX", NewValue: map[string]any{"records": []string{"mx1.example.org"}}}},
		[]findings.Finding{{Severity: findings.SeverityCritical, Title: "TLS certificate expired"}, {Severity: findings.SeverityMedium, Title: "CSP missing"}},
		time.Now(),
	)
	if len(report.FixFirst) == 0 {
		t.Fatal("expected fix-first list in report")
	}
}
