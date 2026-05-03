package diff

import (
	"testing"

	"github.com/zrks/sec-api/internal/scanner"
)

func TestCompareDetectsChanges(t *testing.T) {
	previous := []scanner.Observation{{Category: "dns", Subject: "example.com", Key: "MX", Value: map[string]any{"records": []string{"mx1.example.com"}}}}
	current := []scanner.Observation{{Category: "dns", Subject: "example.com", Key: "MX", Value: map[string]any{"records": []string{"mx2.example.com"}}}, {Category: "subdomain", Subject: "app.example.com", Key: "discovered", Value: map[string]any{"hostname": "app.example.com"}}}

	diffs := Compare(previous, current)
	if len(diffs) != 2 {
		t.Fatalf("expected 2 diffs, got %d", len(diffs))
	}
	if diffs[0].ChangeType != ChangeChanged {
		t.Fatalf("expected first diff to be changed, got %s", diffs[0].ChangeType)
	}
	if diffs[1].ChangeType != ChangeAdded {
		t.Fatalf("expected second diff to be added, got %s", diffs[1].ChangeType)
	}
}

func TestCompareDetectsRemovedObservation(t *testing.T) {
	previous := []scanner.Observation{{Category: "whois", Subject: "example.com", Key: "status", Value: map[string]any{"values": []string{"active"}}}}
	diffs := Compare(previous, nil)
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d", len(diffs))
	}
	if diffs[0].ChangeType != ChangeRemoved {
		t.Fatalf("expected removed diff, got %s", diffs[0].ChangeType)
	}
}

func TestCompareDetectsUnchangedObservation(t *testing.T) {
	previous := []scanner.Observation{{Category: "http", Subject: "example.com", Key: "hsts", Value: map[string]any{"present": true}}}
	current := []scanner.Observation{{Category: "http", Subject: "example.com", Key: "hsts", Value: map[string]any{"present": true}}}
	diffs := Compare(previous, current)
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d", len(diffs))
	}
	if diffs[0].ChangeType != ChangeUnchanged {
		t.Fatalf("expected unchanged diff, got %s", diffs[0].ChangeType)
	}
}
