package diff

import (
	"encoding/json"

	"github.com/zrks/sec-api/internal/scanner"
)

type ChangeType string

const (
	ChangeAdded     ChangeType = "added"
	ChangeRemoved   ChangeType = "removed"
	ChangeChanged   ChangeType = "changed"
	ChangeUnchanged ChangeType = "unchanged"
)

type ObservationDiff struct {
	ChangeType ChangeType `json:"change_type"`
	Category   string     `json:"category"`
	Subject    string     `json:"subject"`
	Key        string     `json:"key"`
	OldValue   any        `json:"old_value,omitempty"`
	NewValue   any        `json:"new_value,omitempty"`
}

type identity struct {
	category string
	subject  string
	key      string
}

func Compare(previous, current []scanner.Observation) []ObservationDiff {
	previousByID := map[identity]scanner.Observation{}
	currentByID := map[identity]scanner.Observation{}
	ordered := make([]identity, 0, len(previous)+len(current))

	for _, observation := range previous {
		id := makeIdentity(observation)
		if _, exists := previousByID[id]; !exists {
			ordered = append(ordered, id)
		}
		previousByID[id] = observation
	}

	for _, observation := range current {
		id := makeIdentity(observation)
		if _, exists := currentByID[id]; !exists {
			ordered = append(ordered, id)
		}
		currentByID[id] = observation
	}

	diffs := make([]ObservationDiff, 0, len(ordered))
	seen := map[identity]struct{}{}
	for _, id := range ordered {
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}

		prev, hasPrev := previousByID[id]
		curr, hasCurr := currentByID[id]
		switch {
		case hasPrev && hasCurr:
			if valuesEqual(prev.Value, curr.Value) {
				diffs = append(diffs, ObservationDiff{ChangeType: ChangeUnchanged, Category: id.category, Subject: id.subject, Key: id.key, OldValue: prev.Value, NewValue: curr.Value})
			} else {
				diffs = append(diffs, ObservationDiff{ChangeType: ChangeChanged, Category: id.category, Subject: id.subject, Key: id.key, OldValue: prev.Value, NewValue: curr.Value})
			}
		case hasCurr:
			diffs = append(diffs, ObservationDiff{ChangeType: ChangeAdded, Category: id.category, Subject: id.subject, Key: id.key, NewValue: curr.Value})
		case hasPrev:
			diffs = append(diffs, ObservationDiff{ChangeType: ChangeRemoved, Category: id.category, Subject: id.subject, Key: id.key, OldValue: prev.Value})
		}
	}

	return diffs
}

func makeIdentity(observation scanner.Observation) identity {
	return identity{category: observation.Category, subject: observation.Subject, key: observation.Key}
}

func valuesEqual(left, right any) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	return string(leftBytes) == string(rightBytes)
}
