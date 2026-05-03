package scanner

import (
	"context"
)

// Target identifies what a scanner should inspect.
type Target struct {
	Domain string
}

// Observation is a single fact collected by a scanner.
type Observation struct {
	Category string
	Subject  string
	Key      string
	Value    any
}

// Scanner defines the common contract implemented by all scanners.
type Scanner interface {
	Name() string
	Scan(context.Context, Target) ([]Observation, error)
}

// Run executes the provided scanners against a target and aggregates
// observations. If any scanner returns an error, it is returned immediately
// along with the observations collected so far. This simple helper makes
// orchestrating multiple scanner implementations easier.
func Run(ctx context.Context, scanners []Scanner, target Target) ([]Observation, error) {
    var all []Observation
    for _, s := range scanners {
        obs, err := s.Scan(ctx, target)
        if err != nil {
            return all, err
        }
        all = append(all, obs...)
    }
    return all, nil
}
