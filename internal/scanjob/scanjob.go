package scanjob

import (
	"context"
	"time"

	"github.com/google/uuid"
	dbpkg "github.com/zrks/sec-api/internal/db"
	"github.com/zrks/sec-api/internal/diff"
	"github.com/zrks/sec-api/internal/reports"
	"github.com/zrks/sec-api/internal/scanner"
	"github.com/zrks/sec-api/internal/scanner/findings"
)

type Result struct {
	ScanRunID     uuid.UUID
	Observations  []scanner.Observation
	Diffs         []diff.ObservationDiff
	Findings      []findings.Finding
	Report        reports.Report
	FinishedAtUTC time.Time
}

// Run executes scanners for a monitored domain, persists the results, and returns the report.
func Run(ctx context.Context, db *dbpkg.DB, domain dbpkg.Domain, scanners []scanner.Scanner, scanType string) (Result, error) {
	scanRunID, err := db.CreateScanRun(ctx, domain.ID, scanType)
	if err != nil {
		return Result{}, err
	}

	observations, runErr := scanner.Run(ctx, scanners, scanner.Target{Domain: domain.Name})
	previousObservations, err := db.LoadPreviousObservations(ctx, domain.ID, scanRunID)
	if err != nil {
		msg := err.Error()
		_ = db.FinishScanRun(ctx, scanRunID, &msg)
		_ = db.RecordDomainScan(ctx, domain.ID, "error", &msg)
		return Result{}, err
	}
	if err := db.StoreObservations(ctx, scanRunID, domain.ID, observations); err != nil {
		msg := err.Error()
		_ = db.FinishScanRun(ctx, scanRunID, &msg)
		_ = db.RecordDomainScan(ctx, domain.ID, "error", &msg)
		return Result{}, err
	}

	result := Result{
		ScanRunID:     scanRunID,
		Observations:  observations,
		Diffs:         diff.Compare(previousObservations, observations),
		FinishedAtUTC: time.Now().UTC(),
	}
	if err := db.StoreObservationDiffs(ctx, scanRunID, domain.ID, result.Diffs); err != nil {
		msg := err.Error()
		_ = db.FinishScanRun(ctx, scanRunID, &msg)
		_ = db.RecordDomainScan(ctx, domain.ID, "error", &msg)
		return result, err
	}

	if runErr != nil {
		msg := runErr.Error()
		_ = db.FinishScanRun(ctx, scanRunID, &msg)
		_ = db.RecordDomainScan(ctx, domain.ID, "error", &msg)
		return result, runErr
	}

	result.Findings = findings.Build(domain.Name, observations)
	if err := db.StoreFindings(ctx, scanRunID, domain.ID, dbpkg.FindingsFromEngine(result.Findings)); err != nil {
		msg := err.Error()
		_ = db.FinishScanRun(ctx, scanRunID, &msg)
		_ = db.RecordDomainScan(ctx, domain.ID, "error", &msg)
		return result, err
	}

	score := findings.Score(result.Findings)
	result.Report = reports.Build(domain.Name, scanRunID, score, observations, result.Diffs, result.Findings, result.FinishedAtUTC)
	if err := db.CreateReport(ctx, scanRunID, domain.ID, score, result.Report); err != nil {
		msg := err.Error()
		_ = db.FinishScanRun(ctx, scanRunID, &msg)
		_ = db.RecordDomainScan(ctx, domain.ID, "error", &msg)
		return result, err
	}

	if err := db.FinishScanRun(ctx, scanRunID, nil); err != nil {
		msg := err.Error()
		_ = db.RecordDomainScan(ctx, domain.ID, "error", &msg)
		return result, err
	}
	if err := db.RecordDomainScan(ctx, domain.ID, "active", nil); err != nil {
		return result, err
	}

	return result, nil
}
