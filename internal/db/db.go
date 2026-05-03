package db

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zrks/sec-api/internal/diff"
	"github.com/zrks/sec-api/internal/scanner"
	enginefindings "github.com/zrks/sec-api/internal/scanner/findings"
)

// DB wraps a pgx connection pool and exposes helper methods
// for storing and retrieving domain risk digest data.
type DB struct {
	pool *pgxpool.Pool
}

// New connects to the database using the provided DSN and returns a DB instance.
func New(ctx context.Context, dsn string) (*DB, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	// verify connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &DB{pool: pool}, nil
}

// Close releases all database resources.
func (db *DB) Close() {
	if db.pool != nil {
		db.pool.Close()
	}
}

// Domain represents a monitored domain.
// It mirrors the schema defined in migrations.
type Domain struct {
	ID                uuid.UUID
	OrganizationID    uuid.UUID
	Name              string
	NormalizedDomain  string
	Status            string
	OwnershipVerified bool
	VerificationToken *string
	CreatedAt         time.Time
	UpdatedAt         time.Time
	LastScanAt        *time.Time
	LastError         *string
}

type Organization struct {
	ID        uuid.UUID
	Name      string
	CreatedAt time.Time
}

type Finding struct {
	Severity       string
	Title          string
	Description    string
	Recommendation string
	Evidence       map[string]any
}

type LatestReport struct {
	ID        uuid.UUID
	ScanRunID uuid.UUID
	Score     int
	Data      json.RawMessage
	CreatedAt time.Time
}

type ReportListItem struct {
	ID        uuid.UUID
	ScanRunID uuid.UUID
	Score     int
	CreatedAt time.Time
}

type DomainSummary struct {
	LatestScore             *int
	LatestReportGeneratedAt *time.Time
	LatestScanStatus        *string
	LatestScanError         *string
}

type ObservationDiffRecord struct {
	ChangeType string
	Category   string
	Subject    string
	Key        string
	OldValue   json.RawMessage
	NewValue   json.RawMessage
	CreatedAt  time.Time
}

// CreateDomain inserts a new monitored domain.
func (db *DB) CreateDomain(ctx context.Context, name, normalizedDomain string) (uuid.UUID, error) {
	id := uuid.New()
	orgID := uuid.Nil
	_, err := db.pool.Exec(ctx,
		`insert into domains (id, organization_id, domain, normalized_domain, status) values ($1, $2, $3, $4, $5)`,
		id, orgID, name, normalizedDomain, "active",
	)
	return id, err
}

func (db *DB) CreateOrganization(ctx context.Context, name string) (uuid.UUID, error) {
	id := uuid.New()
	_, err := db.pool.Exec(ctx, `insert into organizations (id, name) values ($1, $2)`, id, name)
	return id, err
}

// GetDomain returns the domain with the given ID.
func (db *DB) GetDomain(ctx context.Context, id uuid.UUID) (Domain, error) {
	var d Domain
	row := db.pool.QueryRow(ctx,
		`select id, coalesce(organization_id, '00000000-0000-0000-0000-000000000000'::uuid), domain, coalesce(normalized_domain, lower(domain)), status, verified, verification_token, created_at, updated_at, last_scan_at, last_error from domains where id = $1`, id,
	)
	if err := row.Scan(&d.ID, &d.OrganizationID, &d.Name, &d.NormalizedDomain, &d.Status, &d.OwnershipVerified, &d.VerificationToken, &d.CreatedAt, &d.UpdatedAt, &d.LastScanAt, &d.LastError); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Domain{}, ErrNotFound
		}
		return Domain{}, err
	}
	return d, nil
}

// MarkDomainOwnershipVerified updates the optional ownership verification flag for the domain.
func (db *DB) MarkDomainOwnershipVerified(ctx context.Context, id uuid.UUID, verified bool) error {
	_, err := db.pool.Exec(ctx,
		`update domains set verified = $1, updated_at = now() where id = $2`, verified, id,
	)
	return err
}

// SetVerificationToken stores an ownership verification token for future sensitive features.
func (db *DB) SetVerificationToken(ctx context.Context, id uuid.UUID, token string) error {
	_, err := db.pool.Exec(ctx,
		`update domains set verification_token = $1, updated_at = now() where id = $2`, token, id,
	)
	return err
}

// SetDomainStatus updates the monitored domain lifecycle status.
func (db *DB) SetDomainStatus(ctx context.Context, id uuid.UUID, status string, lastError *string) error {
	_, err := db.pool.Exec(ctx,
		`update domains set status = $1, last_error = $2, updated_at = now() where id = $3`, status, lastError, id,
	)
	return err
}

// RecordDomainScan updates scan bookkeeping on the domain itself.
func (db *DB) RecordDomainScan(ctx context.Context, id uuid.UUID, status string, lastError *string) error {
	_, err := db.pool.Exec(ctx,
		`update domains set status = $1, last_error = $2, last_scan_at = now(), updated_at = now() where id = $3`, status, lastError, id,
	)
	return err
}

// ListDomains returns all monitored domains.
func (db *DB) ListDomains(ctx context.Context) ([]Domain, error) {
	rows, err := db.pool.Query(ctx,
		`select id, coalesce(organization_id, '00000000-0000-0000-0000-000000000000'::uuid), domain, coalesce(normalized_domain, lower(domain)), status, verified, verification_token, created_at, updated_at, last_scan_at, last_error from domains order by created_at desc`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Domain
	for rows.Next() {
		var d Domain
		if err := rows.Scan(&d.ID, &d.OrganizationID, &d.Name, &d.NormalizedDomain, &d.Status, &d.OwnershipVerified, &d.VerificationToken, &d.CreatedAt, &d.UpdatedAt, &d.LastScanAt, &d.LastError); err != nil {
			return nil, err
		}
		list = append(list, d)
	}
	return list, rows.Err()
}

// ListActiveDomains returns domains that can be scanned automatically.
func (db *DB) ListActiveDomains(ctx context.Context) ([]Domain, error) {
	rows, err := db.pool.Query(ctx,
		`select id, coalesce(organization_id, '00000000-0000-0000-0000-000000000000'::uuid), domain, coalesce(normalized_domain, lower(domain)), status, verified, verification_token, created_at, updated_at, last_scan_at, last_error from domains where status = 'active' order by created_at desc`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Domain
	for rows.Next() {
		var d Domain
		if err := rows.Scan(&d.ID, &d.OrganizationID, &d.Name, &d.NormalizedDomain, &d.Status, &d.OwnershipVerified, &d.VerificationToken, &d.CreatedAt, &d.UpdatedAt, &d.LastScanAt, &d.LastError); err != nil {
			return nil, err
		}
		list = append(list, d)
	}
	return list, rows.Err()
}

// CreateScanRun inserts a new scan run for a domain and returns its ID.
func (db *DB) CreateScanRun(ctx context.Context, domainID uuid.UUID, scanType string) (uuid.UUID, error) {
	id := uuid.New()
	_, err := db.pool.Exec(ctx,
		`insert into scan_runs (id, domain_id, status, scan_type, started_at) values ($1, $2, $3, $4, now())`,
		id, domainID, "running", scanType,
	)
	return id, err
}

// FinishScanRun updates the scan run with finished_at timestamp and status.
// If errMessage is nil, status is set to 'finished', otherwise 'error' and error stored.
func (db *DB) FinishScanRun(ctx context.Context, id uuid.UUID, errMessage *string) error {
	status := "finished"
	if errMessage != nil {
		status = "error"
	}
	_, err := db.pool.Exec(ctx,
		`update scan_runs set status = $1, finished_at = now(), error = $2 where id = $3`,
		status, errMessage, id,
	)
	return err
}

// InsertObservation stores a single observation for a scan run.
func (db *DB) InsertObservation(ctx context.Context, scanRunID uuid.UUID, domainID uuid.UUID, obs scanner.Observation) error {
	// encode value as JSON
	valueBytes, err := json.Marshal(obs.Value)
	if err != nil {
		return err
	}
	_, err = db.pool.Exec(ctx,
		`insert into observations (id, scan_run_id, domain_id, category, subject, key, value) values ($1, $2, $3, $4, $5, $6, $7)`,
		uuid.New(), scanRunID, domainID, obs.Category, obs.Subject, obs.Key, valueBytes,
	)
	return err
}

// StoreObservations persists all observations for a scan run.
func (db *DB) StoreObservations(ctx context.Context, scanRunID, domainID uuid.UUID, observations []scanner.Observation) error {
	for _, observation := range observations {
		if err := db.InsertObservation(ctx, scanRunID, domainID, observation); err != nil {
			return err
		}
	}
	return nil
}

// LoadPreviousObservations returns the latest observations from a prior scan, if any.
func (db *DB) LoadPreviousObservations(ctx context.Context, domainID, currentScanRunID uuid.UUID) ([]scanner.Observation, error) {
	var previousScanRunID uuid.UUID
	err := db.pool.QueryRow(ctx,
		`select id from scan_runs where domain_id = $1 and id <> $2 and status = 'finished' order by started_at desc limit 1`,
		domainID, currentScanRunID,
	).Scan(&previousScanRunID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	rows, err := db.pool.Query(ctx,
		`select category, subject, key, value from observations where scan_run_id = $1 order by observed_at asc`,
		previousScanRunID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []scanner.Observation
	for rows.Next() {
		var observation scanner.Observation
		var valueBytes []byte
		if err := rows.Scan(&observation.Category, &observation.Subject, &observation.Key, &valueBytes); err != nil {
			return nil, err
		}
		var value any
		if err := json.Unmarshal(valueBytes, &value); err != nil {
			return nil, err
		}
		observation.Value = value
		list = append(list, observation)
	}

	return list, rows.Err()
}

// StoreObservationDiffs persists observation diffs for a scan run.
func (db *DB) StoreObservationDiffs(ctx context.Context, scanRunID, domainID uuid.UUID, diffs []diff.ObservationDiff) error {
	for _, item := range diffs {
		var oldValue any = item.OldValue
		var newValue any = item.NewValue
		_, err := db.pool.Exec(ctx,
			`insert into observation_diffs (id, domain_id, scan_run_id, change_type, category, subject, key, old_value, new_value) values ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			uuid.New(), domainID, scanRunID, string(item.ChangeType), item.Category, item.Subject, item.Key, oldValue, newValue,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

// ListObservationDiffs returns the latest diffs for a given scan run.
func (db *DB) ListObservationDiffs(ctx context.Context, scanRunID uuid.UUID) ([]ObservationDiffRecord, error) {
	rows, err := db.pool.Query(ctx,
		`select change_type, category, subject, key, old_value, new_value, created_at from observation_diffs where scan_run_id = $1 order by created_at asc`,
		scanRunID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []ObservationDiffRecord
	for rows.Next() {
		var item ObservationDiffRecord
		if err := rows.Scan(&item.ChangeType, &item.Category, &item.Subject, &item.Key, &item.OldValue, &item.NewValue, &item.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, item)
	}
	return list, rows.Err()
}

// StoreFindings persists all findings for a scan run.
func (db *DB) StoreFindings(ctx context.Context, scanRunID, domainID uuid.UUID, findings []Finding) error {
	for _, finding := range findings {
		evidenceBytes, err := json.Marshal(finding.Evidence)
		if err != nil {
			return err
		}
		_, err = db.pool.Exec(ctx,
			`insert into findings (id, scan_run_id, domain_id, severity, title, description, recommendation, evidence) values ($1, $2, $3, $4, $5, $6, $7, $8)`,
			uuid.New(), scanRunID, domainID, finding.Severity, finding.Title, finding.Description, finding.Recommendation, evidenceBytes,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

// CreateReport stores the generated JSON report for a scan run.
func (db *DB) CreateReport(ctx context.Context, scanRunID, domainID uuid.UUID, score int, data any) error {
	reportBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = db.pool.Exec(ctx,
		`insert into reports (id, scan_run_id, domain_id, score, data) values ($1, $2, $3, $4, $5)`,
		uuid.New(), scanRunID, domainID, score, reportBytes,
	)
	return err
}

// GetLatestReport returns the most recently created report for a domain.
func (db *DB) GetLatestReport(ctx context.Context, domainID uuid.UUID) (LatestReport, error) {
	var report LatestReport
	if err := db.pool.QueryRow(ctx,
		`select id, scan_run_id, score, data, created_at from reports where domain_id = $1 order by created_at desc limit 1`, domainID,
	).Scan(&report.ID, &report.ScanRunID, &report.Score, &report.Data, &report.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return LatestReport{}, ErrNotFound
		}
		return LatestReport{}, err
	}
	return report, nil
}

// GetReportByID returns a specific stored report.
func (db *DB) GetReportByID(ctx context.Context, reportID uuid.UUID) (LatestReport, error) {
	var report LatestReport
	if err := db.pool.QueryRow(ctx,
		`select id, scan_run_id, score, data, created_at from reports where id = $1`, reportID,
	).Scan(&report.ID, &report.ScanRunID, &report.Score, &report.Data, &report.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return LatestReport{}, ErrNotFound
		}
		return LatestReport{}, err
	}
	return report, nil
}

// ListReportsForDomain returns report history metadata for a domain.
func (db *DB) ListReportsForDomain(ctx context.Context, domainID uuid.UUID) ([]ReportListItem, error) {
	rows, err := db.pool.Query(ctx,
		`select id, scan_run_id, score, created_at from reports where domain_id = $1 order by created_at desc`, domainID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []ReportListItem
	for rows.Next() {
		var item ReportListItem
		if err := rows.Scan(&item.ID, &item.ScanRunID, &item.Score, &item.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, item)
	}
	return list, rows.Err()
}

// GetDomainSummary returns the latest scan and report metadata for a domain.
func (db *DB) GetDomainSummary(ctx context.Context, domainID uuid.UUID) (DomainSummary, error) {
	var summary DomainSummary

	var score *int
	var reportCreatedAt *time.Time
	if err := db.pool.QueryRow(ctx,
		`select score, created_at from reports where domain_id = $1 order by created_at desc limit 1`, domainID,
	).Scan(&score, &reportCreatedAt); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return DomainSummary{}, err
	}
	summary.LatestScore = score
	summary.LatestReportGeneratedAt = reportCreatedAt

	var status *string
	var scanError *string
	if err := db.pool.QueryRow(ctx,
		`select status, error from scan_runs where domain_id = $1 order by started_at desc limit 1`, domainID,
	).Scan(&status, &scanError); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return DomainSummary{}, err
	}
	summary.LatestScanStatus = status
	summary.LatestScanError = scanError

	return summary, nil
}

// GetLatestObservations returns observations for the most recent scan run of a domain.
func (db *DB) GetLatestObservations(ctx context.Context, domainID uuid.UUID) ([]scanner.Observation, error) {
	// find latest scan_run id for domain
	var scanID uuid.UUID
	err := db.pool.QueryRow(ctx,
		`select id from scan_runs where domain_id = $1 order by started_at desc limit 1`, domainID,
	).Scan(&scanID)
	if err != nil {
		return nil, err
	}
	rows, err := db.pool.Query(ctx,
		`select category, subject, key, value from observations where scan_run_id = $1`, scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []scanner.Observation
	for rows.Next() {
		var category, subject, key string
		var valueBytes []byte
		if err := rows.Scan(&category, &subject, &key, &valueBytes); err != nil {
			return nil, err
		}
		var value map[string]any
		if err := json.Unmarshal(valueBytes, &value); err != nil {
			return nil, err
		}
		list = append(list, scanner.Observation{
			Category: category,
			Subject:  subject,
			Key:      key,
			Value:    value,
		})
	}
	return list, rows.Err()
}

// ErrNotFound may be returned when a requested entity does not exist.
var ErrNotFound = errors.New("not found")

// FindingsFromEngine converts findings from the engine package into DB models.
func FindingsFromEngine(findings []enginefindings.Finding) []Finding {
	out := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		out = append(out, Finding{
			Severity:       string(finding.Severity),
			Title:          finding.Title,
			Description:    finding.Description,
			Recommendation: finding.Recommendation,
			Evidence:       finding.Evidence,
		})
	}
	return out
}
