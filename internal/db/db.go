package db

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zrks/sec-api/internal/scanner"
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
	Verified          bool
	VerificationToken *string
}

// CreateDomain inserts a new domain with the given name and verification token.
// It returns the generated UUID for the new domain.
func (db *DB) CreateDomain(ctx context.Context, name, token string) (uuid.UUID, error) {
	id := uuid.New()
	// For MVP we don't associate domains with organizations; use a nil UUID.
	orgID := uuid.Nil
	_, err := db.pool.Exec(ctx,
		`insert into domains (id, organization_id, domain, verified, verification_token) values ($1, $2, $3, false, $4)`,
		id, orgID, name, token,
	)
	return id, err
}

// GetDomain returns the domain with the given ID.
func (db *DB) GetDomain(ctx context.Context, id uuid.UUID) (Domain, error) {
	var d Domain
	row := db.pool.QueryRow(ctx,
		`select id, organization_id, domain, verified, verification_token from domains where id = $1`, id,
	)
	var orgID uuid.UUID
	var name string
	var verified bool
	var token *string
	if err := row.Scan(&d.ID, &orgID, &name, &verified, &token); err != nil {
		return Domain{}, err
	}
	d.OrganizationID = orgID
	d.Name = name
	d.Verified = verified
	d.VerificationToken = token
	return d, nil
}

// SetDomainVerified updates the verified flag for the domain.
func (db *DB) SetDomainVerified(ctx context.Context, id uuid.UUID, verified bool) error {
	_, err := db.pool.Exec(ctx,
		`update domains set verified = $1 where id = $2`, verified, id,
	)
	return err
}

// ListVerifiedDomains returns all domains marked as verified.
func (db *DB) ListVerifiedDomains(ctx context.Context) ([]Domain, error) {
	rows, err := db.pool.Query(ctx,
		`select id, organization_id, domain, verified, verification_token from domains where verified = true`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Domain
	for rows.Next() {
		var d Domain
		var orgID uuid.UUID
		var name string
		var verified bool
		var token *string
		if err := rows.Scan(&d.ID, &orgID, &name, &verified, &token); err != nil {
			return nil, err
		}
		d.OrganizationID = orgID
		d.Name = name
		d.Verified = verified
		d.VerificationToken = token
		list = append(list, d)
	}
	return list, rows.Err()
}

// CreateScanRun inserts a new scan run for a domain and returns its ID.
func (db *DB) CreateScanRun(ctx context.Context, domainID uuid.UUID) (uuid.UUID, error) {
	id := uuid.New()
	_, err := db.pool.Exec(ctx,
		`insert into scan_runs (id, domain_id, status, started_at) values ($1, $2, $3, now())`,
		id, domainID, "running",
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
