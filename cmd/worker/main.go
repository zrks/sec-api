package main

import (
	"context"
	"log"
	"os"

	"github.com/robfig/cron/v3"

    dbpkg "github.com/zrks/sec-api/internal/db"
    "github.com/zrks/sec-api/internal/scanner"
    dnsScanner "github.com/zrks/sec-api/internal/scanner/dns"
    httpScanner "github.com/zrks/sec-api/internal/scanner/httpheaders"
    tlsScanner "github.com/zrks/sec-api/internal/scanner/tls"
)

// main starts the DomainRiskDigest worker, which periodically scans verified
// domains and stores their observations. It reads the database DSN from
// DATABASE_URL and uses robfig/cron for scheduling.
func main() {
    dsn := getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/sec-api?sslmode=disable")
    ctx := context.Background()
    db, err := dbpkg.New(ctx, dsn)
    if err != nil {
        log.Fatalf("worker: failed to connect database: %v", err)
    }
    defer db.Close()

    // Build scanners to reuse across runs
    scs := []scanner.Scanner{
        dnsScanner.New(),
        tlsScanner.New(),
        httpScanner.New(),
    }

    c := cron.New()
    // schedule every hour at minute 0 (can be adjusted by CRON_SCHEDULE env)
    spec := getEnv("CRON_SCHEDULE", "@hourly")
    _, err = c.AddFunc(spec, func() {
        scanAllVerified(ctx, db, scs)
    })
    if err != nil {
        log.Fatalf("worker: failed to schedule job: %v", err)
    }
    log.Printf("DomainRiskDigest worker started with schedule %s", spec)
    c.Start()
    // block
    select {}
}

// scanAllVerified retrieves all verified domains and runs scanners for each.
func scanAllVerified(ctx context.Context, db *dbpkg.DB, scs []scanner.Scanner) {
    domains, err := db.ListVerifiedDomains(ctx)
    if err != nil {
        log.Printf("worker: list verified domains: %v", err)
        return
    }
    if len(domains) == 0 {
        log.Printf("worker: no verified domains to scan")
        return
    }
    for _, dom := range domains {
        scanID, err := db.CreateScanRun(ctx, dom.ID)
        if err != nil {
            log.Printf("worker: create scan run for %s: %v", dom.Name, err)
            continue
        }
        obs, err := scanner.Run(ctx, scs, scanner.Target{Domain: dom.Name})
        var errMsg *string
        if err != nil {
            msg := err.Error()
            errMsg = &msg
        }
        // store observations
        for _, o := range obs {
            if e := db.InsertObservation(ctx, scanID, dom.ID, o); e != nil {
                log.Printf("worker: insert obs for %s: %v", dom.Name, e)
            }
        }
        if e := db.FinishScanRun(ctx, scanID, errMsg); e != nil {
            log.Printf("worker: finish scan run for %s: %v", dom.Name, e)
        }
        log.Printf("worker: scanned domain %s (%s observations)", dom.Name, len(obs))
    }
}

// getEnv returns the environment variable value or fallback if empty.
func getEnv(key, fallback string) string {
    if val := os.Getenv(key); val != "" {
        return val
    }
    return fallback
}
