package main

import (
	"context"
	"log"

	"github.com/robfig/cron/v3"

	"github.com/zrks/sec-api/internal/config"
	dbpkg "github.com/zrks/sec-api/internal/db"
	"github.com/zrks/sec-api/internal/scanjob"
	"github.com/zrks/sec-api/internal/scanner"
	dnsScanner "github.com/zrks/sec-api/internal/scanner/dns"
	httpScanner "github.com/zrks/sec-api/internal/scanner/httpheaders"
	rdapScanner "github.com/zrks/sec-api/internal/scanner/rdap"
	subdomainScanner "github.com/zrks/sec-api/internal/scanner/subdomains"
	tlsScanner "github.com/zrks/sec-api/internal/scanner/tls"
)

// main starts the DomainRiskDigest worker, which periodically scans active
// monitored domains and stores their observations. It reads the database DSN from
// DATABASE_URL and uses robfig/cron for scheduling.
func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("worker: failed to load config: %v", err)
	}

	dsn := cfg.DatabaseURL
	ctx := context.Background()
	db, err := dbpkg.New(ctx, dsn)
	if err != nil {
		log.Fatalf("worker: failed to connect database: %v", err)
	}
	defer db.Close()

	// Build scanners to reuse across runs
	scs := []scanner.Scanner{
		dnsScanner.New(),
		subdomainScanner.New(),
		rdapScanner.New(),
		tlsScanner.New(),
		httpScanner.New(),
	}

	c := cron.New()
	// schedule every hour at minute 0 (can be adjusted by CRON_SCHEDULE env)
	spec := cfg.CronSchedule
	_, err = c.AddFunc(spec, func() {
		scanAllActive(ctx, db, scs)
	})
	if err != nil {
		log.Fatalf("worker: failed to schedule job: %v", err)
	}
	log.Printf("DomainRiskDigest worker started with schedule %s", spec)
	c.Start()
	// block
	select {}
}

// scanAllActive retrieves all active domains and runs scanners for each.
func scanAllActive(ctx context.Context, db *dbpkg.DB, scs []scanner.Scanner) {
	domains, err := db.ListActiveDomains(ctx)
	if err != nil {
		log.Printf("worker: list active domains: %v", err)
		return
	}
	if len(domains) == 0 {
		log.Printf("worker: no active domains to scan")
		return
	}
	for _, dom := range domains {
		result, err := scanjob.Run(ctx, db, dom, scs, "scheduled")
		if err != nil {
			log.Printf("worker: scan domain %s: %v", dom.Name, err)
			continue
		}
		log.Printf("worker: scanned domain %s (%d observations, %d findings, score %d)", dom.Name, len(result.Observations), len(result.Findings), result.Report.Score)
	}
}
