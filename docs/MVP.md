# MVP Status

## Implemented

- PostgreSQL-backed API and worker
- Domain creation, listing, and detail endpoints
- Immediate public-domain scan on add-domain
- Manual scan endpoint for active monitored domains
- Scheduled worker scans for active monitored domains
- DNS, TLS, and HTTP header scanners
- Passive subdomain discovery from certificate transparency
- RDAP registration lookups for registrar, expiry, nameservers, and status when available
- Observation storage
- Observation diff storage between scans
- Finding generation from observations
- Risk scoring
- Stored JSON reports, latest-report endpoint, single-report endpoint, and report history endpoint
- Built-in browser test page at `/`
- Vanilla JavaScript local web app under `web/`
- Docker Compose stack for postgres, pgAdmin, api, and worker

## Not Yet Implemented

- Multi-tenant organization workflows beyond the base table/method
- HTML or PDF report generation
- External integrations for HIBP or NVD
- Advanced migration system with incremental files
- Authentication and authorization
- Alert delivery or email notifications
- CAA parsing and findings
- Ownership verification as a required step for basic public-domain scanning
