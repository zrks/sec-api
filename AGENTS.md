# DomainRiskDigest Agent Instructions

## Product goal
This repository implements DomainRiskDigest, a small external domain-risk monitoring MVP.
The product monitors public domains and reports obvious external exposure issues:
- DNS posture
- SPF / DMARC
- TLS certificate expiry and hostname validity
- HTTP security headers
- weekly scan reports
- risk score

This is not a penetration testing tool.

## Current build goal
- Implement a local web app for the existing Go backend.
- The web app must let users:
  1. add a monitored public domain
  2. run an immediate public profile scan
  3. run another scan on demand
  4. view the latest report
  5. review report history and visible changes
  6. understand what to fix first

## Do not implement yet
- authentication
- Stripe billing
- MSP white-label reports
- HIBP integration
- Shodan or Censys integration
- port scanning
- invasive scanning
- Kubernetes scanning
- AI remediation agents
- enterprise RBAC

## Engineering rules
- Use Go.
- Prefer standard library unless a dependency is justified.
- Keep code simple and explicit.
- The backend remains the source of truth; do not rewrite it unless a small change is required to support the frontend.
- A small frontend under `web/` is allowed for this phase.
- Prefer vanilla JavaScript unless the user explicitly requests a framework.
- Keep frontend dependencies minimal.
- Make loading, error, and empty states explicit.
- Do not assume the backend always returns perfect data.
- Use business-friendly wording and avoid scary certainty.
- Do not add Kubernetes, Terraform, auth provider, or billing unless explicitly requested.
- Do not implement port scanning, exploit testing, brute force checks, credential testing, or invasive scanning.
- Basic public-domain checks must not require TXT verification.
- Ownership verification remains optional and future-facing for sensitive features.
- Make `go test ./...` pass after each implementation phase.
- Keep functions small and testable.
- Use context timeouts for network calls.
- Do not panic in request handlers.
- Return useful JSON errors.

## Local environment
Expected local database URL:

```text
postgres://postgres:postgres@localhost:5432/sec-api?sslmode=disable
```

Expected local API address:

```text
:8080
```

Expected local browser frontend API base URL:

```text
http://localhost:8080
```

## MVP API
Required endpoints:
- `GET /healthz`
- `GET /api/v1/version`
- `POST /api/v1/domains`
- `GET /api/v1/domains`
- `GET /api/v1/domains/{id}`
- `POST /api/v1/domains/{id}/verify`
- `POST /api/v1/domains/{id}/scan-now`
- `GET /api/v1/domains/{id}/latest-report`

## Scanner rules
Scanner output must be stored as observations.

Findings should be generated from observations, not directly inside scanners.

## Severity model
critical:
- expired TLS certificate
- TLS hostname mismatch

high:
- TLS expires in <= 14 days
- DMARC missing
- SPF contains +all
- HTTPS unavailable

medium:
- HSTS missing
- CSP missing
- X-Frame-Options missing
- X-Content-Type-Options missing

low/info:
- server header exposed
- DNS records discovered

## Risk scoring
Start at 100.

- critical: -25
- high: -15
- medium: -7
- low: -2

Clamp final score to `0..100`.

## UX wording
Use:
- Domain Risk Dashboard
- Fix This First
- Certificate Failure Prevention
- Email Spoofing Protection Check
- Website Security Basics
- Domain Change Monitoring
- Breached Email Exposure Alerts as a future feature
- Client-ready reports as a future MSP feature

Avoid:
- military language
- hacker cosplay
- guaranteed security claims
- "AI cyber defense"
- "complete vulnerability scan"

## Validation
After changes:
- run `go test ./...`
- run the frontend build if available
- update `README.md` with exact run commands
