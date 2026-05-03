# DomainRiskDigest Agent Instructions

## Project goal
This repository implements DomainRiskDigest, a small external domain-risk monitoring MVP.
The product monitors verified domains and reports obvious external exposure issues:
- DNS posture
- SPF / DMARC
- TLS certificate expiry and hostname validity
- HTTP security headers
- weekly scan reports
- risk score

This is not a penetration testing tool.

## Engineering rules
- Use Go.
- Prefer standard library unless a dependency is justified.
- Keep code simple and explicit.
- Do not add Kubernetes, Terraform, frontend framework, auth provider, or billing unless explicitly requested.
- Do not implement port scanning, exploit testing, brute force checks, credential testing, or invasive scanning.
- All domain scanning must require prior TXT verification.
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
