# DomainRiskDigest

DomainRiskDigest is a small Go service for monitoring public domains and storing simple external exposure signals.

Current local web MVP includes:
- domain add and immediate public-domain profile scan
- passive subdomain discovery from certificate transparency
- DNS posture checks
- RDAP registration checks when available
- TLS certificate checks
- HTTP security header checks
- report history and change tracking between scans
- fix-first recommendations and risk score
- optional future ownership verification details for sensitive features

## Build

Build the Go binaries:

```sh
go build ./...
```

Run the Go tests:

```sh
make test
```

Build the web app:

```sh
cd web
npm install
npm run build
```

Build the Docker images:

```sh
docker compose build api worker
```

Build the Kuberhealthy checker image:

```sh
docker build --target kuberhealthy-api-check -t your-registry/domainriskdigest-kuberhealthy-check:latest .
```

## CI

GitHub Actions CI is split across two workflows:

- `.github/workflows/ci.yml` for build, package, and SonarQube tasks
- `.github/workflows/playwright.yml` for visual regression testing and GitHub Pages report publishing

The main CI workflow runs:

- `frontend` stage: frontend dependency install, `npm run lint`, and production build
- `go-test` stage: `go test -coverprofile=coverage.out ./...`
- `package` stage: Go binary builds, Docker image builds, and distribution packaging into a `.tar.gz` artifact
- `sonarqube` stage: SonarQube analysis when repository secrets are configured

The `frontend` and `go-test` stages run in parallel.
The `package` and `sonarqube` stages start only after the required upstream artifacts are ready.

Required GitHub secrets for SonarQube:

- `SONAR_TOKEN`
- `SONAR_HOST_URL`

The workflow uploads a distribution artifact containing:

- Linux AMD64 binaries for the API, worker, and Kuberhealthy checker
- `deploy/` manifests
- `migrations/`
- built frontend assets from `web/dist`
- `README.md`

The Playwright workflow uploads a `playwright-report` artifact with the visual test HTML report and any failure attachments.

For pushes to `main` or `master`, the Playwright workflow also publishes the same HTML report to GitHub Pages.
Enable GitHub Pages for the repository using GitHub Actions as the source if it is not already enabled.

Visual differences in the Playwright workflow are currently surfaced as workflow warnings so the HTML report can still be published and reviewed.

Build or restart Postgres with database stats and file logging enabled:

```sh
docker compose build
docker compose up -d postgres
```

## Run

### Docker stack

Start the database and app containers:

```sh
make docker-up
docker compose up -d api worker
```

Or start the full stack directly:

```sh
docker compose up -d postgres pgadmin api worker
```

Apply the schema manually if needed:

```sh
make migrate
```

This also creates the `pg_stat_statements` extension in the `sec-api` database.

### Local backend

Use the local defaults from `.env.example`:

```text
APP_ENV=local
HTTP_ADDR=:8080
DATABASE_URL=postgres://postgres:postgres@localhost:5432/sec-api?sslmode=disable
CRON_SCHEDULE=@hourly
HIBP_API_KEY=
NVD_API_KEY=
```

Run the API locally:

```sh
make run-api
```

Run the worker locally in another terminal:

```sh
make run-worker
```

### Local web app

Run the web app locally in another terminal:

```sh
cd web
npm install
npm run dev
```

Run the visual regression tests locally:

```sh
cd web
npx playwright install chromium
npm run test:visual
```

Update the visual snapshot baselines when the UI change is intentional:

```sh
cd web
npm run test:visual:update
```

Open the visual HTML report:

```sh
cd web
npm run test:visual:report
```

The web UI is plain JavaScript with no runtime frontend dependencies.
Only `vite` is used as a local development/build tool.

## Local setup

1. Start Postgres:

```sh
make docker-up
```

2. Run the API:

```sh
make run-api
```

3. In another terminal, run the worker:

```sh
make run-worker
```

4. In another terminal, run the web app:

```sh
cd web
npm install
npm run dev
```

## Local services

- PostgreSQL: `localhost:5432`
- pgAdmin: `http://localhost:5050`
- API: `http://localhost:8080`
- Web app: `http://localhost:5173`
- Built-in API test UI: `http://localhost:8080/`

Postgres observability enabled locally:
- `pg_stat_statements` extension in database `sec-api`
- file logging via the Postgres `log/` directory inside the persistent database volume
- `auto_explain` for slow query execution plans
- connection, checkpoint, lock-wait, and temp-file logging

The Docker Compose stack now starts these services together:
- `postgres`
- `pgadmin`
- `api`
- `worker`

pgAdmin login:
- email: `pgadmin@local.test`
- password: `ChangeMeLocalOnly123!`

## Migrations

The initial schema is mounted into the Postgres container and is applied automatically on a fresh database volume.

To apply the current migration manually against the running local container:

```sh
make migrate
```

## Basic checks

Run all Go tests:

```sh
go test ./...
```

Frontend environment:

```text
VITE_API_BASE_URL=http://localhost:8080
```

Copy `web/.env.example` if you want to override the default local API base URL.

Health endpoint:

```sh
curl http://localhost:8080/healthz
```

Version endpoint:

```sh
curl http://localhost:8080/api/v1/version
```

Create a domain:

```sh
curl -X POST http://localhost:8080/api/v1/domains \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example.com"}'
```

Optional future ownership verification using DNS TXT:

1. Create the domain and copy the returned values.
2. Publish this TXT record:

```text
_domainriskdigest.<domain> TXT drd-verify-<token>
```

3. Trigger ownership verification:

```sh
curl -X POST http://localhost:8080/api/v1/domains/<id>/verify-ownership
```

Run a manual scan:

```sh
curl -X POST http://localhost:8080/api/v1/domains/<id>/scan-now
```

Fetch the latest report:

```sh
curl http://localhost:8080/api/v1/domains/<id>/latest-report
```

Fetch report history for a domain:

```sh
curl http://localhost:8080/api/v1/domains/<id>/reports
```

Fetch a stored report by report id:

```sh
curl http://localhost:8080/api/v1/reports/<report-id>
```

## Kuberhealthy

This repo includes a small Kuberhealthy external check at `cmd/kuberhealthy-api-check`.
It verifies:

- `GET /healthz` returns `200` and `ok`
- `GET /api/v1/version` returns JSON with a non-empty `version`
- localhost CORS preflight is allowed
- a foreign origin is not reflected by CORS
- baseline security headers are present on the local web UI root page

Build the checker binary locally:

```sh
go build ./cmd/kuberhealthy-api-check
```

Build and push the checker image:

```sh
docker build --target kuberhealthy-api-check -t your-registry/domainriskdigest-kuberhealthy-check:latest .
docker push your-registry/domainriskdigest-kuberhealthy-check:latest
```

Install Kuberhealthy in your cluster using the upstream project instructions:

```sh
kubectl apply -f https://raw.githubusercontent.com/kuberhealthy/kuberhealthy/master/deploy/kuberhealthy.yaml
```

Review and update the example check manifest:

```sh
sed -n '1,200p' deploy/kuberhealthy/kuberhealthy-check.yaml
```

Replace these values before applying it:

- `image`: your pushed checker image
- `API_BASE_URL`: the in-cluster URL for this API service
- `REQUIRE_HTTPS=true` when the target URL is expected to be HTTPS end to end

Apply the example check:

```sh
kubectl apply -f deploy/kuberhealthy/kuberhealthy-check.yaml
```

Useful checker environment variables:

- `API_BASE_URL`: required base URL to test
- `CHECK_ROOT_HEADERS`: set to `false` if a reverse proxy owns browser headers instead of the app
- `REQUIRE_HTTPS`: set to `true` to fail non-HTTPS base URLs
- `REQUEST_TIMEOUT`: per-request timeout such as `5s`
- `ALLOWED_CORS_ORIGIN`: expected localhost origin for positive CORS verification
- `BLOCKED_CORS_ORIGIN`: origin that must not be reflected by CORS

This checker is intentionally limited to safe synthetic verification. It does not perform port scanning, exploit testing, brute force checks, or invasive scanning.

## Manual web app flow

1. Start Postgres and pgAdmin:

```sh
make docker-up
```

2. Apply the current schema if needed:

```sh
make migrate
```

3. Start the API:

```sh
make run-api
```

4. Start the worker:

```sh
make run-worker
```

5. Start the web app:

```sh
cd web
npm install
npm run dev
```

6. Open `http://localhost:5173`
7. Add a domain.
8. Confirm the initial report appears without TXT verification.
9. Review registration, DNS, TLS, header, and passive subdomain data.
10. Run another scan.
11. Open the latest report.
12. Confirm the risk score, findings, passive subdomains, RDAP details, change list, and observations render.

## Verify

Run tests:

```sh
make test
```

Run Go tests directly:

```sh
go test ./...
```

Run frontend syntax check:

```sh
cd web
npm run lint
```

Build the web app:

```sh
cd web
npm run build
```

## Postgres stats and logs

Restart Postgres after pulling these config changes:

```sh
docker compose up -d postgres
make migrate
```

Check that `pg_stat_statements` is enabled:

```sh
docker compose exec postgres psql -U postgres -d sec-api -c "select * from pg_extension where extname = 'pg_stat_statements';"
```

Query statement stats:

```sh
docker compose exec postgres psql -U postgres -d sec-api -c "select query, calls, total_exec_time from pg_stat_statements order by total_exec_time desc limit 10;"
```

Or use the Makefile helper:

```sh
make pg-stats
```

Reset accumulated statement stats:

```sh
make pg-stats-reset
```

Check active observability settings:

```sh
make pg-settings
```

Read Postgres logs:

```sh
docker compose exec postgres ls /var/lib/postgresql/18/docker/log
docker compose exec postgres sh -lc 'cat /var/lib/postgresql/18/docker/log/$(ls /var/lib/postgresql/18/docker/log | sort | tail -n 1)'
```

Or use the Makefile helpers:

```sh
make pg-logs
make pg-logs-latest
```

Enabled slow-query diagnostics:
- `log_min_duration_statement=250ms`
- `auto_explain.log_min_duration=500ms`
- `auto_explain.log_analyze=on`
- `auto_explain.log_buffers=on`
- `auto_explain.log_verbose=on`

These settings persist through container restarts because logs are written under the Postgres data directory in the persistent volume.
