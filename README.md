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
