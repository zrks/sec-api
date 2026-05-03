# DomainRiskDigest

DomainRiskDigest is a small Go service for monitoring verified domains and storing simple external exposure signals.

## Local setup

1. Start the full local stack:

```sh
make docker-up
```

2. Use the local defaults from `.env.example`:

```text
APP_ENV=local
HTTP_ADDR=:8080
DATABASE_URL=postgres://postgres:postgres@localhost:5432/sec-api?sslmode=disable
CRON_SCHEDULE=@hourly
HIBP_API_KEY=
NVD_API_KEY=
```

3. Or run only the API locally without Docker:

```sh
make run-api
```

4. In another terminal, run the worker locally without Docker:

```sh
make run-worker
```

## Local services

- PostgreSQL: `localhost:5432`
- pgAdmin: `http://localhost:5050`
- API: `http://localhost:8080`

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

Health endpoint:

```sh
curl http://localhost:8080/healthz
```

Version endpoint:

```sh
curl http://localhost:8080/api/v1/version
```

Run tests:

```sh
make test
```
