.PHONY: docker-up docker-down run-api run-worker migrate test

docker-up:
	docker compose up -d

docker-down:
	docker compose down

run-api:
	go run ./cmd/api

run-worker:
	go run ./cmd/worker

migrate:
	docker compose exec -T postgres psql -U postgres -d sec-api < migrations/000001_init.sql

test:
	go test ./...
