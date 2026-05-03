.PHONY: docker-up docker-down run-api run-worker migrate test pg-stats pg-stats-reset pg-logs pg-logs-latest pg-settings

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

pg-stats:
	docker compose exec postgres psql -U postgres -d sec-api -c "select query, calls, total_exec_time, mean_exec_time, rows from pg_stat_statements order by total_exec_time desc limit 20;"

pg-stats-reset:
	docker compose exec postgres psql -U postgres -d sec-api -c "select pg_stat_statements_reset();"

pg-logs:
	docker compose exec postgres ls /var/lib/postgresql/18/docker/log

pg-logs-latest:
	docker compose exec postgres sh -lc 'cat /var/lib/postgresql/18/docker/log/$$(ls /var/lib/postgresql/18/docker/log | sort | tail -n 1)'

pg-settings:
	docker compose exec postgres psql -U postgres -d sec-api -c "show shared_preload_libraries; show log_min_duration_statement; show auto_explain.log_min_duration; show data_directory;"
