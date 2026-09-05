.PHONY: build up down logs doctor auth run status export test
build:
	docker compose build
up:
	docker compose up -d postgres storage browser
down:
	docker compose down
logs:
	docker compose logs -f --tail=200
doctor:
	docker compose run --rm runner doctor
auth:
	docker compose run --rm runner auth
run:
	docker compose run --rm runner run /data/benchmarks/benchmark.jsonl --resume
status:
	docker compose run --rm runner status
export:
	docker compose run --rm runner export /data/exports/dataset.jsonl
test:
	docker compose run --rm runner pytest
	docker compose run --rm storage pytest
