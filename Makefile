.PHONY: init adopt-profile build up down logs doctor auth run status export test
init:
	python3 scripts/init_env.py
adopt-profile:
	BROWSER_ADOPT_EXISTING_PROFILE=true docker compose up -d browser
build:
	docker compose --profile runner build
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
	docker compose run --rm --no-deps runner status
export:
	docker compose run --rm --no-deps runner export /data/exports/dataset.jsonl
test:
	docker compose run --rm --no-deps --entrypoint pytest runner
	docker compose run --rm --no-deps --entrypoint pytest storage
