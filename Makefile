.PHONY: init adopt-profile build up down logs doctor auth run status export inspect-tools test test-unit test-integration

init:
	python3 scripts/init_env.py

adopt-profile:
	BROWSER_ADOPT_EXISTING_PROFILE=true docker compose up -d browser

build:
	docker compose --profile runner build

up:
	docker compose up -d postgres storage browser app-code-workspace app-browser

down:
	docker compose down

logs:
	docker compose logs -f --tail=200

doctor:
	docker compose run --rm runner doctor
	docker compose exec -T app-code-workspace python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz', timeout=2)"
	docker compose exec -T app-browser python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz', timeout=2)"

auth:
	docker compose run --rm runner auth

run:
	docker compose run --rm runner run /data/benchmarks/benchmark.jsonl --resume

status:
	docker compose run --rm --no-deps runner status

export:
	docker compose run --rm --no-deps runner export /data/exports/dataset.jsonl

inspect-tools:
	test -n "$(TASK_ID)" || (echo "TASK_ID is required" >&2; exit 2)
	docker compose run --rm --no-deps runner inspect-tools /data/benchmarks/benchmark.jsonl --task-id "$(TASK_ID)"

test: test-unit test-integration

test-unit:
	docker compose run --rm --no-deps --entrypoint pytest runner
	docker compose run --rm --no-deps --entrypoint pytest storage
	docker compose run --rm --no-deps --entrypoint pytest app-code-workspace
	docker compose run --rm --no-deps --entrypoint pytest app-browser -m "not integration"

test-integration:
	docker compose run --rm --no-deps --entrypoint pytest app-browser -m integration
