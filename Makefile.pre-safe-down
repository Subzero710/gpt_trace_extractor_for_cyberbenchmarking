.PHONY: init adopt-profile build up down logs doctor auth run inspect-tools status export test
init:
	python3 scripts/init_env.py
adopt-profile:
	BROWSER_ADOPT_EXISTING_PROFILE=true docker compose up -d browser
build:
	docker compose --profile runner --profile runtime-images build
up:
	docker compose up -d postgres storage browser workspace-gateway browser-gateway
down:
	docker compose down --remove-orphans
logs:
	docker compose logs -f --tail=200
doctor:
	docker compose run --rm runner doctor
auth:
	docker compose run --rm runner auth
run:
	docker compose run --rm runner run /data/benchmarks/benchmark.jsonl --resume
inspect-tools:
	@test -n "$(TASK_ID)" || (echo "TASK_ID is required" >&2; exit 2)
	docker compose run --rm --no-deps runner inspect-tools /data/benchmarks/benchmark.jsonl --task-id "$(TASK_ID)"
status:
	docker compose run --rm --no-deps runner status
export:
	docker compose run --rm --no-deps runner export /data/exports/dataset.jsonl
test:
	docker compose run --rm --no-deps --entrypoint pytest runner
	docker compose run --rm --no-deps --entrypoint pytest storage
	docker compose --profile runtime-images run --rm --no-deps --entrypoint pytest workspace-runtime-image
	docker compose --profile runtime-images run --rm --no-deps --entrypoint pytest browser-runtime-image
	docker compose run --rm --no-deps --entrypoint pytest workspace-gateway
