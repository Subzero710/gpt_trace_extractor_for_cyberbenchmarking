.PHONY: build up doctor tools auth run down

build:
	python3 scripts/build.py

up:
	docker compose up -d postgres storage browser workspace-gateway browser-gateway

doctor:
	docker compose run --rm runner doctor

tools:
	python3 scripts/tools_flow.py

auth:
	docker compose run --rm runner auth

run:
	docker compose run --rm runner run /data/benchmarks/benchmark.jsonl --resume

down:
	python3 scripts/down.py
