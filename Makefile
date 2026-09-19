.PHONY: build up doctor tools auth run down

build:
	python3 scripts/build.py

up:
	python3 scripts/project_state.py core
	docker compose up -d postgres storage browser workspace-gateway browser-gateway

doctor:
	python3 scripts/project_state.py core
	docker compose run --rm runner doctor

tools:
	python3 scripts/tools_flow.py

auth:
	python3 scripts/project_state.py core
	docker compose run --rm runner auth

run:
	python3 scripts/project_state.py core
	# Resume must never start/recreate dependencies, especially the persistent
	# teacher CloakBrowser that owns the authenticated ChatGPT session.
	docker compose run --rm --no-deps runner run /data/benchmarks/benchmark.jsonl --resume

down:
	python3 scripts/down.py
