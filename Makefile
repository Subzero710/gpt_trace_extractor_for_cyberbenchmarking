.PHONY: build up doctor tools auth reset-recovery reset-stale run export down throw_volumes

build:
	python3 scripts/build.py

up:
	python3 scripts/project_state.py core
	docker compose up -d postgres storage browser workspace-gateway browser-gateway

doctor:
	python3 scripts/project_state.py doctor
	# Doctor is observational: never start/recreate persistent dependencies.
	docker compose run --rm --no-deps runner doctor

tools:
	python3 scripts/tools_flow.py

auth:
	python3 scripts/project_state.py core
	docker compose run --rm runner auth

reset-recovery:
	@test -n "$(TASK)" || (echo "usage: sudo make reset-recovery TASK=<task_id>" >&2; exit 2)
	python3 scripts/project_state.py core
	docker compose run --rm --no-deps runner reset-recovery /data/benchmarks/benchmark.jsonl "$(TASK)" --yes

reset-stale:
	python3 scripts/project_state.py core
	docker compose run --rm --no-deps runner reset-stale /data/benchmarks/benchmark.jsonl --yes

run:
	python3 scripts/project_state.py core
	# Resume must never start/recreate dependencies, especially the persistent
	# teacher CloakBrowser that owns the authenticated ChatGPT session.
	docker compose run --rm --no-deps runner run /data/benchmarks/benchmark.jsonl --resume

export:
	python3 scripts/project_state.py core
	@mkdir -p exports
	docker compose run --rm --no-deps \
		--entrypoint python \
		-e GPT_TRACE_EXPORT_URL=http://storage:8080/v1/export.jsonl \
		-e GPT_TRACE_EXPORT_OUTPUT=/data/exports/runs.jsonl \
		-v "$(CURDIR)/scripts/export_messages.py:/tmp/export_messages.py:ro" \
		runner /tmp/export_messages.py
	@echo "host export: $(CURDIR)/exports/runs.jsonl"

throw_volumes:
	@echo "WARNING: permanently deletes benchmark database/state volumes (postgres_data and runner_state)."
	@printf "Type THROW to continue: "; read answer; test "$$answer" = "THROW"
	docker compose stop storage postgres
	docker compose rm -f storage postgres
	docker volume rm -f "$$(docker volume ls -q --filter label=com.docker.compose.project=$$(docker compose ls --format json | python3 -c 'import json,sys; x=json.load(sys.stdin); print(next((i["Name"] for i in x if i.get("ConfigFiles","").endswith("compose.yaml")), "gpt-trace-extractor"))') --filter label=com.docker.compose.volume=postgres_data)" 2>/dev/null || true
	docker volume rm -f "$$(docker volume ls -q --filter label=com.docker.compose.project=$$(docker compose ls --format json | python3 -c 'import json,sys; x=json.load(sys.stdin); print(next((i["Name"] for i in x if i.get("ConfigFiles","").endswith("compose.yaml")), "gpt-trace-extractor"))') --filter label=com.docker.compose.volume=runner_state)" 2>/dev/null || true
	@echo "postgres_data + runner_state removed; browser_profile preserved."

down:
	python3 scripts/down.py
