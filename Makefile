.PHONY: build up doctor tools auth run pause resume status reset-recovery superbench-fetch export-parquet export-sft down throw_volumes

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
	docker compose run --rm --no-deps runner superbench-auth

run:
	python3 scripts/project_state.py core
	GPT_TRACE_RUNNER_BUILD_ID=$$(git rev-parse HEAD) docker compose run --rm --no-deps -e GPT_TRACE_RUNNER_BUILD_ID runner superbench-run $(if $(ADAPTER),--adapter $(ADAPTER),) $(if $(LIMIT),--limit $(LIMIT),)

pause:
	python3 scripts/project_state.py core
	docker compose run --rm --no-deps runner superbench-pause

resume:
	python3 scripts/project_state.py core
	GPT_TRACE_RUNNER_BUILD_ID=$$(git rev-parse HEAD) docker compose run --rm --no-deps -e GPT_TRACE_RUNNER_BUILD_ID runner superbench-resume-active

status:
	python3 scripts/project_state.py core
	docker compose run --rm --no-deps runner superbench-active-status

reset-recovery:
	@test -n "$(TASK)" || (echo "usage: sudo make reset-recovery TASK=<run_task_id>" >&2; exit 2)
	python3 scripts/project_state.py core
	docker compose run --rm --no-deps runner superbench-reset-recovery "$(TASK)" --yes

