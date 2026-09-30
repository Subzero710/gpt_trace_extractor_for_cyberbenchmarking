.PHONY: requirements build up doctor tools auth run pause resume status reset-recovery superbench-fetch export-parquet export-sft down throw_volumes

requirements:
	python3 scripts/host_requirements.py

build:
	python3 scripts/build.py

up:
	python3 scripts/project_state.py core
	python3 scripts/workstation_broker.py start
	docker compose up -d --wait --wait-timeout 300 postgres storage teacher-browser kali-workstation-controller workstation-gateway

doctor: up
	python3 scripts/host_doctor.py
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

throw_volumes:
	python3 scripts/throw_volumes.py

down:
	python3 scripts/down.py

superbench-fetch:
	@test -n "$(ADAPTER)" || (echo "usage: make superbench-fetch ADAPTER=<adapter_id>" >&2; exit 2)
	docker compose run --rm --no-deps benchmark-fetch --adapter "$(ADAPTER)"

export-parquet:
	python3 scripts/project_state.py core
	@mkdir -p exports
	docker compose run --rm --no-deps runner export-parquet /data/exports/corpus.parquet

export-sft: export-parquet
	python3 scripts/project_state.py core
	@mkdir -p exports
	docker compose run --rm --no-deps runner export-sft /data/exports/corpus.parquet /data/exports/sft.parquet
