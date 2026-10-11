.PHONY: requirements build up doctor tunnels register_apps start_kali status_kali stop_kali auth run pause resume status reset-recovery superbench-fetch export-parquet down throw_volumes kali_control

requirements:
	python3 scripts/distributed.py requirements

build:
	python3 scripts/distributed.py build

up:
	python3 scripts/distributed.py up

doctor:
	python3 scripts/distributed.py doctor

tunnels:
	python3 scripts/distributed.py tunnels

register_apps:
	python3 scripts/distributed.py register_apps

start_kali:
	python3 scripts/distributed.py start_kali

status_kali:
	python3 scripts/distributed.py status_kali

stop_kali:
	python3 scripts/distributed.py stop_kali

auth:
	python3 scripts/distributed.py auth

run:
	python3 scripts/distributed.py run $(if $(ADAPTER),--adapter "$(ADAPTER)",) $(if $(LIMIT),--limit "$(LIMIT)",)

pause:
	python3 scripts/distributed.py pause

resume:
	python3 scripts/distributed.py resume

status:
	python3 scripts/distributed.py status

reset-recovery:
	python3 scripts/distributed.py reset-recovery $(if $(TASK),--task "$(TASK)",)

superbench-fetch:
	python3 scripts/distributed.py superbench-fetch $(if $(ADAPTER),--adapter "$(ADAPTER)",)

export-parquet:
	python3 scripts/distributed.py export-parquet

down:
	python3 scripts/distributed.py down

throw_volumes:
	python3 scripts/distributed.py throw_volumes

kali_control:
	python3 scripts/distributed.py kali_control

