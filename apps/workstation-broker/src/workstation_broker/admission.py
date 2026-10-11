"""Persistent shutdown barrier; explicit execution host up reopens only audited absence."""
from __future__ import annotations
import json
import os
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

from gpt_trace_transport.local_templates import atomic_json, safe, sync_directory
from workstation_broker.preparation import PreparationManager, same_process


def deployment():
    return {"control_id": os.environ["WORKSTATION_BROKER_CONTROL_ID"],
            "execution_id": os.environ["WORKSTATION_BROKER_EXECUTION_ID"]}


def barrier_path():
    return Path(os.environ["WORKSTATION_BASE_IMAGE"]).parent / "broker-drain.json"


def read_barrier(path, expected):
    value = json.loads(safe(path).read_bytes())
    if (set(value) != {"schema", "deployment", "state", "created_at"} or value["schema"] != 1
            or value["deployment"] != expected or value["state"] != "draining"):
        raise RuntimeError("persistent broker drain belongs to an unexpected deployment/state")
    return value


def mark_draining(path):
    if Path(path).exists():
        read_barrier(path, deployment())
        return
    atomic_json(path, {"schema": 1, "deployment": deployment(), "state": "draining", "created_at": time.time()}, 0o600)


def reopen():
    if os.geteuid() != 0: raise RuntimeError("execution host admission requires root")
    marker = barrier_path()
    read_barrier(marker, deployment())
    state = subprocess.check_output(["systemctl", "show", "--property=ActiveState", "--value",
        "gpt-trace-distributed-broker.service"], text=True, timeout=30).strip()
    pid = subprocess.check_output(["systemctl", "show", "--property=MainPID", "--value",
        "gpt-trace-distributed-broker.service"], text=True, timeout=30).strip()
    if state not in {"inactive", "failed"} or pid != "0":
        raise RuntimeError("drained broker must be stopped before explicit up can reopen admission")
    runtime = safe(Path(os.environ["WORKSTATION_BROKER_SOCKET"]).parent, directory=True)
    record_path = runtime / "broker-process.json"
    if record_path.exists():
        record = json.loads(safe(record_path).read_bytes())
        if record.get("deployment") != deployment() or same_process(record["broker_identity"]):
            raise RuntimeError("native broker process is not proved stopped")
    for path in runtime.glob("shutdown-*.json"):
        value = json.loads(safe(path).read_bytes())
        if value.get("deployment") != deployment(): raise RuntimeError("foreign shutdown confirmation; preserved")
        if value.get("observer") and same_process(value["observer"]):
            raise RuntimeError("finite shutdown confirmation is still active; wait for it before make up")
    from workstation_broker.server import inventory
    from workstation_broker.templates import TemplateRegistry
    base = Path(os.environ["WORKSTATION_BASE_IMAGE"])
    templates = TemplateRegistry(Path(os.environ["WORKSTATION_TEMPLATE_ROOT"]), base, lambda p: {})
    manager = PreparationManager(base, templates.root, templates)
    view = SimpleNamespace(root=Path(os.environ["WORKSTATION_BROKER_STATE"]), preparations=manager)
    if not inventory(view)["absent"]:
        raise RuntimeError("temporary project resources remain; complete make down on execution host before reopening admission")
    safe(marker)
    marker.unlink()
    sync_directory(marker.parent)


if __name__ == "__main__": reopen()
