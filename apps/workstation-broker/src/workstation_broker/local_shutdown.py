"""execution host-only offline cleanup after a proved inactive managed broker.

No service starts, guest allocation or image mutation. The dispatcher supplies
the same fixed deployment configuration used by serve, in the native venv.
"""
from __future__ import annotations
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

from gpt_trace_transport.local_templates import atomic_json, safe
from workstation_broker.preparation import same_process, PreparationManager


def main():
    if os.geteuid() != 0: raise RuntimeError("local cleanup requires execution host root")
    runtime = safe(Path(os.environ["WORKSTATION_BROKER_SOCKET"]).parent, directory=True)
    record_path = runtime / "broker-process.json"
    if record_path.exists():
        record = json.loads(safe(record_path).read_bytes())
        expected = {"control_id": os.environ["WORKSTATION_BROKER_CONTROL_ID"],
                    "execution_id": os.environ["WORKSTATION_BROKER_EXECUTION_ID"]}
        if record.get("deployment") != expected: raise RuntimeError("local broker process record belongs to another deployment")
        if same_process(record["broker_identity"]): raise RuntimeError("recorded broker is still alive; use its authenticated shutdown barrier")
    status = subprocess.check_output(["systemctl", "show", "--property=ActiveState", "--value",
        "gpt-trace-distributed-broker.service"], text=True, timeout=30).strip()
    pid = subprocess.check_output(["systemctl", "show", "--property=MainPID", "--value",
        "gpt-trace-distributed-broker.service"], text=True, timeout=30).strip()
    if status not in {"inactive", "failed"} or pid != "0":
        raise RuntimeError("managed broker is not proved inactive")
    # Cover an explicitly launched native broker, rather than infer absence from
    # a missing socket or systemd alone. Foreign deployments remain untouched.
    for path in Path("/proc").iterdir():
        if not path.name.isdigit(): continue
        try:
            command = (path / "cmdline").read_bytes().split(b"\0")
            if b"workstation_broker.server" not in command: continue
            environment = (path / "environ").read_bytes().split(b"\0")
        except FileNotFoundError: continue
        if ("WORKSTATION_BROKER_EXECUTION_ID=" + os.environ["WORKSTATION_BROKER_EXECUTION_ID"]).encode() in environment:
            raise RuntimeError("a native broker for this execution host deployment is still alive")
    from workstation_broker.server import Broker, inventory
    base = Path(os.environ["WORKSTATION_BASE_IMAGE"])
    limits = __import__("tomllib").loads(Path(os.environ["WORKSTATION_CONFIG"]).read_text())["workstation"]
    from gpt_trace_transport.wire import token_value
    broker = Broker(Path(os.environ["WORKSTATION_BROKER_STATE"]), base,
        token_value(os.environ["WORKSTATION_BROKER_ADMIN_TOKEN"]),
        token_value(os.environ["WORKSTATION_BROKER_CONTROLLER_TOKEN"]),
        memory_mb=limits["memory_mb"], vcpus=limits["vcpus"],
        boot_timeout_seconds=limits["boot_timeout_seconds"], guest_agent_timeout_seconds=limits["guest_agent_timeout_seconds"],
        overlay_quota_gb=limits["overlay_quota_gb"], screenshot_max_bytes=limits["screenshot_max_bytes"],
        max_terminals=limits["max_terminals"], max_output_bytes=limits["max_output_bytes"],
        max_transfer_bytes=limits["max_transfer_bytes"], max_seed_bytes=limits["max_seed_bytes"],
        egress_allow_cidrs=tuple(limits["egress_allow_cidrs"]), template_root=Path(os.environ["WORKSTATION_TEMPLATE_ROOT"]))
    broker.preparations = PreparationManager(base, broker.templates.root, broker.templates)
    from workstation_broker.admission import mark_draining, barrier_path
    mark_draining(barrier_path())
    broker.draining = True
    broker.preparations.cancel_all()
    broker.destroy_all()
    proof = inventory(broker)
    if not proof["absent"]: raise RuntimeError("local resource absence unconfirmed")
    print(json.dumps({"scope": "execution-local", "global": False, "broker_stopped": True,
        "inventory": proof, "deployment": {"control_id": os.environ["WORKSTATION_BROKER_CONTROL_ID"],
        "execution_id": os.environ["WORKSTATION_BROKER_EXECUTION_ID"]}}))


if __name__ == "__main__": main()
