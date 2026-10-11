"""One-shot authenticated proof after the actual broker process has exited.

This finite child has no mutation route and no new service/unit. It reuses the
same protected Unix socket after the native broker PID/start-time is gone,
audits resource absence again, confirms one fresh shutdown nonce, then exits.
"""
from __future__ import annotations
import argparse
import hmac
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

from gpt_trace_transport.local_templates import ROOT, atomic_json, safe
from gpt_trace_transport.wire import token_value
from workstation_broker.preparation import (identifier, process_identity,
    same_process, PreparationManager)

PROJECT = "gpt-trace-extractor"
SCOPES = frozenset({"global", "execution-local"})


def proof_path(shutdown_id):
    runtime = Path(os.environ["WORKSTATION_BROKER_SOCKET"]).parent
    safe(runtime, directory=True)
    if runtime.stat().st_mode & 0o077: raise ValueError("shutdown runtime must be private")
    return runtime / ("shutdown-" + identifier(shutdown_id) + ".json")


def deployment():
    return {"control_id": os.environ["WORKSTATION_BROKER_CONTROL_ID"],
            "execution_id": os.environ["WORKSTATION_BROKER_EXECUTION_ID"]}


def read_proof(shutdown_id):
    value = json.loads(safe(proof_path(shutdown_id)).read_bytes())
    if (value.get("schema") != 1 or value.get("shutdown_id") != shutdown_id
            or value.get("project") != PROJECT or value.get("deployment") != deployment()
            or value.get("scope") not in SCOPES):
        raise ValueError("shutdown proof identity differs")
    return value


def request_observation(broker, payload, before):
    if set(payload) != {"shutdown_id", "scope"} or payload["scope"] not in SCOPES:
        raise ValueError("invalid shutdown confirmation fields")
    shutdown_id = identifier(payload["shutdown_id"])
    path = proof_path(shutdown_id)
    if path.exists() or path.is_symlink():
        raise RuntimeError("shutdown nonce already exists; rediscover its status, do not repeat mutation")
    stamp = process_identity(os.getpid())
    value = {"schema": 1, "shutdown_id": shutdown_id, "scope": payload["scope"],
        "project": PROJECT, "deployment": deployment(), "broker_identity": stamp,
        "status": "waiting", "broker_stopped": False, "inventory_before": before,
        "created_at": time.time(), "observer": None}
    atomic_json(path, value, 0o600)
    with path.with_suffix(".log").open("ab") as log:
        os.fchmod(log.fileno(), 0o600)
        process = subprocess.Popen([sys.executable, "-B", "-m", "workstation_broker.shutdown_observer", shutdown_id],
            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    # The handoff is finite and must be claimed before the broker exits. A failed
    # spawn leaves the broker draining and running, with no false stopped proof.
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        claimed = read_proof(shutdown_id)
        if claimed.get("observer") and same_process(claimed["observer"]):
            return {"project": PROJECT, "shutdown_id": shutdown_id, "scope": payload["scope"],
                    "absent": True, "shutdown": True, "broker_stopped": False}
        if process.poll() is not None: raise RuntimeError("shutdown observer failed before handoff")
        time.sleep(0.05)
    raise RuntimeError("shutdown observer did not claim the handoff; broker remains running")


def pending_status(payload):
    if set(payload) != {"shutdown_id"}: raise ValueError("invalid shutdown status fields")
    value = read_proof(identifier(payload["shutdown_id"]))
    # This handler is inside a LIVE broker. Its existence is never stopped proof,
    # even when an earlier nonce has a retained local confirmation on disk.
    return {"project": PROJECT, "shutdown_id": value["shutdown_id"], "scope": value["scope"],
            "deployment": deployment(), "broker_stopped": False, "pending": True}


def verify_stopped(value, shutdown_id, scope, expected_deployment):
    if (value.get("shutdown_id") != identifier(shutdown_id) or value.get("scope") != scope
            or value.get("deployment") != expected_deployment or value.get("project") != PROJECT
            or value.get("broker_stopped") is not True or value.get("inventory", {}).get("absent") is not True
            or value["inventory"].get("project") != PROJECT or not isinstance(value.get("broker_identity"), dict)):
        raise RuntimeError("no authenticated post-exit broker/absence confirmation")
    return value


class Confirmation:
    def __init__(self, proof):
        self.proof = proof
        self.completed = threading.Event()
        self.credential = token_value(os.environ["WORKSTATION_BROKER_ADMIN_TOKEN"])

    def exchange(self, method, path, body, authorization, *, timeout=None):
        if not hmac.compare_digest(authorization, "Bearer " + self.credential):
            return 403, b'{"detail":"administrative confirmation required"}'
        if method != "POST" or path not in {"/v1/shutdown_status", "/v1/shutdown_complete"}:
            return 404, b'{"detail":"finite shutdown confirmation only"}'
        try:
            payload = json.loads(body)
            if not isinstance(payload, dict) or payload != {"shutdown_id": self.proof["shutdown_id"]}:
                raise ValueError("shutdown nonce differs")
            if same_process(self.proof["broker_identity"]):
                raise RuntimeError("native broker process still exists")
            return 200, json.dumps(self.proof, separators=(",", ":")).encode()
        except (ValueError, RuntimeError):
            return 409, b'{"detail":"shutdown confirmation identity/outcome differs"}'

    def response_sent(self, method, path, status, body, role):
        if (role == "admin" and method == "POST" and path == "/v1/shutdown_complete" and status == 200
                and json.loads(body) == {"shutdown_id": self.proof["shutdown_id"]}):
            self.completed.set()


def observe(shutdown_id):
    if os.geteuid() != 0: raise RuntimeError("shutdown observer requires execution host root")
    path = proof_path(shutdown_id)
    value = read_proof(shutdown_id)
    if value["status"] != "waiting" or value["observer"] is not None or not same_process(value["broker_identity"]):
        raise RuntimeError("observer cannot claim this handoff")
    value = {**value, "observer": process_identity(os.getpid())}
    atomic_json(path, value, 0o600)
    listener = None
    try:
        deadline = time.monotonic() + 60
        while same_process(value["broker_identity"]):
            if time.monotonic() >= deadline: raise RuntimeError("native broker did not exit before confirmation deadline")
            time.sleep(0.1)
        # Read-only post-exit audit; never instantiate or start a VM here.
        from workstation_broker.server import inventory
        from workstation_broker.templates import TemplateRegistry
        base = Path(os.environ["WORKSTATION_BASE_IMAGE"])
        templates = TemplateRegistry(Path(os.environ["WORKSTATION_TEMPLATE_ROOT"]), base, lambda p: {})
        manager = PreparationManager(base, templates.root, templates)
        view = SimpleNamespace(root=Path(os.environ["WORKSTATION_BROKER_STATE"]), preparations=manager)
        proof = inventory(view)
        if not proof["absent"]: raise RuntimeError("project resources appeared after native broker exit")
        value = {**value, "status": "stopped", "broker_stopped": True,
                 "inventory": proof, "observed_at": time.time()}
        if value["scope"] == "execution-local":
            atomic_json(path, value, 0o600)
            return
        confirmation = Confirmation(value)
        # cloudflared keeps forwarding to this exact Unix origin during handoff.
        # Only the admin bearer credential can observe/acknowledge shutdown.
        from gpt_trace_transport.unix_confirmation import start_confirmation
        listener = start_confirmation(Path(os.environ['WORKSTATION_BROKER_SOCKET']), confirmation)
        atomic_json(path, value, 0o600)
        confirmation.completed.wait(120)
    except BaseException as exc:
        atomic_json(path, {**value, 'status': 'failed', 'error': type(exc).__name__ + ': ' + str(exc),
                           'broker_stopped': False}, 0o600)
        raise
    finally:
        if listener is not None:
            listener.shutdown()
            listener.server_close()
            socket_path = Path(os.environ['WORKSTATION_BROKER_SOCKET'])
            if socket_path.is_socket() and not socket_path.is_symlink(): socket_path.unlink()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("shutdown_id")
    args = parser.parse_args()
    observe(identifier(args.shutdown_id))
