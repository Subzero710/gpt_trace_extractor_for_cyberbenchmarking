#!/usr/bin/env python3
"""Real KVM/MCP acceptance on the configured pair. There are no simulated VM results."""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import uuid
from dataclasses import replace


async def exercise(adapter_name=None):
    from gpt_trace_runner.cli import internal_local_apps_task, make_lifecycle, ensure_no_pending_journal, ensure_no_running_storage
    from gpt_trace_runner.config import Settings
    from gpt_trace_runner.exceptions import AppInfrastructureError
    from gpt_trace_runner.lock import RunnerLock
    from gpt_trace_runner.manual_kali import require_manual_kali_stopped
    from gpt_trace_runner.models import task_fingerprint
    from gpt_trace_runner.registry import AppRegistry
    from gpt_trace_runner.runtime_preflight import preflight_tasks
    from gpt_trace_runner.storage_client import StorageClient
    from gpt_trace_runner.workstation_provider import InternalRuntime
    from rich.console import Console

    if os.environ.get("WORKSTATION_BROKER_TRANSPORT") != "mtls":
        raise RuntimeError("this acceptance command requires the real distributed deployment")
    settings = Settings()
    require_manual_kali_stopped(settings)
    ensure_no_pending_journal(settings)
    storage = StorageClient(settings.storage_base_url)
    try:
        await storage.health()
        await ensure_no_running_storage(storage)
    finally:
        await storage.close()
    task = internal_local_apps_task(AppRegistry.load(settings.app_registry_path),
        task_id="distributed-acceptance-" + uuid.uuid4().hex,
        prompt="Internal disposable distributed transport and isolation acceptance.")
    logical_task = None
    if adapter_name:
        from gpt_trace_runner.superbench.registry import AdapterRegistry
        adapter = AdapterRegistry.discover().get(adapter_name)
        choices = [item for item in adapter.discover_tasks() if item.workstation_template is not None]
        if not choices: raise RuntimeError("selected adapter exposes no immutable VM templates")
        logical_task = choices[0].task_id
        task = replace(task, workstation_template=choices[0].workstation_template, template_task_id=logical_task)
    lifecycle = make_lifecycle(settings, [task])
    fingerprint = task_fingerprint(task)
    environments = lifecycle.environment_ids(task, attempt=1, fingerprint=fingerprint)
    runtime = InternalRuntime(lifecycle.runtime, task, environments, fingerprint, 1,
        settings.runner_state_root / "distributed-acceptance" / task.task_id)
    prepared, completed = False, False
    try:
        with RunnerLock(settings.runner_lock_path):
            # Existing smoke performs actual PTY, guest browser, MCP manifest, screenshot, keyboard/mouse and network tests.
            await preflight_tasks(lifecycle, [task], console=Console())
            await lifecycle.prepare(task, environments, fingerprint, attempt=1)
            prepared = True
            first = await lifecycle.runtime_metadata(task, environments, fingerprint, attempt=1)
            second = await lifecycle.runtime_metadata(task, environments, fingerprint, attempt=1)
            if first != second: raise RuntimeError("authenticated rediscovery changed attempt identity or backing")
            data = os.urandom(3 * 1048576 + 197)
            path = "/home/kali/workspace/distributed-exact-bytes.bin"
            imported = await runtime.import_bytes(data, path)
            exported = await runtime.export(path, "roundtrip.bin")
            from pathlib import Path
            if Path(exported["local_path"]).read_bytes() != data or imported["sha256"] != hashlib.sha256(data).hexdigest():
                raise RuntimeError("remote bounded import/export did not preserve exact bytes")
            control_address = os.environ.get("WORKSTATION_CONTROL_PLANE_ADDRESS", "")
            if not control_address:
                raise RuntimeError("set DIST_CONTROL_ADDRESS on control host for physical isolation acceptance")
            program = "import socket\naddress=" + repr(control_address) + "\n"
            program += "for port in (22,8080,9222,9443):\n"
            program += " s=socket.socket(); s.settimeout(2)\n"
            program += " try:\n  s.connect((address,port))\n except OSError:\n  pass\n else:\n  raise SystemExit('Control Plane reachable from Kali')\n finally:\n  s.close()\n"
            isolation = await runtime.call("exec_command", {"command": "python3 -c 'import sys; exec(sys.stdin.read())'",
                "stdin": program, "cwd": "/tmp", "timeout_seconds": 20})
            if isolation["exit_code"] != 0: raise RuntimeError("Kali reached control host: " + isolation["stderr"])
            # Force a new HTTPS connection and rebind the exact surviving runtime through the normal recovery contract.
            await lifecycle.assert_resume(task, environments, fingerprint, attempt=1)
            if await lifecycle.runtime_metadata(task, environments, fingerprint, attempt=1) != first:
                raise RuntimeError("reconciliation did not preserve the original runtime")
            if logical_task is not None:
                from gpt_trace_runner.superbench.adapters.swe_gym.task_sources import artifact_id
                artifact = artifact_id("task_source", logical_task)
                template_record = await runtime.materialize_template_artifact(artifact)
                if template_record["logical_task_id"] != logical_task or template_record["artifact_id"] != artifact:
                    raise RuntimeError("remote template artifact source scope changed")
                evaluator = await runtime.create_evaluator()
                try:
                    if evaluator.record.get("network") is not None: raise RuntimeError("evaluator has a network route")
                    interfaces = await evaluator.call("exec_command", {"command": "ls /sys/class/net", "cwd": "/tmp"})
                    if interfaces["exit_code"] != 0 or interfaces["stdout"].split() != ["lo"]:
                        raise RuntimeError("isolated evaluator contains a network interface")
                    delivered = await evaluator.materialize_template_artifact(artifact)
                    if delivered["sha256"] != template_record["sha256"]: raise RuntimeError("evaluator template source digest changed")
                    await evaluator.import_bytes(data, "/tmp/distributed-evaluator-bytes")
                    evaluator_copy = await evaluator.export("/tmp/distributed-evaluator-bytes", "evaluator-roundtrip.bin")
                    if Path(evaluator_copy["local_path"]).read_bytes() != data: raise RuntimeError("evaluator transfer integrity mismatch")
                    try:
                        await evaluator.call("browser_goto", {"url": "https://example.com"})
                    except AppInfrastructureError as exc:
                        if "no browser" not in str(exc): raise
                    else:
                        raise RuntimeError("evaluator admitted a model/browser RPC")
                finally:
                    await evaluator.destroy()
            await lifecycle.reset(task, environments, fingerprint, attempt=1)
            prepared = False
            await lifecycle.assert_clean(task, environments, fingerprint, attempt=1)
            completed = True
            print(json.dumps({"status": "passed", "task_id": task.task_id,
                "transport": "real mTLS", "runtime": first, "template_evaluator_tested": logical_task is not None}, indent=2))
    finally:
        # Technical failures remain diagnosable; do not invent cleanup success or destroy an uncertain attempt.
        await lifecycle.close()
        if prepared and not completed:
            print("Acceptance interrupted. Preserve this exact attempt for diagnosis: " + task.task_id)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--adapter", choices=("swe-gym-lite",))
    args = parser.parse_args()
    asyncio.run(exercise(args.adapter))
