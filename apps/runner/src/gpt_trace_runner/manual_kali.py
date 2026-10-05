from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from .app_lifecycle import AppLifecycle
from .config import Settings
from .exceptions import AppInfrastructureError, RecoveryIncomplete
from .journal import JournalStore
from .models import BenchmarkTask, BenchmarkTool, task_fingerprint
from .registry import AppRegistry
from .superbench.run_control import RunControlStore
from .workstation_provider import LibvirtWorkstationProvider

APP_ID = "kali-workstation"
MANUAL_TASK_ID = "__manual_kali__"
MANUAL_ATTEMPT = 910001
STATE_SCHEMA_VERSION = 1

ManualPhase = Literal["starting", "running"]


@dataclass(frozen=True, slots=True)
class ManualKaliState:
    schema_version: int
    phase: ManualPhase
    task_id: str
    attempt: int
    task_fingerprint: str
    environment_id: str
    started_at: str

    def validate(self) -> "ManualKaliState":
        if self.schema_version != STATE_SCHEMA_VERSION:
            raise RecoveryIncomplete("unsupported manual Kali state schema")
        if self.phase not in {"starting", "running"}:
            raise RecoveryIncomplete("invalid manual Kali state phase")
        if self.task_id != MANUAL_TASK_ID:
            raise RecoveryIncomplete("manual Kali state has unexpected task_id")
        if not 1 <= self.attempt <= 1_000_000:
            raise RecoveryIncomplete("manual Kali state has invalid attempt")
        if not re.fullmatch(r"[0-9a-f]{64}", self.task_fingerprint):
            raise RecoveryIncomplete("manual Kali state has invalid task fingerprint")
        if not self.environment_id or len(self.environment_id) > 255:
            raise RecoveryIncomplete("manual Kali state has invalid environment_id")
        if not self.started_at:
            raise RecoveryIncomplete("manual Kali state has invalid started_at")
        return self


class ManualKaliStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> ManualKaliState | None:
        if not self.path.exists():
            return None
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("state must be a JSON object")
            return ManualKaliState(**payload).validate()
        except RecoveryIncomplete:
            raise
        except Exception as exc:
            raise RecoveryIncomplete(
                f"manual Kali state is unreadable: {self.path}: {exc}"
            ) from exc

    def write(self, state: ManualKaliState) -> None:
        state.validate()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        data = json.dumps(asdict(state), sort_keys=True, separators=(",", ":"))
        with tmp.open("w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self.path)
        self._sync_parent()

    def clear(self) -> None:
        if not self.path.exists():
            return
        self.path.unlink()
        self._sync_parent()

    def _sync_parent(self) -> None:
        fd = os.open(self.path.parent, os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def manual_kali_task(registry: AppRegistry) -> BenchmarkTask:
    resolved = registry.resolve_id(APP_ID)
    if resolved.kind != "local_mcp":
        raise RuntimeError(f"{APP_ID!r} must resolve to a local_mcp App")
    tool = BenchmarkTool(
        type="app",
        app_id=resolved.app_id,
        ui_name=resolved.ui_name,
        kind=resolved.kind,
        version=resolved.version,
        manifest_sha256=resolved.manifest_sha256,
        tool_manifest=resolved.manifest,
        mcp_endpoint=resolved.mcp_endpoint,
        control_endpoint=resolved.control_endpoint,
        attachment_mode=resolved.attachment_mode,
    )
    return BenchmarkTask(
        task_id=MANUAL_TASK_ID,
        prompt="Manual ephemeral Kali workstation.",
        attachments=(),
        tools=(tool,),
    )


def require_manual_kali_stopped(settings: Settings) -> None:
    state = ManualKaliStore(settings.manual_kali_state_path).load()
    if state is not None:
        raise RecoveryIncomplete(
            "manual Kali workstation state exists; run `make status_kali` and "
            "`make stop_kali` before starting a benchmark/registration lifecycle"
        )


def require_no_active_benchmark_for_manual_kali(settings: Settings) -> None:
    journal = JournalStore(settings.journal_path).load()
    if journal is not None:
        raise RecoveryIncomplete(
            f"pending benchmark recovery journal for {journal.task_id!r}; "
            "resolve/resume it before using manual Kali"
        )
    active = RunControlStore(settings.superbench_active_run_path).load()
    if active is not None and active.status != "completed":
        raise RecoveryIncomplete(
            f"Superbench run {active.run_id} is {active.status}; "
            "manual Kali is unavailable until that run is completed/reset"
        )


class ManualKaliManager:
    def __init__(
        self,
        settings: Settings,
        registry: AppRegistry,
        *,
        lifecycle: AppLifecycle | None = None,
    ) -> None:
        self.settings = settings
        self.task = manual_kali_task(registry)
        self.tool = self.task.tools[0]
        self.fingerprint = task_fingerprint(self.task)
        self.attempt = MANUAL_ATTEMPT
        self.environments = AppLifecycle.environment_ids(
            self.task,
            attempt=self.attempt,
            fingerprint=self.fingerprint,
        )
        self.store = ManualKaliStore(settings.manual_kali_state_path)
        self._owns_lifecycle = lifecycle is None
        self.lifecycle = lifecycle or AppLifecycle(
            settings.app_control_token_file,
            runtime=LibvirtWorkstationProvider(
                settings.workstation_broker_socket,
                settings.workstation_broker_token_file,
            ),
        )

    async def close(self) -> None:
        if self._owns_lifecycle:
            await self.lifecycle.close()

    def _state(
        self,
        phase: ManualPhase,
        *,
        fingerprint: str | None = None,
        environment_id: str | None = None,
        attempt: int | None = None,
        started_at: str | None = None,
    ) -> ManualKaliState:
        return ManualKaliState(
            schema_version=STATE_SCHEMA_VERSION,
            phase=phase,
            task_id=MANUAL_TASK_ID,
            attempt=self.attempt if attempt is None else attempt,
            task_fingerprint=self.fingerprint if fingerprint is None else fingerprint,
            environment_id=(
                self.environments[APP_ID]
                if environment_id is None
                else environment_id
            ),
            started_at=started_at
            or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        ).validate()

    @staticmethod
    def _matches_active(state: ManualKaliState, active: object) -> bool:
        if not isinstance(active, dict):
            return False
        return (
            active.get("task_id") == state.task_id
            and active.get("attempt") == state.attempt
            and active.get("environment_id") == state.environment_id
            and active.get("task_fingerprint") == state.task_fingerprint
        )

    def _state_from_active(
        self,
        active: dict,
        *,
        started_at: str | None = None,
    ) -> ManualKaliState:
        if active.get("task_id") != MANUAL_TASK_ID:
            raise RecoveryIncomplete("gateway is not owned by manual Kali")
        attempt = active.get("attempt")
        environment_id = active.get("environment_id")
        fingerprint = active.get("task_fingerprint")
        if type(attempt) is not int:
            raise RecoveryIncomplete("gateway manual Kali attempt is invalid")
        if not isinstance(environment_id, str):
            raise RecoveryIncomplete("gateway manual Kali environment is invalid")
        if not isinstance(fingerprint, str):
            raise RecoveryIncomplete("gateway manual Kali fingerprint is invalid")
        return self._state(
            "running",
            attempt=attempt,
            environment_id=environment_id,
            fingerprint=fingerprint,
            started_at=started_at,
        )

    @staticmethod
    def _environments(state: ManualKaliState) -> dict[str, str]:
        return {APP_ID: state.environment_id}

    async def _runtime_probe(
        self,
        state: ManualKaliState,
    ) -> tuple[bool, dict | None, str | None]:
        try:
            metadata = await self.lifecycle.runtime_metadata(
                self.task,
                self._environments(state),
                state.task_fingerprint,
                attempt=state.attempt,
            )
        except AppInfrastructureError as exc:
            return False, None, str(exc)
        return True, metadata, None

    async def status(self) -> dict:
        persisted = self.store.load()
        gateway_error: str | None = None
        try:
            gateway = await self.lifecycle.gateway_status(self.tool)
        except AppInfrastructureError as exc:
            gateway = {"active": None}
            gateway_error = str(exc)

        active = gateway.get("active")
        probe_state = persisted
        if (
            probe_state is None
            and isinstance(active, dict)
            and active.get("task_id") == MANUAL_TASK_ID
        ):
            probe_state = self._state_from_active(active)
        if probe_state is None:
            probe_state = self._state("running")

        runtime_ok, runtime_metadata, runtime_error = await self._runtime_probe(
            probe_state
        )

        if gateway_error is not None:
            status = "unavailable"
        elif isinstance(active, dict) and active.get("task_id") != MANUAL_TASK_ID:
            status = "benchmark-owned"
        elif persisted is None and active is None and not runtime_ok:
            status = "stopped"
        elif (
            persisted is not None
            and persisted.phase == "running"
            and self._matches_active(persisted, active)
            and runtime_ok
        ):
            status = "running"
        else:
            status = "inconsistent"

        runtime_summary = None
        if isinstance(runtime_metadata, dict):
            runtime_summary = runtime_metadata.get("apps", {}).get(APP_ID)
            if runtime_summary is None:
                runtime_summary = runtime_metadata

        return {
            "status": status,
            "state": asdict(persisted) if persisted is not None else None,
            "gateway_active": active,
            "gateway_error": gateway_error,
            "runtime_present": runtime_ok,
            "runtime": runtime_summary,
            "runtime_error": runtime_error,
        }

    async def start(self) -> dict:
        existing = self.store.load()
        if existing is not None:
            raise RecoveryIncomplete(
                "manual Kali state already exists; run `make status_kali` "
                "or `make stop_kali`"
            )

        gateway = await self.lifecycle.gateway_status(self.tool)
        active = gateway.get("active")
        if active is not None:
            owner = active.get("task_id") if isinstance(active, dict) else "<unknown>"
            raise RecoveryIncomplete(
                f"Kali Workstation gateway is already owned by {owner!r}"
            )

        candidate = self._state("starting")
        try:
            await self.lifecycle.runtime.assert_absent(
                self.task,
                self._environments(candidate),
                candidate.task_fingerprint,
                attempt=candidate.attempt,
            )
        except AppInfrastructureError as exc:
            raise RecoveryIncomplete(
                "manual Kali resources already exist without clean state; "
                "run `make status_kali` then `make stop_kali`"
            ) from exc

        self.store.write(candidate)
        await self.lifecycle.prepare(
            self.task,
            self._environments(candidate),
            candidate.task_fingerprint,
            attempt=candidate.attempt,
        )
        self.store.write(replace(candidate, phase="running"))
        return await self.status()

    async def stop(self) -> dict:
        persisted = self.store.load()
        gateway = await self.lifecycle.gateway_status(self.tool)
        active = gateway.get("active")

        if isinstance(active, dict) and active.get("task_id") != MANUAL_TASK_ID:
            raise RecoveryIncomplete(
                "Kali Workstation gateway is owned by benchmark task "
                f"{active.get('task_id')!r}; refusing manual cleanup"
            )

        if persisted is not None:
            state = persisted
            if active is not None and not self._matches_active(state, active):
                raise RecoveryIncomplete(
                    "manual Kali state and gateway identity disagree; "
                    "refusing to destroy an ambiguous runtime"
                )
        elif isinstance(active, dict):
            state = self._state_from_active(active)
        else:
            state = self._state("running")

        runtime_ok, _, runtime_error = await self._runtime_probe(state)

        if active is not None and self._matches_active(state, active):
            await self.lifecycle.reset(
                self.task,
                self._environments(state),
                state.task_fingerprint,
                attempt=state.attempt,
            )
            await self.lifecycle.assert_clean(
                self.task,
                self._environments(state),
                state.task_fingerprint,
                attempt=state.attempt,
            )
            self.store.clear()
            return await self.status()

        if runtime_ok:
            await self.lifecycle.assert_resume(
                self.task,
                self._environments(state),
                state.task_fingerprint,
                attempt=state.attempt,
            )
            await self.lifecycle.reset(
                self.task,
                self._environments(state),
                state.task_fingerprint,
                attempt=state.attempt,
            )
            await self.lifecycle.assert_clean(
                self.task,
                self._environments(state),
                state.task_fingerprint,
                attempt=state.attempt,
            )
            self.store.clear()
            return await self.status()

        try:
            await self.lifecycle.runtime.assert_absent(
                self.task,
                self._environments(state),
                state.task_fingerprint,
                attempt=state.attempt,
            )
        except AppInfrastructureError as exc:
            raise RecoveryIncomplete(
                "manual Kali runtime could not be inspected or proven absent; "
                f"last inspect error: {runtime_error or '<none>'}"
            ) from exc

        self.store.clear()
        return await self.status()
