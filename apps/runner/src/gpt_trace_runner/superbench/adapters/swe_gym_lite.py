from __future__ import annotations

import hashlib
import json
import shlex
from dataclasses import dataclass
from pathlib import Path

from ...exceptions import AppInfrastructureError, RecoveryIncomplete
from ..models import EvaluationResult, TaskSpec
from .base import BenchmarkAdapter, PreparedBenchmarkContext
from .swe_gym import guest_runtime, source, task_sources


@dataclass(frozen=True, slots=True)
class LiteContext(PreparedBenchmarkContext):
    instance_id: str


def guest_program(body):
    # Both helpers are runner-owned bytes, including during teacher capture.
    program = "import types\n_sources = types.ModuleType('trusted_task_sources')\n"
    program += "exec(compile(" + repr(Path(task_sources.__file__).read_text()) + ", 'trusted-task-sources', 'exec'), _sources.__dict__)\n"
    program += "exec(compile(" + repr(Path(guest_runtime.__file__).read_text()) + ", 'trusted-swe-gym-runtime', 'exec'), globals())\n"
    program += "import fcntl\noperation_lock = (ROOT / 'attempt.lock').open('a+b')\nfcntl.flock(operation_lock, fcntl.LOCK_EX)\n"
    return program + body + "\n"


async def materialize(runtime, item, kind):
    artifact_id = task_sources.artifact_id(kind, item['instance_id'])
    record = await runtime.materialize_template_artifact(artifact_id)
    expected = {key: item[key] for key in ('instance_id', 'repo', 'base_commit')}
    if record.get('artifact_id') != artifact_id or record.get('kind') != kind or record.get('logical_task_id') != item['instance_id'] or record.get('source_identity') != expected or record.get('path') != '/var/lib/gpt-trace-template-artifacts/' + artifact_id + '/payload':
        raise AppInfrastructureError('task template artifact identity mismatch')
    return record


async def execute(runtime, program, *, timeout=1800):
    result = await runtime.call("exec_command", {
        "command": "sudo -n /usr/bin/python3 -c 'import sys; exec(compile(sys.stdin.read(), \"trusted-swe-gym\", \"exec\"))'",
        "cwd": "/tmp", "stdin": program, "timeout_seconds": timeout,
    })
    if result.get("timed_out") or result.get("exit_code") != 0 or result.get("stdout_truncated") or result.get("stderr_truncated"):
        raise AppInfrastructureError("SWE-Gym trusted guest operation failed: " + str(result.get("stderr", ""))[-3000:])
    return result


def native_grade(row, output):
    official = source.harness()
    statuses = official.parsers.MAP_REPO_TO_PARSER[row["repo"].lower()](output)
    if not statuses:
        raise AppInfrastructureError("official SWE-Gym parser produced no test results")
    oracle = {key: json.loads(row[key]) if isinstance(row[key], str) else row[key]
              for key in ("FAIL_TO_PASS", "PASS_TO_PASS")}
    report = official.grading.get_eval_tests_report(statuses, oracle)
    resolution = official.grading.get_resolution_status(report)
    counts = {key: {name: len(values) for name, values in report[key].items()}
              for key in ("FAIL_TO_PASS", "PASS_TO_PASS")}
    return resolution == official.constants.ResolvedStatus.FULL.value, counts


class SWEGymLiteAdapter(BenchmarkAdapter):
    adapter_id = "swe-gym-lite"
    adapter_version = "2"

    def __init__(self):
        self._rows = None

    @property
    def uses_runtime_hooks(self):
        return True

    def fetch(self):
        source.fetch(self.source_root)

    def rows(self):
        if self._rows is None:
            self._rows = {row["instance_id"]: row for row in source.read_rows(self.source_root)}
        return self._rows

    def discover_tasks(self):
        rows = self.rows()
        data = source.contract()
        groups = {repo: sorted((row for row in rows.values() if row["repo"] == repo), key=lambda row: row["instance_id"])
                  for repo in sorted(source.repository_counts(data))}
        ordered = []
        while any(groups.values()):
            for group in groups.values():
                if group:
                    ordered.append(group.pop(0))
        return [TaskSpec(
            task_id=row["instance_id"], prompt=row["problem_statement"], tools=("kali-workstation",),
            workstation_template=data["tasks"][row["instance_id"]]["template_id"],
            metadata={"repo": row["repo"], "base_commit": row["base_commit"], "version": row["version"],
                      "env_hash": data["tasks"][row["instance_id"]]["env_hash"],
                      "dataset_revision": source.PINS["dataset_revision"],
                      "parquet_sha256": source.PINS["parquet_sha256"],
                      "harness_commit": source.PINS["harness_commit"],
                      "source_fingerprint": source.source_fingerprint(), "recipe_version": source.PINS["recipe_version"],
                      "selection_order": position},
        ) for position, row in enumerate(ordered)]

    def task_order_key(self, task):
        return f"{task.metadata['selection_order']:06d}:{task.task_id}"

    async def prepare(self, task):
        if task.task_id not in self.rows():
            raise AppInfrastructureError("unknown pinned Lite instance")
        return LiteContext(task.task_id)

    async def prepare_runtime(self, task, *, prepared, runtime):
        item = source.contract()["tasks"][task.task_id]
        if task.workstation_template != item["template_id"]:
            raise AppInfrastructureError("Lite task/template mapping mismatch")
        artifact = await materialize(runtime, item, "task_source")
        cache = await materialize(runtime, item, "setup_cache")
        body = f"""
item = json.loads({json.dumps(json.dumps(item))})
ROOT.joinpath('attempt').mkdir(exist_ok=True)
artifact = json.loads({json.dumps(json.dumps(artifact))})
cache = json.loads({json.dumps(json.dumps(cache))})
install_setup_cache(item, cache)
prepare(item, artifact=artifact, log=ROOT / 'attempt/setup.log')
workspace = Path('/home/kali/workspace')
if workspace.is_symlink():
    if workspace.resolve() != Path('/testbed'):
        raise RuntimeError('unexpected teacher workspace symlink')
else:
    if list(workspace.iterdir()):
        raise RuntimeError('teacher workspace was not empty before benchmark setup')
    workspace.rmdir()
    workspace.symlink_to('/testbed', target_is_directory=True)
run('chmod', '-R', '777', '/testbed')
profile = Path('/etc/profile.d/swe-gym-lite.sh')
profile.write_text('source /opt/miniconda3/bin/activate testbed\\n')
print(json.dumps({{'base_commit': run('git', '-C', '/testbed', 'rev-parse', 'HEAD').decode().strip(),
                  'env_hash': item['env_hash']}}))
"""
        result = await execute(runtime, guest_program(body))
        proof = json.loads(result["stdout"])
        if proof != {"base_commit": item["base_commit"], "env_hash": item["env_hash"]}:
            raise AppInfrastructureError("Lite runtime setup proof mismatch")

    async def capture_candidate(self, task, *, prepared, captured, runtime):
        item = source.contract()["tasks"][task.task_id]
        artifact = await materialize(runtime, item, "task_source")
        body = f"""
item = json.loads({json.dumps(json.dumps(item))})
artifact = json.loads({json.dumps(json.dumps(artifact))})
folder = Path('/tmp/swe-gym-candidate')
folder.mkdir(exist_ok=True)
patch = folder / 'candidate.patch'
proof = candidate_patch('/testbed', item['base_commit'], patch)
verify_candidate(item, patch, artifact, folder / 'verify')
print(json.dumps(proof))
"""
        result = await execute(runtime, guest_program(body))
        proof = json.loads(result["stdout"])
        exported = await runtime.export("/tmp/swe-gym-candidate/candidate.patch", "candidate.patch")
        if exported["sha256"] != proof.get("sha256") or exported["size"] != proof.get("size"):
            raise AppInfrastructureError("candidate changed while exporting")
        template = captured.runtime_metadata.get("app_runtime", {}).get("apps", {}).get("kali-workstation", {})
        if template.get("template_id") != task.workstation_template or template.get("template_source_fingerprint") != source.source_fingerprint():
            raise AppInfrastructureError("candidate runtime template provenance mismatch")
        return {**exported, "env_hash": item["env_hash"], "template_id": task.workstation_template,
                "template_generation": template["template_generation"],
                "backing_sha256": template["backing_sha256"], "source_sha256": artifact["sha256"],
                "source_artifact_id": artifact["artifact_id"]}

    async def evaluate_runtime(self, task, *, prepared, captured, candidate, runtime):
        if not isinstance(candidate, dict) or candidate.get("template_id") != task.workstation_template:
            raise RecoveryIncomplete("candidate checkpoint identity mismatch")
        expected = runtime.artifact_root / "candidate.patch"
        if candidate.get("local_path") != str(expected) or not expected.is_file() or expected.is_symlink():
            raise RecoveryIncomplete("persisted candidate artifact missing")
        if expected.stat().st_size != candidate.get("size") or expected.stat().st_size > 268435456 or task_sources.digest(expected) != candidate.get("sha256"):
            raise RecoveryIncomplete("persisted candidate patch changed")
        patch = expected.read_bytes()  # Candidate is bounded; source archives never enter runner RAM.
        if hashlib.sha256(patch).hexdigest() != candidate["sha256"]:
            raise RecoveryIncomplete("candidate changed while reading")
        row = self.rows()[task.task_id]
        item = source.contract()["tasks"][task.task_id]
        if candidate.get("env_hash") != item["env_hash"]:
            raise RecoveryIncomplete("candidate environment mapping changed")
        current = await runtime.provider.snapshot(runtime.task, runtime.environments, runtime.fingerprint,
                                                   attempt=runtime.attempt, control_token="unused-for-metadata")
        template = current["apps"]["kali-workstation"]
        if template["template_generation"] != candidate["template_generation"] or template["backing_sha256"] != candidate["backing_sha256"]:
            raise RecoveryIncomplete("candidate backing generation changed")
        evaluator = await runtime.create_evaluator()
        record = evaluator.record
        if record["template_generation"] != candidate["template_generation"] or record["backing_sha256"] != candidate["backing_sha256"] or record["backing_path"] != template["backing_path"]:
            raise RecoveryIncomplete("fresh evaluator backing differs from teacher immutable generation")
        try:
            artifact = await materialize(evaluator, item, "task_source")
            if artifact["sha256"] != candidate.get("source_sha256") or artifact["artifact_id"] != candidate.get("source_artifact_id"):
                raise RecoveryIncomplete("checkpointed source artifact changed")
            cache = await materialize(evaluator, item, "setup_cache")
            official = source.harness()
            specs = official.constants.MAP_REPO_VERSION_TO_SPECS[row["repo"].lower()][row["version"]]
            commands = official.test_spec.make_eval_script_list(row, specs, "testbed", "/testbed",
                                                                row["base_commit"], row["test_patch"])
            test_command = official.test_spec.make_test_command(row)
            if commands[-2] != test_command or commands[-3].find(row["test_patch"]) < 0:
                raise AppInfrastructureError("pinned native evaluation command contract changed")
            setup = commands[:-4]  # Includes upstream eval-time install, on CLEAN BASE.
            hidden = commands[:3] + specs.get("eval_commands", []) + commands[-4:-2]
            # No gold patch or oracle lists enter either VM. Only hidden tests
            # enter this runner-only evaluator, after clean setup and candidate.
            prepare_body = f"""
item = json.loads({json.dumps(json.dumps(item))})
artifact = json.loads({json.dumps(json.dumps(artifact))})
cache = json.loads({json.dumps(json.dumps(cache))})
install_setup_cache(item, cache)
proof = prepare_evaluator(item, artifact, json.loads({json.dumps(json.dumps(setup))}), '/tmp/swe-gym-evaluator')
print(json.dumps(proof))
"""
            ready = await execute(evaluator, guest_program(prepare_body))
            if json.loads(ready["stdout"]) != {"base_commit":item["base_commit"], "env_hash":item["env_hash"], "source_sha256":artifact["sha256"]}:
                raise AppInfrastructureError("clean evaluator setup proof mismatch")
            # Even the candidate FILE enters only after all clean setup succeeds.
            await evaluator.import_bytes(patch, "/tmp/swe-gym-candidate/exact-candidate.patch")
            body = f"""
item = json.loads({json.dumps(json.dumps(item))})
proof = grade_prepared(item, '/tmp/swe-gym-candidate/exact-candidate.patch',
    candidate_sha256={candidate['sha256']!r}, candidate_size={candidate['size']!r},
    hidden=json.loads({json.dumps(json.dumps(hidden))}), test_command={test_command!r},
    test_prelude=json.loads({json.dumps(json.dumps(commands[:3] + specs.get('eval_commands', [])))}),
    folder='/tmp/swe-gym-evaluator')
print(json.dumps(proof))
"""
            result = await execute(evaluator, guest_program(body))
            proof = json.loads(result["stdout"])
            log = await evaluator.export("/tmp/swe-gym-evaluator/tests.log", "tests.log")
            await evaluator.export("/tmp/swe-gym-evaluator/setup.log", "setup.log")
            await evaluator.export("/tmp/swe-gym-evaluator/eval-setup.log", "eval-setup.log")
            await evaluator.export("/tmp/swe-gym-evaluator/hidden.log", "hidden.log")
            passed, counts = native_grade(row, Path(log["local_path"]).read_text(errors="replace"))
        except BaseException:
            # Preserve both guests, exact checkpoint and broker artifacts. These
            # best-effort diagnostic exports never substitute for a verdict.
            errors = []
            for name in ("setup.log", "eval-setup.log", "hidden.log", "tests.log", "test-launch.log"):
                try:
                    await evaluator.export("/tmp/swe-gym-evaluator/" + name, name)
                except Exception as exc:
                    errors.append({"artifact": name, "error": str(exc)[:1000]})
            evaluator.artifact_root.mkdir(parents=True, exist_ok=True)
            (evaluator.artifact_root / "diagnostic-export-errors.json").write_text(json.dumps(errors))
            raise
        await evaluator.destroy()  # Native pass AND native fail use normal cleanup.
        return EvaluationResult("pass" if passed else "fail", score=1.0 if passed else 0.0, details=counts,
            metadata={"candidate_patch_sha256": candidate["sha256"], "candidate_artifact": candidate["local_path"],
                      "env_hash": item["env_hash"], "template_id": task.workstation_template,
                      "template_generation": candidate["template_generation"], "harness_commit": source.PINS["harness_commit"],
                      "evaluator_identity": record["identity"], "evaluator_backing_sha256": record["backing_sha256"],
                      "source_artifact_sha256": artifact["sha256"],
                      "test_command_sha256": hashlib.sha256(test_command.encode()).hexdigest(),
                      "test_exit_status": proof["test_exit_status"], "log_artifact_id": log["artifact_id"],
                      "log_sha256": log["sha256"], "log_artifact": log["local_path"]})
