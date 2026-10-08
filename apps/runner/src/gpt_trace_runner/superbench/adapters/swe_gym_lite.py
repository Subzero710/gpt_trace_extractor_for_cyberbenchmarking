from __future__ import annotations

import hashlib
import json
import shlex
from dataclasses import dataclass
from pathlib import Path

from ...exceptions import AppInfrastructureError, RecoveryIncomplete
from ..models import EvaluationResult, TaskSpec
from .base import BenchmarkAdapter, PreparedBenchmarkContext
from .swe_gym import guest_runtime, source


@dataclass(frozen=True, slots=True)
class LiteContext(PreparedBenchmarkContext):
    instance_id: str


def guest_program(body):
    # Deliver runner-owned code each time, rather than executing a file the
    # teacher may have edited. Dataset gold patches are never passed to it.
    # A cancelled host request can leave its guest operation running. Serialize
    # retries inside the guest before touching the shared evaluator/checkouts.
    barrier = "\nimport fcntl\noperation_lock = (ROOT / 'attempt.lock').open('a+b')\n"
    barrier += "fcntl.flock(operation_lock, fcntl.LOCK_EX)\n"
    return Path(guest_runtime.__file__).read_text() + barrier + body + "\n"


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
    adapter_version = "1"

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
                  for repo in sorted(source.COUNTS)}
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
        body = f"""
item = json.loads({json.dumps(json.dumps(item))})
ROOT.joinpath('attempt').mkdir(exist_ok=True)
prepare(item, log=ROOT / 'attempt/setup.log')
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
        body = f"""
item = json.loads({json.dumps(json.dumps(item))})
folder = Path('/tmp/swe-gym-candidate')
folder.mkdir(exist_ok=True)
patch = folder / 'candidate.patch'
proof = candidate_patch('/testbed', item['base_commit'], patch)
mirror = ROOT / 'repos' / (repo_name(item['repo']) + '.git')
verify_candidate(item, patch, mirror, folder / 'verify')
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
                "backing_sha256": template["backing_sha256"]}

    async def evaluate_runtime(self, task, *, prepared, captured, candidate, runtime):
        if not isinstance(candidate, dict) or candidate.get("template_id") != task.workstation_template:
            raise RecoveryIncomplete("candidate checkpoint identity mismatch")
        expected = runtime.artifact_root / "candidate.patch"
        if candidate.get("local_path") != str(expected) or not expected.is_file() or expected.is_symlink():
            raise RecoveryIncomplete("persisted candidate artifact missing")
        patch = expected.read_bytes()
        if hashlib.sha256(patch).hexdigest() != candidate.get("sha256") or len(patch) != candidate.get("size"):
            raise RecoveryIncomplete("persisted candidate patch changed")
        row = self.rows()[task.task_id]
        item = source.contract()["tasks"][task.task_id]
        if candidate.get("env_hash") != item["env_hash"]:
            raise RecoveryIncomplete("candidate environment mapping changed")
        current = await runtime.provider.snapshot(runtime.task, runtime.environments, runtime.fingerprint,
                                                   attempt=runtime.attempt, control_token="unused-for-metadata")
        template = current["apps"]["kali-workstation"]
        if template["template_generation"] != candidate["template_generation"] or template["backing_sha256"] != candidate["backing_sha256"]:
            raise RecoveryIncomplete("candidate backing generation changed")
        await runtime.import_bytes(patch, "/tmp/swe-gym-candidate/exact-candidate.patch")
        official = source.harness()
        specs = official.constants.MAP_REPO_VERSION_TO_SPECS[row["repo"].lower()][row["version"]]
        directory = "/tmp/swe-gym-evaluator/repo"
        commands = official.test_spec.make_eval_script_list(row, specs, "testbed", directory,
                                                            row["base_commit"], row["test_patch"])
        test_command = official.test_spec.make_test_command(row)
        if commands[-2] != test_command:
            raise AppInfrastructureError("pinned native evaluation command contract changed")
        # Only the official hidden test patch enters the guest, after the runner's
        # durable candidate barrier. The dataset's gold code patch is never used.
        body = f"""
item = json.loads({json.dumps(json.dumps(item))})
folder = Path('/tmp/swe-gym-evaluator')
folder.mkdir(exist_ok=True)
mirror = ROOT / 'repos' / (repo_name(item['repo']) + '.git')
destination = folder / 'repo'
prefix = clone_env(item, offline=True)
configure_vcs_cache(item)
verify_candidate(item, '/tmp/swe-gym-candidate/exact-candidate.patch', mirror, destination)
env = runtime_environment(item, offline=True)
setup = setup_commands(item, mirror, prefix)
setup = relocate_checkout(setup, destination)
shell(setup, cwd=destination, env=env, offline=True, log=folder / 'setup.log')
commands = json.loads({json.dumps(json.dumps(commands))})
eval_script = 'set -eo pipefail\\n' + '\\n'.join(commands[:-2])
eval_script += '\\nset +e\\n' + commands[-2] + ' >' + shlex.quote(str(folder / 'tests.log')) + ' 2>&1\\n'
eval_script += 'status=$?\\nprintf \"%s\\n\" \"$status\" >' + shlex.quote(str(folder / 'tests.exit')) + '\\nexit 0\\n'
shell([eval_script], cwd=destination, env=env, offline=True, log=folder / 'eval-setup.log')
status = int((folder / 'tests.exit').read_text())
if status < 0 or status in (126, 127) or status >= 128:
    raise RuntimeError('native test process failed to execute')
print(json.dumps({{'test_exit_status': status}}))
"""
        result = await execute(runtime, guest_program(body))
        proof = json.loads(result["stdout"])
        log = await runtime.export("/tmp/swe-gym-evaluator/tests.log", "tests.log")
        # Keep setup diagnostics as artifacts even after a successful verdict.
        await runtime.export("/tmp/swe-gym-evaluator/eval-setup.log", "eval-setup.log")
        passed, counts = native_grade(row, Path(log["local_path"]).read_text(errors="replace"))
        return EvaluationResult("pass" if passed else "fail", score=1.0 if passed else 0.0, details=counts,
            metadata={"candidate_patch_sha256": candidate["sha256"], "candidate_artifact": candidate["local_path"],
                      "env_hash": item["env_hash"], "template_id": task.workstation_template,
                      "template_generation": candidate["template_generation"], "harness_commit": source.PINS["harness_commit"],
                      "test_command_sha256": hashlib.sha256(test_command.encode()).hexdigest(),
                      "test_exit_status": proof["test_exit_status"], "log_artifact_id": log["artifact_id"],
                      "log_sha256": log["sha256"], "log_artifact": log["local_path"]})
