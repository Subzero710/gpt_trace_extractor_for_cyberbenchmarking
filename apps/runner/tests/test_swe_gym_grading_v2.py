from __future__ import annotations

import json
import shlex
from pathlib import Path

from test_swe_gym_sources_v2 import history
from gpt_trace_runner.superbench.adapters.swe_gym import guest_runtime as guest, task_sources


def test_actual_candidate_setup_file_change_is_applied_after_clean_setup_before_hidden(history, tmp_path, monkeypatch):
    _, item, archive, record, *_ = history
    artifact = {**record,"path":str(archive)}
    teacher = tmp_path / "teacher"
    guest.clean_checkout(item, artifact, teacher)
    (teacher / "setup.py").write_text("CANDIDATE SETUP\n")
    patch = tmp_path / "candidate.patch"
    captured = guest.candidate_patch(teacher, item["base_commit"], patch)
    evaluator, logs, observed = tmp_path / "evaluator", tmp_path / "logs", tmp_path / "setup-observed"
    logs.mkdir()
    root = tmp_path / "runtime"
    (root / "task-provenance").mkdir(parents=True)
    (root / "task-provenance" / (item["instance_id"] + ".json")).write_text("{}")
    monkeypatch.setattr(guest, "ROOT", root)
    monkeypatch.setattr(guest, "env_inventory", lambda prefix: {})
    monkeypatch.setattr(guest, "verify_os_packages", lambda: None)
    events = []
    def prepare(item, *, artifact, **kwargs):
        guest.clean_checkout(item, artifact, evaluator)
        events.append("base")
        return tmp_path / "frozen-environment"
    monkeypatch.setattr(guest, "prepare", prepare)
    original_apply, original_shell = guest.apply_candidate, guest.shell
    def apply(*args, **kwargs):
        events.append("candidate")
        original_apply(*args, **kwargs)
    monkeypatch.setattr(guest, "apply_candidate", apply)
    def shell(commands, **kwargs):
        stage = Path(kwargs["log"]).name
        if stage == "eval-setup.log":
            events.append("setup")
            assert (evaluator / "setup.py").read_text() == "BASE SETUP\n"
            # An official setup mutation is restored after install, so applying
            # the exact base-relative persisted candidate remains well defined.
            original_shell(commands, cwd=evaluator, offline=False, log=kwargs["log"])
        elif stage == "hidden.log":
            events.append("hidden")
            assert (evaluator / "setup.py").read_text() == "CANDIDATE SETUP\n"
            original_shell(commands, cwd=evaluator, offline=False, log=kwargs["log"])
        else:
            events.append("tests")
            assert (evaluator / "hidden-test.txt").read_text() == "hidden after candidate\n"
            (logs / "tests.exit").write_text("1\n")
            (logs / "tests.log").write_text("FAILED native_test\n")
    monkeypatch.setattr(guest, "shell", shell)
    proof = guest.evaluate_clean(item, artifact, patch, candidate_sha256=captured["sha256"], candidate_size=captured["size"],
        setup=["cat setup.py > " + shlex.quote(str(observed)), "printf 'OFFICIAL SETUP MUTATION\\n' > setup.py"],
        hidden=["printf 'hidden after candidate\\n' > hidden-test.txt"], test_command="native test command", folder=logs, destination=evaluator)
    assert events == ["base","setup","candidate","hidden","tests"]
    assert observed.read_text() == "BASE SETUP\n"
    assert (evaluator / "setup.py").read_text() == "CANDIDATE SETUP\n"
    assert proof == {"test_exit_status":1}


def test_warming_freezes_repo_and_eval_install_inventories_separately(history, tmp_path, monkeypatch):
    _, item, *_ = history
    item = {**item, "eval_setup_commands": ["official evaluation install"]}
    root = tmp_path / "runtime"
    for name in ("task-provenance", "logs"):
        (root / name).mkdir(parents=True)
    monkeypatch.setattr(guest, "ROOT", root)
    phase = {"inventory": {"pip_freeze": "repo-dependency==1"}}
    monkeypatch.setattr(guest, "prepare", lambda *args, **kwargs: tmp_path / "environment")
    monkeypatch.setattr(guest, "env_inventory", lambda prefix: phase["inventory"])
    def eval_install(commands, **kwargs):
        assert commands == item["eval_setup_commands"]
        phase["inventory"] = {"pip_freeze": "repo-dependency==1\neval-dependency==2"}
    monkeypatch.setattr(guest, "shell", eval_install)
    monkeypatch.setattr(guest, "run", lambda *args, **kwargs: b"{}" if "-c" in args else b"[]")
    monkeypatch.setattr(guest, "freeze_vcs_dependencies", lambda *args: None)
    guest.warm_task(item, {})
    records = root / "task-provenance"
    assert json.loads((records / (item["instance_id"] + ".setup.json")).read_text()) == {"pip_freeze": "repo-dependency==1"}
    assert json.loads((records / (item["instance_id"] + ".json")).read_text()) == {"pip_freeze": "repo-dependency==1\neval-dependency==2"}


def test_clean_replay_verifies_each_install_against_its_own_frozen_phase(history, tmp_path, monkeypatch):
    _, item, archive, record, *_ = history
    item = {**item, "repo_script_list": []}
    root, logs, checkout = tmp_path / "runtime", tmp_path / "logs", tmp_path / "checkout"
    (root / "task-provenance").mkdir(parents=True)
    logs.mkdir()
    before, after = {"pip_freeze": "repo-dependency==1"}, {"pip_freeze": "repo-dependency==1\neval-dependency==2"}
    (root / "task-provenance" / (item["instance_id"] + ".setup.json")).write_text(json.dumps(before))
    (root / "task-provenance" / (item["instance_id"] + ".json")).write_text(json.dumps(after))
    monkeypatch.setattr(guest, "ROOT", root)
    monkeypatch.setattr(guest, "configure_vcs_cache", lambda item: None)
    monkeypatch.setattr(guest, "clone_env", lambda *args, **kwargs: tmp_path / "environment")
    monkeypatch.setattr(guest, "setup_commands", lambda *args: ["official repo setup"])
    monkeypatch.setattr(guest, "verify_os_packages", lambda: None)
    phase = {"inventory": None}
    def install(commands, **kwargs):
        assert (checkout / "setup.py").read_text() == "BASE SETUP\n"
        phase["inventory"] = before if commands == ["official repo setup"] else after
        (checkout / "setup.py").write_text("OFFICIAL INSTALL MUTATION\n")
    monkeypatch.setattr(guest, "shell", install)
    monkeypatch.setattr(guest, "env_inventory", lambda prefix: phase["inventory"])
    prefix = guest.prepare(item, artifact={**record, "path": str(archive)}, destination=checkout, log=logs / "setup.log")
    guest.evaluation_setup(item, prefix, ["official evaluation install"], logs, destination=checkout)
    assert phase["inventory"] == after
    assert (checkout / "setup.py").read_text() == "BASE SETUP\n"
