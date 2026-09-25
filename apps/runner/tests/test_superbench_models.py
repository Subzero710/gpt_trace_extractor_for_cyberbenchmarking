from gpt_trace_runner.superbench.models import TaskSpec, TeacherCampaign, run_task_id, task_spec_fingerprint


def test_campaign_identity_ignores_runtime_tuning_and_runner_commit():
    a = TeacherCampaign("gpt", {"turn_timeout_seconds": 1}, "commit-a")
    b = TeacherCampaign("gpt", {"turn_timeout_seconds": 9999}, "commit-b")
    assert a.campaign_id == b.campaign_id
    assert a.campaign_id != TeacherCampaign("other-model", {}, "commit-a").campaign_id


def test_run_identity_includes_adapter_version():
    campaign = TeacherCampaign("gpt", {}, "commit").campaign_id
    assert run_task_id("task", campaign, "gaia", "1") != run_task_id("task", campaign, "gaia", "2")



def test_task_spec_fingerprint_covers_metadata_and_source_files(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("one", encoding="utf-8")
    first = TaskSpec("x", "prompt", attachments=(source,), metadata={"revision": "1"})
    digest = task_spec_fingerprint(first)
    source.write_text("two", encoding="utf-8")
    assert task_spec_fingerprint(first) != digest
    second = TaskSpec("x", "prompt", attachments=(source,), metadata={"revision": "2"})
    assert task_spec_fingerprint(second) != task_spec_fingerprint(
        TaskSpec("x", "prompt", attachments=(source,), metadata={"revision": "1"})
    )
