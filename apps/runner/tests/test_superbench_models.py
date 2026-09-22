import pytest

from gpt_trace_runner.superbench.models import TaskSpec, TeacherCampaign, run_task_id


def test_campaign_identity_ignores_runtime_tuning_and_runner_commit():
    a = TeacherCampaign("gpt", {"turn_timeout_seconds": 1}, "commit-a")
    b = TeacherCampaign("gpt", {"turn_timeout_seconds": 9999}, "commit-b")
    assert a.campaign_id == b.campaign_id
    assert a.campaign_id != TeacherCampaign("other-model", {}, "commit-a").campaign_id


def test_run_identity_includes_adapter_version():
    campaign = TeacherCampaign("gpt", {}, "commit").campaign_id
    assert run_task_id("task", campaign, "gaia", "1") != run_task_id("task", campaign, "gaia", "2")


def test_required_tools_must_be_declared():
    TaskSpec("x", "prompt", tools=("browser",), required_tools=("browser",))
    with pytest.raises(ValueError, match="required tools"):
        TaskSpec("x", "prompt", tools=("browser",), required_tools=("code-workspace",))
