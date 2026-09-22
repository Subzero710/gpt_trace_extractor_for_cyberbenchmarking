import pytest

from gpt_trace_runner.superbench.adapters.base import BenchmarkAdapter
from gpt_trace_runner.superbench.catalog import SuperbenchCatalog
from gpt_trace_runner.superbench.models import TaskSpec
from gpt_trace_runner.superbench.registry import AdapterRegistry


class A(BenchmarkAdapter):
    adapter_id = "a"
    adapter_version = "1"

    def discover_tasks(self):
        return [TaskSpec("same", "a")]


class B(A):
    adapter_id = "b"

    def discover_tasks(self):
        return [TaskSpec("same", "b")]


def test_duplicate_task_ids_across_adapters_are_rejected():
    with pytest.raises(ValueError, match="duplicate task_id"):
        SuperbenchCatalog(AdapterRegistry([A(), B()])).discover()
