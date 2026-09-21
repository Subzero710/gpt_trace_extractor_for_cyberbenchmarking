from __future__ import annotations
from importlib.metadata import entry_points
from .adapters.base import BenchmarkAdapter

class AdapterRegistry:
    def __init__(self, adapters: list[BenchmarkAdapter]):
        self.adapters = {a.adapter_id: a for a in adapters}
        if len(self.adapters) != len(adapters): raise ValueError("duplicate adapter_id")
    @classmethod
    def discover(cls):
        adapters: list[BenchmarkAdapter] = []
        for ep in entry_points(group="gpt_trace_runner.benchmark_adapters"):
            obj = ep.load(); adapters.append(obj() if isinstance(obj, type) else obj)
        return cls(adapters)
    def get(self, adapter_id): return self.adapters[adapter_id]
