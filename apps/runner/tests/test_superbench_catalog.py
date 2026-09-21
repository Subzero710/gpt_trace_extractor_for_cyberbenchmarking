import pytest
from gpt_trace_runner.superbench.catalog import SuperbenchCatalog
from gpt_trace_runner.superbench.registry import AdapterRegistry
from gpt_trace_runner.superbench.adapters.base import BenchmarkAdapter
from gpt_trace_runner.superbench.models import CanonicalTask,EvaluationResult
class A(BenchmarkAdapter):
 adapter_id='a'; adapter_version='1'
 def discover_tasks(self): return [CanonicalTask('a:1','x','1','1','repo','sha','p','a','1',dedup_group='same')]
 async def evaluate(self,*a,**k): return EvaluationResult(True)
class B(A):
 adapter_id='b'
 def discover_tasks(self): return [CanonicalTask('b:1','y','1','2','repo2','sha','p','b','1',dedup_group='same')]
def test_cross_source_duplicate_detection():
 with pytest.raises(ValueError,match='cross-source'): SuperbenchCatalog(AdapterRegistry([A(),B()])).discover()
