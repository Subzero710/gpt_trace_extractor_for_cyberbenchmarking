from __future__ import annotations
from dataclasses import dataclass, field
import hashlib, json, re
from pathlib import Path
from typing import Any

_ID=re.compile(r"^[a-z0-9][a-z0-9._:-]{0,254}$")

def _stable(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()

@dataclass(frozen=True, slots=True)
class TaskBudgets:
    max_runtime: float|None=None; max_tool_calls: int|None=None; max_messages: int|None=None; max_output_bytes: int|None=None
    def __post_init__(self):
        for n in ("max_runtime","max_tool_calls","max_messages","max_output_bytes"):
            v=getattr(self,n)
            if v is not None and v <= 0: raise ValueError(f"{n} must be positive or null")
    def as_dict(self): return {k:getattr(self,k) for k in self.__slots__}

@dataclass(frozen=True, slots=True)
class EvaluationResult:
    success: bool|None
    reward: float|None=None
    native_result: dict[str,Any]=field(default_factory=dict)
    evaluator_metadata: dict[str,Any]=field(default_factory=dict)
    def as_dict(self): return {"success":self.success,"reward":self.reward,"native_result":self.native_result,"evaluator_metadata":self.evaluator_metadata}

@dataclass(frozen=True, slots=True)
class CanonicalTask:
    canonical_task_id: str
    source_benchmark: str
    source_benchmark_version: str
    source_task_id: str
    upstream_repository: str
    upstream_commit: str
    prompt: str
    adapter_id: str
    adapter_version: str
    source_license: str|None=None
    source_metadata: dict[str,Any]=field(default_factory=dict)
    required_apps: tuple[str,...]=()
    attachments: tuple[Path,...]=()
    initial_workspace: Path|None=None
    environment_spec: dict[str,Any]=field(default_factory=dict)
    evaluator_metadata: dict[str,Any]=field(default_factory=dict)
    budgets: TaskBudgets=field(default_factory=TaskBudgets)
    dedup_group: str|None=None
    def __post_init__(self):
        if not _ID.fullmatch(self.canonical_task_id): raise ValueError("invalid canonical_task_id")
        for name in ("source_benchmark","source_benchmark_version","source_task_id","upstream_repository","upstream_commit","prompt","adapter_id","adapter_version"):
            if not str(getattr(self,name)).strip(): raise ValueError(f"{name} must not be empty")
        if len(set(self.required_apps)) != len(self.required_apps): raise ValueError("duplicate required app")
    def identity_payload(self):
        return {"source_benchmark":self.source_benchmark,"source_benchmark_version":self.source_benchmark_version,"source_task_id":self.source_task_id,"upstream_repository":self.upstream_repository,"upstream_commit":self.upstream_commit,"adapter_id":self.adapter_id,"adapter_version":self.adapter_version}
    @property
    def fingerprint(self): return hashlib.sha256(_stable(self.identity_payload())).hexdigest()
    def provenance(self):
        return {**self.identity_payload(),"canonical_task_id":self.canonical_task_id,"source_license":self.source_license,"source_metadata":self.source_metadata,"evaluator_metadata":self.evaluator_metadata,"task_fingerprint":self.fingerprint}

@dataclass(frozen=True, slots=True)
class TeacherCampaign:
    expected_model: str; teacher_configuration: dict[str,Any]; runner_commit: str
    def __post_init__(self):
        if not self.expected_model.strip() or not self.runner_commit.strip(): raise ValueError("campaign identity is incomplete")
    @property
    def campaign_id(self): return hashlib.sha256(_stable({"expected_model":self.expected_model,"teacher_configuration":self.teacher_configuration,"runner_commit":self.runner_commit})).hexdigest()

def canonical_id(source_benchmark:str, source_task_id:str, upstream_repository:str, origin:str|None=None)->str:
    key=(origin or f"{upstream_repository}:{source_task_id}").strip().lower()
    digest=hashlib.sha256(key.encode()).hexdigest()[:24]
    prefix=re.sub(r"[^a-z0-9._:-]+","-",source_benchmark.lower()).strip("-.") or "task"
    return f"{prefix}:{digest}"

def run_task_id(canonical_task_id:str,campaign_id:str)->str:
    return f"sb:{campaign_id[:16]}:{hashlib.sha256(canonical_task_id.encode()).hexdigest()[:32]}"
