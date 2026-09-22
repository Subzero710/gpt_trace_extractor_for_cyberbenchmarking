from __future__ import annotations
from dataclasses import dataclass
from enum import StrEnum

class ObjectState(StrEnum):
    CREATING = "CREATING"
    READY = "READY"
    DELIVERED = "DELIVERED"
    ACKED = "ACKED"
    EXPIRED = "EXPIRED"

@dataclass(frozen=True, slots=True)
class Identity:
    task_id: str
    attempt: int
    app: str

@dataclass(frozen=True, slots=True)
class Limits:
    max_file_bytes: int
    max_total_bytes: int
    max_objects: int
    max_concurrent_uploads: int
    max_concurrent_downloads: int
    ttl_seconds: int
    max_filename_bytes: int
