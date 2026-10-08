"""Host-owned, immutable template generations. No task-supplied paths."""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}/[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
SHA = re.compile(r"[a-f0-9]{64}\Z")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def trusted(path: Path, root: Path) -> Path:
    if not path.is_absolute() or not path.is_relative_to(root) or ".." in path.parts:
        raise ValueError("template path escapes trusted root")
    current = path
    while True:
        info = current.lstat()
        if current.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError(f"untrusted template path: {current}")
        if current == root:
            break
        current = current.parent
    return path


def backing(info: dict, image: Path) -> Path | None:
    value = info.get("full-backing-filename") or info.get("backing-filename")
    if not value:
        return None
    path = Path(value)
    return (path if path.is_absolute() else image.parent / path).resolve()


class TemplateRegistry:
    def __init__(self, root: Path, base: Path, image_info):
        self.root = root.absolute()
        self.base = base.absolute()
        self.image_info = image_info
        self._digests = {}

    def immutable_sha256(self, path):
        stat = path.stat()
        if path.is_symlink() or not path.is_file() or stat.st_mode & 0o222:
            raise ValueError("immutable backing image became mutable or missing")
        key = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
        old = self._digests.get(path)
        if old is None or old[0] != key:
            old = (key, sha256(path))
            self._digests[path] = old
        return old[1]

    def select(self, template_id: str, generation: str | None = None) -> dict:
        if not isinstance(template_id, str) or ID.fullmatch(template_id) is None:
            raise ValueError("invalid workstation template ID")
        namespace, _ = template_id.split("/")
        if generation is None:
            registry = self.root / namespace / "registry.json"
            trusted(registry, self.root)
            payload = json.loads(registry.read_text())
            if payload.get("schema_version") != 1:
                raise ValueError("unsupported template registry schema")
            generation = payload.get("generation")
        if not isinstance(generation, str) or SHA.fullmatch(generation) is None:
            raise ValueError("invalid template generation")
        manifest_path = self.root / namespace / "generations" / generation / "manifest.json"
        trusted(manifest_path, self.root)
        manifest = json.loads(manifest_path.read_text())
        if manifest.get("schema_version") != 1 or manifest.get("generation") != generation:
            raise ValueError("template generation/schema mismatch")
        source = manifest.get("source_fingerprint")
        if not isinstance(source, str) or SHA.fullmatch(source) is None:
            raise ValueError("invalid template source fingerprint")
        row = manifest.get("templates", {}).get(template_id)
        if not isinstance(row, dict) or not isinstance(row.get("chain"), list) or len(row["chain"]) < 2:
            raise ValueError("unknown/incomplete workstation template")
        chain = row["chain"]
        paths = []
        for index, record in enumerate(chain):
            raw = record.get("path")
            digest = record.get("sha256")
            if not isinstance(raw, str) or not isinstance(digest, str) or SHA.fullmatch(digest) is None:
                raise ValueError("invalid template image record")
            path = Path(raw)
            if not path.is_absolute():
                if ".." in path.parts:
                    raise ValueError("template traversal")
                path = manifest_path.parent / path
            if index == len(chain) - 1:
                if path != self.base:
                    raise ValueError("template chain does not end in the installed Kali golden")
                if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o222:
                    raise ValueError("Kali golden is mutable or missing")
            else:
                trusted(path, self.root)
                if not path.is_relative_to(manifest_path.parent) or not path.is_file() or path.stat().st_mode & 0o222:
                    raise ValueError("template image is mutable, missing, or outside generation")
            if self.immutable_sha256(path) != digest:
                raise ValueError("template image digest mismatch")
            paths.append(path)
        if len(set(paths)) != len(paths):
            raise ValueError("cyclic template chain")
        for index, path in enumerate(paths):
            info = self.image_info(path)
            expected = paths[index + 1].resolve() if index + 1 < len(paths) else None
            if info.get("format") != "qcow2" or backing(info, path) != expected:
                raise ValueError("template backing chain mismatch")
        return {"template_id": template_id, "backing_path": str(paths[0]),
                "backing_sha256": chain[0]["sha256"], "template_generation": generation,
                "template_source_fingerprint": source}

    def verify_record(self, record: dict) -> dict:
        expected = self.select(record.get("template_id"), record.get("template_generation"))
        if any(record.get(key) != value for key, value in expected.items()):
            raise ValueError("attempt template generation/backing identity changed")
        return expected
