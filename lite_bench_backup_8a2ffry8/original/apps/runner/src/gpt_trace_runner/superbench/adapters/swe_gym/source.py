"""Pinned public Lite source. Campaign reads are entirely offline."""
from __future__ import annotations

import hashlib
import json
import os
import types
import urllib.request
from collections import Counter
from pathlib import Path

from .harness import ROOT, PINS, load

COUNTS = {"getmoto/moto": 59, "python/mypy": 40, "iterative/dvc": 36,
          "Project-MONAI/MONAI": 27, "pydantic/pydantic": 20, "dask/dask": 14,
          "conan-io/conan": 12, "facebookresearch/hydra": 11,
          "pandas-dev/pandas": 5, "modin-project/modin": 5, "bokeh/bokeh": 1}
PARQUET = "train-00000-of-00001.parquet"


def stable(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def contract():
    path = ROOT / "contract.json"
    if digest(path) != PINS["contract_sha256"]:
        raise RuntimeError("SWE-Gym Lite recipe contract changed")
    data = json.loads(path.read_text())
    if len(data["tasks"]) != 230 or len(data["environments"]) != 25:
        raise RuntimeError("SWE-Gym Lite task/environment contract changed")
    if Counter(item["repo"] for item in data["tasks"].values()) != COUNTS:
        raise RuntimeError("SWE-Gym Lite repository distribution changed")
    return data


def harness(data=None):
    data = contract() if data is None else data
    def get(url):
        # The pinned upstream function still chooses paths at exact base_commit.
        # Every HTTP 404 used by its path search is also recorded explicitly.
        if url not in data["snapshots"]:
            raise RuntimeError(f"unmapped pinned source URL: {url}")
        return types.SimpleNamespace(**data["snapshots"][url])
    return load(get)


def validate_rows(rows):
    data = contract()
    if len(rows) != 230 or Counter(row["repo"] for row in rows) != COUNTS:
        raise RuntimeError("expected exactly 230 SWE-Gym Lite tasks across 11 repositories")
    if len({row["instance_id"] for row in rows}) != 230:
        raise RuntimeError("duplicate Lite instance IDs")
    official = harness(data)
    seen = set()
    for row in rows:
        item = data["tasks"].get(row["instance_id"])
        if item is None or any(row[key] != item[key] for key in ("repo", "base_commit", "version")):
            raise RuntimeError("unmapped task or Lite source contract drift")
        if "environment_setup_commit" in row and row["environment_setup_commit"] != row["base_commit"]:
            raise RuntimeError("Lite environment source must be the exact task base commit")
        specs = official.constants.MAP_REPO_VERSION_TO_SPECS[row["repo"].lower()][row["version"]]
        repo_script = official.test_spec.make_repo_script_list(
            specs, row["repo"].lower(), "/testbed", row["base_commit"], "testbed")
        if repo_script != item["repo_script_list"]:
            raise RuntimeError("official SWE-Gym repository setup drift")
        original = official.test_spec.make_env_script_list(row, specs, "testbed")
        env_hash = hashlib.sha256(str(original).encode("utf-8")).hexdigest()[:22]
        if env_hash != item["env_hash"] or original != data["environments"][env_hash]["original_script"]:
            raise RuntimeError("official SWE-Gym environment hash drift")
        stored = official.test_spec.make_env_script_list(row, specs, data["environments"][env_hash]["stored_name"])
        if stored != data["environments"][env_hash]["stored_script"]:
            raise RuntimeError("stored environment transformation drift")
        for key in ("FAIL_TO_PASS", "PASS_TO_PASS"):
            values = json.loads(row[key]) if isinstance(row[key], str) else row[key]
            if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
                raise RuntimeError("invalid evaluator-side oracle data")
        if not row["FAIL_TO_PASS"] or not row["test_patch"] or not row["problem_statement"].strip():
            raise RuntimeError("incomplete Lite task")
        seen.add(env_hash)
    if len(seen) != 25:
        raise RuntimeError("expected exactly 25 official Lite environment hashes")
    return data


def read_rows(root):
    import pyarrow.parquet as pq
    path = Path(root) / PARQUET
    if not path.is_file() or path.is_symlink() or digest(path) != PINS["parquet_sha256"]:
        raise RuntimeError("missing/mutated pinned Lite parquet; run make superbench-fetch ADAPTER=swe-gym-lite")
    rows = pq.read_table(path).to_pylist()
    validate_rows(rows)
    return rows


def fetch(root):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    target = root / PARQUET
    if target.exists():
        read_rows(root)
        return
    url = ("https://huggingface.co/datasets/SWE-Gym/SWE-Gym-Lite/resolve/"
           + PINS["dataset_revision"] + "/data/" + PARQUET)
    partial = target.with_suffix(".part")
    with urllib.request.urlopen(url, timeout=120) as response, partial.open("wb") as output:
        while chunk := response.read(1024 * 1024):
            output.write(chunk)
        output.flush()
        os.fsync(output.fileno())
    if digest(partial) != PINS["parquet_sha256"]:
        raise RuntimeError("public Lite parquet does not match the pinned SHA256")
    os.replace(partial, target)
    fd = os.open(root, os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)
    read_rows(root)


def source_fingerprint():
    return hashlib.sha256(stable(PINS)).hexdigest()


def export_inputs(destination, root):
    """Only safe recipes/source snapshots leave the evaluator-side source cache."""
    fetch(root)
    data = validate_rows(read_rows(root))
    safe = {"pins": PINS, "source_fingerprint": source_fingerprint(),
            "tasks": data["tasks"], "environments": data["environments"],
            "snapshots": data["snapshots"]}
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "inputs.json").write_bytes(stable(safe))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--export", required=True, type=Path)
    parser.add_argument("--source-root", type=Path, default=Path(os.environ.get(
        "GPT_TRACE_SUPERBENCH_SOURCE_ROOT", "/data/state/superbench/sources")) / "swe-gym-lite")
    args = parser.parse_args()
    export_inputs(args.export, args.source_root)
