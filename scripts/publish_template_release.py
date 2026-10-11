#!/usr/bin/env python3
"""One-time permanent publication. Never invoked by deployment/benchmark targets."""
from __future__ import annotations

import argparse
import fcntl
import http.client
import importlib.util
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shared"))
sys.path.insert(0, str(ROOT / "apps/workstation-broker/src"))
from gpt_trace_transport.template_release import (
    API, REPOSITORY, GitHub, asset_digest, atomic_json, compatibility, digest,
    package, release_tag, safe, validate_publication, validate_release,
)

BASE = Path("/var/lib/libvirt/images/gpt-trace/kali-base.qcow2")


def load_builder():
    spec = importlib.util.spec_from_file_location("permanent_template_build", ROOT / "scripts/template_publication_build.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def upload(client, release_id, path):
    """Stream bytes directly, bound to uploads.github.com, without a shell/token log."""
    path = Path(path)
    url = "/repos/" + REPOSITORY + "/releases/" + str(release_id) + "/assets?name=" + urllib.parse.quote(path.name, safe="")
    connection = http.client.HTTPSConnection("uploads.github.com", timeout=120)
    try:
        connection.putrequest("POST", url)
        connection.putheader("Authorization", "Bearer " + client.token)
        connection.putheader("Accept", "application/vnd.github+json")
        connection.putheader("X-GitHub-Api-Version", "2026-03-10")
        connection.putheader("Content-Type", "application/octet-stream")
        connection.putheader("Content-Length", str(path.stat().st_size))
        connection.endheaders()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1048576), b""): connection.send(chunk)
        response = connection.getresponse()
        raw = response.read(1024 ** 2 + 1)
        if response.status != 201 or len(raw) > 1024 ** 2:
            raise RuntimeError("GitHub publication upload failed, HTTP " + str(response.status))
        record = json.loads(raw)
        if asset_digest(record) != digest(path) or record["size"] != path.stat().st_size or record["name"] != path.name:
            raise ValueError("GitHub did not confirm the exact uploaded bytes")
        return record
    finally:
        connection.close()


def publish(args):
    if os.geteuid() != 0:
        raise RuntimeError("publication requires root on the isolated KVM publication host")
    credential = os.environ.get("TEMPLATE_PUBLISH_TOKEN")
    if not credential:
        raise RuntimeError("TEMPLATE_PUBLISH_TOKEN is required for explicit publication")
    client = GitHub(credential)
    # Enable/check the documented repository setting before any guest build.
    # This needs the publication credential's repository Administration write
    # permission; deployments use read-only access or public anonymous access.
    try:
        setting = client.json("/immutable-releases")
    except urllib.error.HTTPError as exc:
        if exc.code != 404: raise
        client.json("/immutable-releases", method="PUT")
        setting = client.json("/immutable-releases")
    if not isinstance(setting, dict) or setting.get("enabled") is not True:
        raise RuntimeError("GitHub immutable releases could not be enabled/verified")
    builder = load_builder()
    golden = builder.load_module("publication_golden", ROOT / "infra/workstation/image/build.py")
    golden.verify()
    expected = compatibility(BASE)
    tag = release_tag(expected)
    work = BASE.parent / "template-publications" / tag
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    safe(work, directory=True)
    descriptor = os.open(work / "publication.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            release = client.json("/releases/tags/" + urllib.parse.quote(tag, safe=""))
        except urllib.error.HTTPError as exc:
            if exc.code != 404: raise
            release = None
        journal = work / "publication-state.json"
        previous = json.loads(journal.read_bytes()) if journal.exists() else None
        if release is not None and release.get("draft") is False:
            live = client.release(tag)
            assets = validate_release(live, tag)
            import tempfile
            with tempfile.TemporaryFile() as stream:
                client.download(assets["publication.json"], stream)
                stream.seek(0)
                publication = json.load(stream)
            validate_publication(publication, expected, assets, source_commit=live["source_commit"])
            print("Already published immutably; no build: " + tag)
            return
        if previous is None:
            if release is not None:
                raise RuntimeError("existing draft has no local build journal; refusing an unproven rebuild")
            commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
            if re.fullmatch(r"[0-9a-f]{40}", commit) is None: raise ValueError("invalid publication source commit")
            dirty = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT, text=True)
            if dirty.strip(): raise RuntimeError("publication requires a committed, clean source tree")
            release = client.json("/releases", method="POST", body={"tag_name": tag,
                "target_commitish": commit, "name": tag, "draft": True, "prerelease": False,
                "body": "Immutable SWE-Gym Lite v2 templates, exact native replay proofs and SHA-256 manifest."})
            previous = {"schema": 1, "release_id": release["id"], "source_commit": commit,
                        "tag": tag, "compatibility": expected, "phase": "created", "generation": None}
            atomic_json(journal, previous, 0o600)
        if previous.get("tag") != tag or previous.get("compatibility") != expected or release is None or release["id"] != previous.get("release_id") or release.get("draft") is not True:
            raise RuntimeError("publication journal/draft identity mismatch")
        builder.TEMPLATES = work / "build-output"
        if previous["phase"] == "created":
            # Write-ahead marker prevents every retry from initiating another
            # build for the same immutable compatibility tag.
            previous["phase"] = "building"
            atomic_json(journal, previous, 0o600)
            final = builder.build(SimpleNamespace(publication=True, virtual_gib=args.virtual_gib,
                free_space_gib=args.free_space_gib, build_timeout_hours=args.build_timeout_hours))
            previous.update(phase="built", generation=final.name)
            atomic_json(journal, previous, 0o600)
        elif previous["phase"] == "building":
            # Recover only a generation the original build finished and sealed.
            # Failed/partial stages remain diagnostic; they are never rebuilt.
            completed = builder.TEMPLATES / "swe-gym-lite/generations"
            candidates = [p for p in completed.iterdir() if re.fullmatch(r"[0-9a-f]{64}", p.name)] if completed.exists() else []
            if len(candidates) != 1:
                raise RuntimeError("previous build did not finish; preserved diagnostics; refusing a second build for this tag")
            previous.update(phase="built", generation=candidates[0].name)
            atomic_json(journal, previous, 0o600)
        final = builder.TEMPLATES / "swe-gym-lite/generations" / previous["generation"]
        output = work / "assets"
        if not output.exists():
            publication = package(final, output, expected, previous["source_commit"])
        else:
            # A partial packaging run is never accepted as complete.
            publication = json.loads((output / "publication.json").read_bytes())
            if publication["compatibility"] != expected or publication["generation"] != previous["generation"]:
                raise ValueError("publication package conflicts with original build")
        live = client.release(tag)
        uploaded = {row["name"]: row for row in live["assets"]}
        for path in sorted(output.iterdir()):
            safe(path)
            old = uploaded.get(path.name)
            if old is not None:
                if old["size"] != path.stat().st_size or asset_digest(old) != digest(path):
                    raise ValueError("an existing draft asset differs; it will never be replaced")
            else:
                uploaded[path.name] = upload(client, release["id"], path)
        validate_publication(publication, expected, uploaded)
        previous["phase"] = "uploaded"
        atomic_json(journal, previous, 0o600)
        client.json("/releases/" + str(release["id"]), method="PATCH", body={"draft": False, "make_latest": "false"})
        published = client.release(tag)
        assets = validate_release(published, tag)
        validate_publication(publication, expected, assets, source_commit=published["source_commit"])
        previous["phase"] = "published"
        atomic_json(journal, previous, 0o600)
        print("Published and verified immutable release: " + tag)
    finally:
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--virtual-gib", type=int, default=512)
    parser.add_argument("--free-space-gib", type=int, default=64)
    parser.add_argument("--build-timeout-hours", type=int, default=96)
    args = parser.parse_args()
    if not 128 <= args.virtual_gib <= 2048 or args.free_space_gib < 32 or not 1 <= args.build_timeout_hours <= 336:
        parser.error("invalid build capacity, reserve or deadline")
    publish(args)


if __name__ == "__main__":
    try: main()
    except (OSError, ValueError, RuntimeError, urllib.error.HTTPError) as exc:
        print("template publication failed: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
