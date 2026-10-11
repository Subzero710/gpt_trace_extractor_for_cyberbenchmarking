"""Permanent SWE-Gym Lite release installation; never builds or boots a guest.

Trust starts at GitHub's HTTPS API, an immutable release and its asset digests.
The root-owned receipt binds every installed byte to that release. Use is offline.
"""
from __future__ import annotations

import fcntl
import gzip
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path, PurePosixPath

REPOSITORY = "Subzero710/gpt_trace_extractor_for_cyberbenchmarking"
API = "https://api.github.com/repos/" + REPOSITORY
SHA = re.compile(r"[0-9a-f]{64}\Z")
ASSET = re.compile(r"file-[0-9]{6}-[0-9]{6}\.gzpart\Z")
SECURITY = {"task_scoped_sources": 1, "broker_streaming": 1,
            "isolated_evaluator": 1, "resolved_os_artifacts": 1}
ROOT = Path(__file__).resolve().parents[2]
PINS = Path("apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/pins.json")
RUNTIME = PINS.parent
MAX_MANIFEST = 32 * 1024 * 1024
PART_BYTES = 2 ** 31 - 1024 ** 2  # Strictly below GitHub's 2 GiB asset limit.
MAX_ASSETS = 1000


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            value.update(chunk)
    return value.hexdigest()


def relative(name):
    if not isinstance(name, str) or not name or "\\" in name or "\0" in name:
        raise ValueError("invalid release file path")
    path = PurePosixPath(name)
    if path.is_absolute() or any(x in {"", ".", ".."} for x in path.parts) or path.as_posix() != name:
        raise ValueError("release path traversal/noncanonical path")
    return path


def safe(path, *, immutable=False, directory=False):
    path = Path(path).absolute()
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValueError("symlink in template release path")
    info = path.lstat()
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("template release must be root-owned and protected")
    if directory and not stat.S_ISDIR(info.st_mode):
        raise ValueError("release directory is missing")
    if not directory and not stat.S_ISREG(info.st_mode):
        raise ValueError("release file is not regular")
    if immutable and info.st_mode & 0o222:
        raise ValueError("release file became mutable")
    return path


def atomic_json(path, payload, mode=0o444):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("unsafe publication destination")
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), mode)
            handle.write(canonical(payload) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def sync_directory(path):
    descriptor = os.open(path, os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def compatibility(base, source_root=ROOT, *, hasher=digest):
    base, source_root = Path(base), Path(source_root)
    pins = json.loads((source_root / PINS).read_bytes())
    if pins.get("schema_version") != 2 or pins.get("recipe_version") != 2:
        raise ValueError("unsupported pinned Lite recipe")
    if digest(source_root / RUNTIME / "contract.json") != pins["contract_sha256"]:
        raise ValueError("pinned Lite source contract differs")
    provenance = json.loads(base.with_suffix(".provenance.json").read_bytes())
    sha = hasher(base)
    if provenance.get("base_sha256") != sha:
        raise ValueError("installed Kali golden provenance differs")
    return {"architecture": "x86_64", "schema_version": 2, "recipe_version": 2,
        "pins": pins, "source_fingerprint": hashlib.sha256(canonical(pins)).hexdigest(),
        "security": SECURITY, "golden_sha256": sha,
        "runtime_sources": {name: digest(source_root / RUNTIME / name)
            for name in ("guest_runtime.py", "task_sources.py", "os_packages.py")}}


def release_tag(expected):
    return "swe-gym-lite-v2-" + hashlib.sha256(canonical(expected)).hexdigest()


class UnpublishedRelease(RuntimeError):
    """A missing release disables Lite; it does not invalidate GAIA's golden."""


class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        url = urllib.parse.urlsplit(newurl)
        host = url.hostname or ""
        if url.scheme != "https" or url.username or url.password or not (
                host in {"github.com", "api.github.com"} or host.endswith(".githubusercontent.com")):
            raise ValueError("untrusted release asset redirect")
        result = super().redirect_request(request, fp, code, message, headers, newurl)
        if result is not None:
            result.remove_header("Authorization")
        return result


class GitHub:
    def __init__(self, token=None):
        self.token = token
        # A deployment proxy cannot receive publication credentials or replace
        # the download origin. TLS uses the platform's verified CA store.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirect())

    def request(self, url, *, accept="application/vnd.github+json", method="GET", body=None):
        if not url.startswith(API + "/"):
            raise ValueError("request outside the exact publication repository")
        headers = {"Accept": accept, "User-Agent": "gpt-trace-template-release/1",
                   "X-GitHub-Api-Version": "2026-03-10"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        if body is not None:
            body = canonical(body)
            headers["Content-Type"] = "application/json"
        return self.opener.open(urllib.request.Request(url, data=body, headers=headers, method=method), timeout=120)

    def json(self, suffix, *, method="GET", body=None):
        with self.request(API + suffix, method=method, body=body) as response:
            raw = response.read(MAX_MANIFEST + 1)
            if len(raw) > MAX_MANIFEST:
                raise ValueError("GitHub response exceeds publication metadata limit")
            return json.loads(raw) if raw else None

    def release(self, tag):
        try:
            row = self.json("/releases/tags/" + urllib.parse.quote(tag, safe=""))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise UnpublishedRelease("no published Lite release for this exact recipe/golden; "
                    "run the publication workflow once; deployment never rebuilds templates") from None
            raise RuntimeError("GitHub release lookup failed with HTTP " + str(exc.code)) from None
        # The release endpoint may inline only a page of assets. Enumerate all
        # pages, otherwise the 460+ task artifacts cannot be checked completely.
        rows = []
        for page in range(1, 1001):
            values = self.json(f'/releases/{row["id"]}/assets?per_page=100&page={page}')
            if not isinstance(values, list): raise ValueError("invalid GitHub assets page")
            rows.extend(values)
            if len(values) < 100: break
        else:
            raise ValueError("release asset pagination did not terminate")
        source_commit = row.get("target_commitish")
        if row.get("draft") is False:
            ref = self.json("/git/ref/tags/" + urllib.parse.quote(tag, safe=""))["object"]
            for _ in range(10):
                if ref.get("type") == "commit": break
                if ref.get("type") != "tag" or not re.fullmatch(r"[0-9a-f]{40}", str(ref.get("sha"))):
                    raise ValueError("invalid immutable release tag object")
                ref = self.json("/git/tags/" + ref["sha"])["object"]
            else: raise ValueError("immutable tag nesting exceeds limit")
            source_commit = ref.get("sha")
        if re.fullmatch(r"[0-9a-f]{40}", str(source_commit)) is None:
            raise ValueError("release has no exact source commit")
        return {**row, "assets": rows, "source_commit": source_commit}

    def download(self, asset, output):
        sha = asset_digest(asset)
        size, done, value = asset["size"], 0, hashlib.sha256()
        with self.request(API + "/releases/assets/" + str(asset["id"]),
                          accept="application/octet-stream") as response:
            while chunk := response.read(1048576):
                done += len(chunk)
                if done > size:
                    raise ValueError("release asset exceeded its immutable size")
                output.write(chunk)
                value.update(chunk)
        if done != size or value.hexdigest() != sha:
            raise ValueError("downloaded release asset size/SHA-256 mismatch")


def asset_digest(asset):
    value = asset.get("digest") if isinstance(asset, dict) else None
    if not isinstance(value, str) or not value.startswith("sha256:") or SHA.fullmatch(value[7:]) is None:
        raise ValueError("release asset has no authentic SHA-256 digest")
    if type(asset.get("id")) is not int or asset["id"] < 1 or type(asset.get("size")) is not int or not 0 <= asset["size"] < 2 ** 31:
        raise ValueError("release asset identity/size is invalid")
    if asset.get("state") != "uploaded":
        raise ValueError("release asset is not completely uploaded")
    return value[7:]


def validate_release(release, tag):
    if not isinstance(release, dict) or release.get("immutable") is not True or release.get("draft") is not False:
        raise ValueError("Lite release is unpublished or mutable")
    if release.get("tag_name") != tag or type(release.get("id")) is not int or release["id"] < 1:
        raise ValueError("published Lite release identity differs")
    assets = release.get("assets")
    if not isinstance(assets, list) or not 1 <= len(assets) <= MAX_ASSETS:
        raise ValueError("missing/excessive published Lite assets")
    result = {}
    for row in assets:
        name = row.get("name")
        if not isinstance(name, str) or name in result:
            raise ValueError("ambiguous published asset name")
        asset_digest(row)
        result[name] = row
    if "publication.json" not in result or result["publication.json"]["size"] > MAX_MANIFEST:
        raise ValueError("immutable publication manifest is absent or oversized")
    return result


def validate_publication(value, expected, assets, *, source_commit=None):
    if not isinstance(value, dict) or set(value) != {"schema", "repository", "tag", "source_commit", "compatibility", "generation", "files"}:
        raise ValueError("invalid publication manifest fields")
    if value["schema"] != 1 or value["repository"] != REPOSITORY or value["tag"] != release_tag(expected) or value["compatibility"] != expected:
        raise ValueError("published template compatibility/provenance mismatch")
    if not re.fullmatch(r"[0-9a-f]{40}", str(value["source_commit"])) or SHA.fullmatch(str(value["generation"])) is None:
        raise ValueError("publication has no immutable source/generation identity")
    if source_commit is not None and value["source_commit"] != source_commit:
        raise ValueError("publication source commit differs from the immutable Git tag")
    files = value["files"]
    if not isinstance(files, dict) or not {"manifest.json", "resolved-inputs.json", "common.qcow2"} <= set(files) or len(files) > 10000:
        raise ValueError("publication lacks required artifacts")
    names, seen_paths = {"publication.json"}, set()
    for name, record in files.items():
        path = relative(name)
        if name in {"release-receipt.json", "publication.json"} or any(str(parent) in files for parent in path.parents if str(parent) != "."):
            raise ValueError("release file/directory collision")
        if not isinstance(record, dict) or set(record) != {"size", "sha256", "parts"} or type(record["size"]) is not int or not 0 <= record["size"] <= 2 ** 43 or SHA.fullmatch(str(record["sha256"])) is None:
            raise ValueError("invalid published file integrity record")
        parts = record["parts"]
        if not isinstance(parts, list) or not parts:
            raise ValueError("published file has no download parts")
        for part in parts:
            if not isinstance(part, dict) or set(part) != {"name", "sha256", "size"}:
                raise ValueError("invalid published part")
            asset = assets.get(part["name"])
            if ASSET.fullmatch(str(part["name"])) is None or part["name"] in names or asset is None:
                raise ValueError("missing/duplicate published part")
            if part["sha256"] != asset_digest(asset) or type(part["size"]) is not int or part["size"] != asset["size"]:
                raise ValueError("published part differs from immutable GitHub asset digest")
            names.add(part["name"])
        seen_paths.add(name)
    if names != set(assets):
        raise ValueError("release has missing or unmanifested assets")
    return files


def verify_receipt(folder, manifest, *, expected=None, hasher=digest, complete=True):
    """Verify all bytes at installation/first selection; metadata on every use.

    Subsequent selections also verify each backing and each requested artifact
    against the authenticated manifest in TemplateRegistry. Unused task archives
    do not need to be walked repeatedly during unrelated tool calls.
    """
    folder = Path(folder)
    receipt_path = safe(folder / "release-receipt.json", immutable=True)
    receipt = json.loads(receipt_path.read_bytes())
    if not isinstance(receipt, dict) or set(receipt) != {"schema", "repository", "release_id", "immutable", "tag", "publication_sha256", "publication"}:
        raise ValueError("invalid installed publication receipt")
    publication = receipt["publication"]
    if receipt["schema"] != 1 or receipt["repository"] != REPOSITORY or receipt["immutable"] is not True or type(receipt["release_id"]) is not int or receipt["release_id"] < 1:
        raise ValueError("installed template lacks immutable release provenance")
    payload_path = safe(folder / "publication.json", immutable=True)
    if hasher(payload_path) != receipt["publication_sha256"] or json.loads(payload_path.read_bytes()) != publication:
        raise ValueError("installed publication manifest SHA-256 mismatch")
    if publication.get("repository") != REPOSITORY or receipt["tag"] != publication.get("tag") or receipt["tag"] != release_tag(publication["compatibility"]):
        raise ValueError("installed release tag/compatibility mismatch")
    if publication.get("generation") != manifest.get("generation"):
        raise ValueError("installed release generation differs")
    if expected is not None and publication["compatibility"] != expected:
        raise ValueError("installed template is incompatible with current source/golden")
    files = publication.get("files")
    if not isinstance(files, dict):
        raise ValueError("installed release file manifest is missing")
    if not complete:
        for name in ("manifest.json", "resolved-inputs.json", "audit/offline-setups.json"):
            row = files.get(name)
            path = safe(folder / name, immutable=True)
            if not isinstance(row, dict) or path.stat().st_size != row["size"] or hasher(path) != row["sha256"]:
                raise ValueError("installed release metadata size/SHA-256 mismatch: " + name)
        return publication
    actual = set()
    for path in folder.rglob("*"):
        if path.is_symlink(): raise ValueError("symlink in installed immutable generation")
        if path.is_dir():
            safe(path, directory=True)
        elif path.is_file():
            actual.add(path.relative_to(folder).as_posix())
        else:
            raise ValueError("special file in installed generation")
    if actual != set(files) | {"publication.json", "release-receipt.json"}:
        raise ValueError("installed release file population differs")
    for name, row in files.items():
        relative(name)
        path = safe(folder / name, immutable=True)
        if path.stat().st_size != row["size"] or hasher(path) != row["sha256"]:
            raise ValueError("installed release artifact size/SHA-256 mismatch: " + name)
    return publication


def verify_manifest(folder, expected):
    """Check resolved identities and complete recipe coverage before activation."""
    folder = Path(folder)
    manifest = json.loads((folder / "manifest.json").read_bytes())
    resolved_path = folder / "resolved-inputs.json"
    resolved = json.loads(resolved_path.read_bytes())
    generation = hashlib.sha256(canonical(resolved)).hexdigest()
    if manifest.get("generation") != generation or manifest.get("resolved_inputs_sha256") != digest(resolved_path):
        raise ValueError("resolved template generation/input SHA-256 mismatch")
    for key in ("schema_version", "recipe_version", "pins", "source_fingerprint", "security", "templates", "artifacts", "task_artifacts", "publication_validation"):
        if manifest.get(key) != resolved.get(key): raise ValueError("manifest/resolved input mismatch: " + key)
    for key in ("schema_version", "recipe_version", "pins", "source_fingerprint", "security"):
        if manifest.get(key) != expected[key]: raise ValueError("template recipe/security compatibility mismatch: " + key)
    if resolved.get("golden", {}).get("sha256") != expected["golden_sha256"]:
        raise ValueError("template uses another Kali golden")
    for name, sha in expected["runtime_sources"].items():
        source_path = (RUNTIME / name).as_posix()
        if resolved.get("builder_sources", {}).get(source_path) != sha:
            raise ValueError("template guest source differs from installed native harness")
    if manifest.get("invariants") != {"tasks": 230, "repos": 11, "env_hashes": 25, "unmapped_tasks": 0, "missing_base_commits": 0} or len(manifest.get("templates", {})) != 11 or len(manifest.get("task_artifacts", {})) != 230 or len(manifest.get("env_mapping", {})) != 25:
        raise ValueError("published Lite coverage changed")
    proof = json.loads((folder / "audit/offline-setups.json").read_bytes())
    if digest(folder / "audit/offline-setups.json") != resolved.get("offline_setups_sha256") or set(proof) != set(manifest["task_artifacts"]) or any(not isinstance(x, dict) or x.get("offline") is not True for x in proof.values()):
        raise ValueError("published fresh isolated replay proof differs")
    contract = json.loads((ROOT / RUNTIME / "contract.json").read_bytes())
    if digest(ROOT / RUNTIME / "contract.json") != expected["pins"]["contract_sha256"]:
        raise ValueError("installed native Lite contract differs")
    if set(manifest["task_artifacts"]) != set(contract["tasks"]) or manifest["env_mapping"] != {
            key: row["stored_name"] for key, row in contract["environments"].items()}:
        raise ValueError("published task/environment mapping differs from pinned source")
    clean = {"builder_mirrors": 0, "repo_mirrors": 0, "task_sources": 0, "checkouts": 0}
    publications = manifest["publication_validation"]
    repos = {row["repo"] for row in contract["tasks"].values()}
    if not isinstance(publications, dict) or set(publications) != repos | {"common"} or any(
            row != clean for row in publications.values()):
        raise ValueError("permanent template source-isolation proof differs")
    for logical, task in contract["tasks"].items():
        if proof[logical] != {"base_commit": task["base_commit"], "env_hash": task["env_hash"], "offline": True}:
            raise ValueError("published replay used a different task base/environment")
        mapping = manifest["task_artifacts"][logical]
        if mapping.get("template_id") != task["template_id"]:
            raise ValueError("published task/repository template mapping differs")
        for kind in ("task_source", "setup_cache"):
            artifact = manifest["artifacts"].get(mapping.get(kind), {})
            identity = {key: task[key] for key in ("instance_id", "repo", "base_commit")}
            if artifact.get("source_identity") != identity or artifact.get("kind") != kind:
                raise ValueError("published task artifact source provenance differs")
    return manifest


def seal(folder):
    for path in sorted(Path(folder).rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if path.is_symlink(): raise ValueError("symlink in staged release")
        path.chmod(0o555 if path.is_dir() else 0o444)
        if path.is_file():
            with path.open("rb") as handle: os.fsync(handle.fileno())
        else:
            sync_directory(path)
    Path(folder).chmod(0o555)
    sync_directory(folder)


def install(base, template_root, registry_factory, *, github=None, source_root=ROOT):
    """Download/install/activate once. Reuse validates locally without network."""
    if os.geteuid() != 0 or platform.machine() not in {"x86_64", "AMD64"}:
        raise RuntimeError("Lite installation requires root on the Acer x86_64 execution host")
    base, template_root = Path(base).absolute(), Path(template_root).absolute()
    safe(base, immutable=True)
    expected = compatibility(base, source_root)
    namespace = template_root / "swe-gym-lite"
    namespace.mkdir(mode=0o755, parents=True, exist_ok=True)
    safe(namespace, directory=True)
    lock_path = namespace / "install.lock"
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        registry_path = namespace / "registry.json"
        if registry_path.exists():
            safe(registry_path, immutable=True)
            selected = json.loads(registry_path.read_bytes())
            if selected.get("schema_version") != 2 or SHA.fullmatch(str(selected.get("generation"))) is None:
                raise ValueError("invalid existing template registry; refusing replacement")
            folder = namespace / "generations" / selected["generation"]
            manifest = verify_manifest(folder, expected)
            verify_receipt(folder, manifest, expected=expected)
            registry = registry_factory(template_root, base)
            for tid in manifest["templates"]:
                record = registry.select(tid, selected["generation"])
                for logical, mapping in manifest["task_artifacts"].items():
                    if mapping["template_id"] == tid: registry.task_scope(record, logical)
            return selected["generation"]
        github = github or GitHub(os.environ.get("GH_TOKEN"))
        tag = release_tag(expected)
        release = github.release(tag)
        assets = validate_release(release, tag)
        with tempfile.TemporaryFile() as stream:
            github.download(assets["publication.json"], stream)
            stream.seek(0)
            publication_raw = stream.read(MAX_MANIFEST + 1)
        if len(publication_raw) > MAX_MANIFEST: raise ValueError("oversized publication manifest")
        publication = json.loads(publication_raw)
        files = validate_publication(publication, expected, assets, source_commit=release["source_commit"])
        generations = namespace / "generations"
        generations.mkdir(mode=0o755, exist_ok=True)
        safe(generations, directory=True)
        final = generations / publication["generation"]
        if final.exists():
            # A crash after directory rename but before registry activation is
            # recoverable from exact verified bytes, with no replacement/rebuild.
            manifest = verify_manifest(final, expected)
            verified = verify_receipt(final, manifest, expected=expected)
            if verified != publication: raise ValueError("existing generation conflicts with release")
        else:
            stage = Path(tempfile.mkdtemp(prefix=".install-", dir=generations))
            try:
                if shutil.disk_usage(generations).free < 1024 ** 3:
                    raise RuntimeError("Acer SSD has less than 1 GiB safety margin")
                for name, row in files.items():
                    path = stage / name
                    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                    with tempfile.TemporaryFile(dir=generations) as compressed:
                        for part in row["parts"]:
                            github.download(assets[part["name"]], compressed)
                        compressed.seek(0)
                        sha, count = hashlib.sha256(), 0
                        with gzip.GzipFile(fileobj=compressed, mode="rb") as expanded, path.open("xb") as output:
                            while chunk := expanded.read(1048576):
                                count += len(chunk)
                                if count > row["size"]: raise ValueError("release decompression exceeded declared size")
                                sha.update(chunk)
                                # Preserve sparse QCOW2 holes without changing bytes.
                                if not chunk.strip(b"\0"): output.seek(len(chunk), os.SEEK_CUR)
                                else: output.write(chunk)
                                if shutil.disk_usage(generations).free < 1024 ** 3:
                                    raise RuntimeError("Acer SSD safety margin exhausted; no registry changed")
                            output.truncate(count)
                            output.flush()
                            os.fsync(output.fileno())
                        if count != row["size"] or sha.hexdigest() != row["sha256"]:
                            raise ValueError("expanded template file size/SHA-256 mismatch: " + name)
                (stage / "publication.json").write_bytes(publication_raw)
                atomic_json(stage / "release-receipt.json", {"schema": 1, "repository": REPOSITORY,
                    "release_id": release["id"], "immutable": True, "tag": tag,
                    "publication_sha256": asset_digest(assets["publication.json"]), "publication": publication})
                manifest = verify_manifest(stage, expected)
                if manifest["generation"] != publication["generation"]: raise ValueError("release generation mismatch")
                seal(stage)
                verify_receipt(stage, manifest, expected=expected)
                # A sealed directory needs a writable '..' entry for rename.
                stage.chmod(0o755)
                os.rename(stage, final)
                final.chmod(0o555)
                sync_directory(final)
                sync_directory(generations)
            except BaseException:
                # Never activate a failed install. Keep the stage for diagnosis
                # rather than risk deleting an unrelated/permanent generation.
                raise
        manifest = verify_manifest(final, expected)
        registry = registry_factory(template_root, base)
        for tid in manifest["templates"]:
            record = registry.select(tid, publication["generation"])
            for logical, mapping in manifest["task_artifacts"].items():
                if mapping["template_id"] == tid: registry.task_scope(record, logical)
        atomic_json(registry_path, {"schema_version": 2, "generation": publication["generation"]})
        return publication["generation"]
    finally:
        os.close(descriptor)


def _package(folder, destination, expected, source_commit):
    """Publication only: gzip/split real artifacts, calculating every digest."""
    folder, destination = Path(folder), Path(destination)
    manifest = verify_manifest(folder, expected)
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    files, asset_count = {}, 1  # Reserve publication.json before upload.
    for index, path in enumerate(sorted(folder.rglob("*"))):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError("unsafe publication build output")
        if path.is_dir(): continue
        safe(path, immutable=True)
        initial = path.stat()
        name = path.relative_to(folder).as_posix()
        relative(name)
        # Compression is bounded on disk; huge sparse disks never enter RAM.
        with tempfile.TemporaryFile(dir=destination) as stream:
            with gzip.GzipFile(fileobj=stream, mode="wb", filename="", mtime=0) as output, path.open("rb") as source:
                original_sha, original_size = hashlib.sha256(), 0
                while chunk := source.read(1048576):
                    original_sha.update(chunk)
                    original_size += len(chunk)
                    output.write(chunk)
            stream.seek(0)
            parts, number = [], 0
            while True:
                first = stream.read(1048576)
                if not first: break
                asset_count += 1
                if asset_count > MAX_ASSETS:
                    raise ValueError("sealed generation exceeds GitHub's 1000-asset release quota; no assets were uploaded")
                part_name = f"file-{index:06d}-{number:06d}.gzpart"
                target = destination / part_name
                size, sha = len(first), hashlib.sha256(first)
                with target.open("xb") as output:
                    output.write(first)
                    while size < PART_BYTES:
                        chunk = stream.read(min(1048576, PART_BYTES - size))
                        if not chunk: break
                        output.write(chunk)
                        sha.update(chunk)
                        size += len(chunk)
                    output.flush()
                    os.fsync(output.fileno())
                parts.append({"name": part_name, "sha256": sha.hexdigest(), "size": size})
                number += 1
        after = path.stat()
        if (initial.st_dev, initial.st_ino, initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or digest(path) != original_sha.hexdigest() or original_size != after.st_size:
            raise ValueError("immutable publication output changed during compression")
        files[name] = {"sha256": original_sha.hexdigest(), "size": original_size, "parts": parts}
    publication = {"schema": 1, "repository": REPOSITORY, "tag": release_tag(expected),
        "source_commit": source_commit, "compatibility": expected,
        "generation": manifest["generation"], "files": files}
    atomic_json(destination / "publication.json", publication)
    return publication


def package(folder, destination, expected, source_commit):
    destination = Path(destination)
    if destination.exists(): raise ValueError("publication package already exists")
    temporary = destination.with_name(".package-" + uuid.uuid4().hex)
    publication = _package(folder, temporary, expected, source_commit)
    os.rename(temporary, destination)
    sync_directory(destination.parent)
    return publication
