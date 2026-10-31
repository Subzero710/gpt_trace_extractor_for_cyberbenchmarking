"""Root-private, hash-checked persistent downloads shared with the build guest.

The 9p export is available only to the trusted golden constructor. It is never
attached to task/evaluator guests. A stage never owns or removes this cache.
"""
from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

SHA = re.compile(r"[0-9a-f]{64}\Z")
CACHE_TAG = "gpt_trace_golden_cache"
CACHE_MOUNT = Path("/run/gpt-trace-golden-cache")
BROWSER = Path("/opt/cloakbrowser/chromium")


def safe(path, *, directory=False):
    path = Path(path).absolute()
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValueError("symlink in golden artifact path: " + str(parent))
    info = path.lstat()
    if (info.st_uid != 0 or info.st_mode & 0o022
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))):
        raise ValueError("non-root/unprotected/nonregular golden artifact: " + str(path))
    return path


def mkdir(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("symlink in golden cache directory")
    if not path.exists():
        safe(path.parent, directory=True)
        path.mkdir(mode=0o700)
        sync(path.parent)
    safe(path, directory=True)
    if path.stat().st_mode & 0o077:
        raise ValueError("golden cache/stage directory must be private: " + str(path))
    return path


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def digest(path):
    path = safe(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("nonregular golden hash input")
        h = hashlib.sha256()
        with os.fdopen(fd, "rb", closefd=False) as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                h.update(chunk)
        after = os.fstat(fd)
        if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("golden artifact changed while hashing")
        return h.hexdigest()
    finally:
        os.close(fd)


def atomic_bytes(path, raw, mode=0o600):
    path = Path(path)
    safe(path.parent, directory=True)
    if path.is_symlink():
        raise ValueError("symlink in atomic golden destination")
    if path.exists():
        safe(path)
    fd, name = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), mode)
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
        sync(path.parent)
    finally:
        Path(name).unlink(missing_ok=True)


def atomic_json(path, value, mode=0o600):
    atomic_bytes(path, json.dumps(value, sort_keys=True, separators=(",", ":"),
                                allow_nan=False).encode() + b"\n", mode)


def read_json(path, *, private=False):
    path = safe(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or private and info.st_mode & 0o077):
            raise ValueError("unsafe golden JSON permissions: " + str(path))
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read()
        after = os.fstat(fd)
        if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("golden JSON changed during read")
    finally:
        os.close(fd)
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate golden JSON key: " + key)
            result[key] = value
        return result
    def constant(value):
        raise ValueError("nonfinite golden JSON number: " + value)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def inventory(folder):
    safe(folder, directory=True)
    result = {}
    for path in sorted(Path(folder).rglob("*")):
        safe(path, directory=path.is_dir())
        if path.is_file():
            result[path.relative_to(folder).as_posix()] = {
                "size": path.stat().st_size, "sha256": digest(path),
                "mode": stat.S_IMODE(path.stat().st_mode)}
    return result


def download(url, destination, expected=None, *, pass_fds=()):
    """One explicit origin; resumable .part and atomic verified promotion."""
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        safe(destination)
        if expected is not None and digest(destination) != expected:
            raise ValueError("cached download hash mismatch; preserved: " + str(destination))
        return destination
    part = destination.with_name(destination.name + ".part")
    fd = os.open(part, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1:
            raise ValueError("unsafe partial golden download")
        # The schema-1 curl cache used the process umask and can be 0644.
        # Its root-owned, non-writable bytes are retained while access tightens.
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    # A process can die after the final write but before curl returns or before
    # rename. The pinned hash proves a complete .part without another request.
    if expected is not None and digest(part) == expected:
        part.chmod(0o444)
        with part.open("rb") as stream:
            os.fsync(stream.fileno())
        os.replace(part, destination)
        sync(destination.parent)
        return destination
    subprocess.run(["curl", "--fail", "--location", "--retry", "5", "--retry-all-errors",
                    "--continue-at", "-", "--output", str(part), url], check=True, timeout=7200,
                   pass_fds=pass_fds)
    if expected is not None and digest(part) != expected:
        raise ValueError("download hash mismatch; partial preserved: " + str(part))
    with safe(part).open("rb") as stream:
        os.fsync(stream.fileno())
    part.chmod(0o444)
    os.replace(part, destination)
    sync(destination.parent)
    return destination


def browser_identity():
    from importlib.metadata import version
    from cloakbrowser.config import PLATFORM_CHROMIUM_VERSIONS, get_platform_tag
    # No requested version, update marker, license, local override or custom
    # mirror may change the package-defined free binary identity.
    forbidden = {key: os.environ[key] for key in (
        "CLOAKBROWSER_VERSION", "CLOAKBROWSER_DOWNLOAD_URL", "CLOAKBROWSER_SKIP_CHECKSUM",
        "CLOAKBROWSER_LICENSE_KEY", "CLOAKBROWSER_BINARY_PATH") if os.environ.get(key)}
    if forbidden:
        raise ValueError("browser acquisition environment overrides are forbidden: " + ",".join(sorted(forbidden)))
    tag = get_platform_tag()
    if tag not in PLATFORM_CHROMIUM_VERSIONS:
        raise ValueError("browser package has no explicit identity for target platform")
    return {"wrapper": version("cloakbrowser"), "platform": tag,
            "version": PLATFORM_CHROMIUM_VERSIONS[tag]}


def browser_archive(cache, identity, *, fetch=download):
    from cloakbrowser import config, download as upstream
    key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    namespace = mkdir(mkdir(cache / "browser") / key)
    identity_path = namespace / "identity.json"
    if identity_path.exists() or identity_path.is_symlink():
        if json.loads(safe(identity_path).read_bytes()) != identity:
            raise ValueError("browser cache acquisition identity differs")
    else:
        atomic_json(identity_path, identity, 0o444)
    url = config.get_download_url(identity["version"])
    origin = url.rsplit("/", 1)[0]
    manifest = fetch(origin + "/SHA256SUMS", namespace / "SHA256SUMS")
    signature = fetch(origin + "/SHA256SUMS.sig", namespace / "SHA256SUMS.sig")
    raw = safe(manifest).read_bytes()
    try:
        upstream._verify_signature(raw, safe(signature).read_bytes())
    except RuntimeError as exc:
        raise ValueError("browser signature verification failed: " + str(exc)) from exc
    text = raw.decode("utf-8")
    if upstream._parse_manifest_version(text) != identity["version"]:
        raise ValueError("signed browser manifest version differs from package identity")
    archive_name = config.get_archive_name(identity["platform"])
    matches = [line.split() for line in text.splitlines()
               if len(line.split()) == 2 and line.split()[1].lstrip("*") == archive_name]
    if len(matches) != 1 or SHA.fullmatch(matches[0][0]) is None:
        raise ValueError("signed browser manifest has no unique archive hash")
    sha = matches[0][0]
    archive = fetch(url, namespace / (sha + ".tar.gz"), sha)
    # Even an already-cached file is verified under the signed upstream hash.
    upstream._verify_checksum(safe(archive), sha)
    return archive, {**identity, "archive_sha256": sha,
                     "manifest_sha256": hashlib.sha256(raw).hexdigest(),
                     "signature_sha256": digest(signature), "verification": "upstream-ed25519-and-sha256"}


def extract_browser(archive, destination):
    """Validate every tar member first; materialize safe links as regular files."""
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError("browser extraction destination must be new")
    with tarfile.open(safe(archive), "r:gz") as tar:
        members = {}
        for member in tar.getmembers():
            name = member.name.rstrip("/")
            while name.startswith("./"):
                name = name[2:]
            if name in {"", "."} and member.isdir():
                continue
            path = PurePosixPath(name)
            if (not name or path.is_absolute() or ".." in path.parts or "\\" in name
                    or path.as_posix() != name or name in members
                    or not (member.isfile() or member.isdir() or member.issym() or member.islnk())):
                raise ValueError("unsafe/duplicate browser tar member: " + member.name)
            members[name] = member
        links = {}
        for name, member in members.items():
            if member.issym() or member.islnk():
                raw = member.linkname
                target = posixpath.normpath(posixpath.join(posixpath.dirname(name), raw)
                                           if member.issym() else raw)
                if (raw.startswith("/") or "\\" in raw or target.startswith("../")
                        or target not in members or not members[target].isfile()):
                    raise ValueError("unsafe browser archive link")
                links[name] = target
            for parent in PurePosixPath(name).parents:
                if str(parent) in members and not members[str(parent)].isdir():
                    raise ValueError("browser archive file/directory collision")
        destination.mkdir(mode=0o700)
        for name, member in members.items():
            path = destination / name
            if member.isdir():
                path.mkdir(parents=True, mode=0o755, exist_ok=True)
            elif member.isfile():
                path.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
                source = tar.extractfile(member)
                if source is None:
                    raise ValueError("browser archive regular file has no content")
                with source, path.open("xb") as output:
                    shutil.copyfileobj(source, output)
                path.chmod(0o555 if member.mode & 0o111 else 0o444)
        for name, target in links.items():
            path = destination / name
            path.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
            shutil.copyfile(destination / target, path)
            path.chmod(stat.S_IMODE((destination / target).stat().st_mode))
    entries = list(destination.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        wrapper = entries[0]
        for item in list(wrapper.iterdir()):
            item.rename(destination / item.name)
        wrapper.rmdir()
    chrome = destination / "chrome"
    safe(chrome)
    if not os.access(chrome, os.X_OK):
        raise ValueError("verified browser archive has no executable chrome")
