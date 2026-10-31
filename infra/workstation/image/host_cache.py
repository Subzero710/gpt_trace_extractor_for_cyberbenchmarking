"""Validate retained heavy objects before KVM, without executing cached code.

Browser keys/version maps are read as literals from the hash-locked wrapper
wheel. The guest independently repeats upstream's verification before use.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import zipfile
from pathlib import Path

from golden_assets import digest, safe
from golden_lock import SHA


def verify(cache, graph, *, system, architecture):
    for path in cache.rglob("*"):
        safe(path, directory=path.is_dir())
    objects = cache / "python/objects"
    wrapper = next(row for row in graph["packages"] if row["name"] == "cloakbrowser")
    wheels = []
    if objects.exists():
        for folder in objects.iterdir():
            safe(folder, directory=True)
            if SHA.fullmatch(folder.name) is None:
                raise ValueError("invalid persistent wheel CAS directory")
            for path in folder.iterdir():
                if digest(path) != folder.name:
                    raise ValueError("persistent wheel CAS hash mismatch before KVM: " + str(path))
                if folder.name in wrapper["hashes"]:
                    wheels.append(path)
    namespace = cache / "browser"
    if not namespace.exists():
        return
    active = []
    for folder in namespace.iterdir():
        safe(folder, directory=True)
        path = folder / "identity.json"
        if not path.exists():
            if any(folder.iterdir()):
                raise ValueError("browser cache has bytes without an acquisition identity")
            continue  # Empty interrupted mkdir has no artifact eligible for reuse.
        identity = json.loads(safe(path).read_bytes())
        if (not isinstance(identity, dict) or set(identity) != {"wrapper", "platform", "version"}
                or folder.name != hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()):
            raise ValueError("browser cache namespace/identity mismatch")
        if identity["wrapper"] == wrapper["version"]:
            active.append((folder, identity))
    if not active:
        return
    if not wheels:
        raise ValueError("cannot authenticate retained browser without its hash-locked wrapper wheel")
    configurations = []
    wanted = {"PLATFORM_CHROMIUM_VERSIONS", "SUPPORTED_PLATFORMS", "BINARY_SIGNING_PUBKEYS"}
    for path in wheels:
        with zipfile.ZipFile(path) as wheel:
            source = wheel.read("cloakbrowser/config.py")
        constants = {}
        for node in ast.parse(source).body:
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)] if isinstance(node, ast.Assign) else [node.target.id] if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) else []
            for name in set(targets) & wanted:
                constants[name] = ast.literal_eval(node.value)
        if set(constants) != wanted:
            raise ValueError("hash-locked wrapper exposes no auditable browser keys/version map")
        configurations.append(constants)
    if any(value != configurations[0] for value in configurations):
        raise ValueError("locked wrapper wheels disagree on browser trust roots")
    config = configurations[0]
    tag = config["SUPPORTED_PLATFORMS"][(system, architecture)]
    version = config["PLATFORM_CHROMIUM_VERSIONS"][tag]
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    for folder, identity in active:
        if identity["platform"] != tag:
            continue
        if identity["version"] != version:
            raise ValueError("retained browser version differs from locked wrapper")
        manifest, signature = folder / "SHA256SUMS", folder / "SHA256SUMS.sig"
        archives = list(folder.glob("*.tar.gz"))
        if not manifest.exists() or not signature.exists():
            if archives:
                raise ValueError("browser archive has no complete signed manifest")
            continue  # Interrupted metadata acquisition; no activated archive.
        raw = safe(manifest).read_bytes()
        sig = base64.b64decode(safe(signature).read_bytes().strip(), validate=True)
        verified = False
        for key in config["BINARY_SIGNING_PUBKEYS"]:
            public = Ed25519PublicKey.from_public_bytes(base64.b64decode(key, validate=True))
            try:
                public.verify(sig, raw)
            except InvalidSignature:
                continue
            verified = True
            break
        if not verified:
            raise ValueError("retained browser signature verification failed before KVM")
        lines = raw.decode().splitlines()
        if [line for line in lines if line.startswith("version=")] != ["version=" + version]:
            raise ValueError("signed retained browser manifest version mismatch")
        filename = "cloakbrowser-" + tag + ".tar.gz"
        rows = [line.split() for line in lines if len(line.split()) == 2 and line.split()[1].lstrip("*") == filename]
        if len(rows) != 1 or SHA.fullmatch(rows[0][0]) is None:
            raise ValueError("signed retained browser manifest has no unique target hash")
        for path in archives:
            if path.name != rows[0][0] + ".tar.gz" or digest(path) != rows[0][0]:
                raise ValueError("retained browser archive hash mismatch before KVM")
