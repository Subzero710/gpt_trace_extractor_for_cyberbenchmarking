#!/usr/bin/env python3
# GPT_TRACE_SWEGYM_CONDA_LOCK_V1
"""Maintenance-only compiler for the SWE-Gym Lite Conda archive lock.

It does not execute benchmark task recipes. It pulls one published evaluation
image per environment hash and reads only Conda provenance (`conda-meta/history`,
final `conda-meta/*.json`, and cached `repodata_record.json`). The resulting
lock contains exact package URLs and SHA-256 digests and is consumed by the
host-only dependency fetcher without running a Conda solver.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

SHA = re.compile(r"[0-9a-f]{64}\Z")
PYTHONS = ("3.8", "3.9", "3.10", "3.11", "3.12")
IMAGE_PREFIX = "xingyaoww/sweb.eval.x86_64."
ALLOWED_HOSTS = frozenset({"conda.anaconda.org", "repo.anaconda.com"})
ADAPTER = Path("apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym")


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            h.update(chunk)
    return h.hexdigest()


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode()).hexdigest()


def python_version(script):
    values = re.findall(r"\bpython\s*[= ]\s*(3\.(?:8|9|10|11|12))(?!\d)", "\n".join(script))
    if not values:
        raise RuntimeError("Conda environment has no Python constraint")
    return values[-1]


def shell_segments(line):
    lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|")
    lexer.whitespace_split = True
    lexer.commenters = ""
    tokens = list(lexer)
    segments = []
    current = []
    for token in tokens:
        if token in (";", "&&", "||", "|"):
            if current:
                segments.append(current)
                current = []
        else:
            current.append(token)
    if current:
        segments.append(current)
    return segments


def post_install_specs(script):
    result = []
    for command in script:
        try:
            segments = shell_segments(command)
        except ValueError:
            continue
        for tokens in segments:
            for pos, token in enumerate(tokens):
                if Path(token).name != "conda" or pos + 1 >= len(tokens) or tokens[pos + 1] != "install":
                    continue
                specs = []
                i = pos + 2
                while i < len(tokens):
                    token = tokens[i]
                    if token in ("-n", "--name", "-p", "--prefix"):
                        i += 2
                        continue
                    if token in ("-y", "--yes", "-q", "--quiet"):
                        i += 1
                        continue
                    if token.startswith("-"):
                        raise RuntimeError("unsupported post-create Conda option: " + token)
                    specs.append(token)
                    i += 1
                if specs:
                    result.append(specs)
    return result


def transaction_keys(env_hash, script):
    post = post_install_specs(script)
    if not post:
        return ["env-" + env_hash]
    result = ["env-" + env_hash + "-base"]
    for index in range(1, len(post) + 1):
        result.append("env-" + env_hash if index == len(post)
                      else "env-" + env_hash + "-step" + str(index))
    return result


def image_name(instance_id):
    if not isinstance(instance_id, str) or not instance_id or "\0" in instance_id:
        raise RuntimeError("invalid instance ID")
    return IMAGE_PREFIX + instance_id.replace("__", "_s_")


def docker_command():
    if shutil.which("docker"):
        probe = subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
        if probe.returncode == 0:
            return ["docker"]
    if shutil.which("sudo") and shutil.which("docker"):
        # sudo may use /dev/tty for an interactive password prompt. Do not use a
        # shell or copy caller credentials into the container.
        probe = subprocess.run(["sudo", "docker", "info"], stdout=subprocess.DEVNULL)
        if probe.returncode == 0:
            return ["sudo", "docker"]
    raise RuntimeError("Docker is required to compile conda-lock.json")


def command(docker, *args, capture=False, check=True, timeout=None):
    argv = [*docker, *map(str, args)]
    print("[conda-lock]", " ".join(argv), flush=True)
    return subprocess.run(argv, check=check, text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None, timeout=timeout)


EXTRACTOR = r"""import hashlib,json
from pathlib import Path

env=Path("/opt/miniconda3/envs/testbed/conda-meta")
cache=Path("/opt/miniconda3/pkgs")
if not (env/"history").is_file():
    raise SystemExit("missing testbed conda history")
history=(env/"history").read_text()
dists=sorted({line[1:].strip().split("::",1)[-1]
              for line in history.splitlines() if line[:1] in ("+","-")})
records={}
missing=[]
for dist in dists:
    path=cache/dist/"info"/"repodata_record.json"
    if not path.is_file():
        missing.append(dist); continue
    data=json.loads(path.read_text())
    if not data.get("sha256"):
        fn=data.get("fn")
        archive=cache/fn if isinstance(fn,str) else None
        if archive is not None and archive.is_file():
            h=hashlib.sha256()
            with archive.open("rb") as stream:
                for chunk in iter(lambda:stream.read(1048576),b""):h.update(chunk)
            data["sha256"]=h.hexdigest()
    records[dist]={key:data.get(key) for key in
        ("name","version","build","build_string","url","channel","subdir","fn","sha256","md5","size")}
final=[]
for path in sorted(env.glob("*.json")):
    data=json.loads(path.read_text())
    final.append({key:data.get(key) for key in
        ("name","version","build","build_string","url","channel","subdir","fn","sha256","md5","size")})
print(json.dumps({"history":history,"records":records,"missing":missing,"final":final},
                 sort_keys=True,separators=(",",":")))
"""


def validate_url(url):
    parsed = urllib.parse.urlsplit(str(url))
    if (parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS or
            parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise RuntimeError("untrusted Conda package URL: " + str(url))
    filename = Path(parsed.path).name
    if not (filename.endswith(".conda") or filename.endswith(".tar.bz2")):
        raise RuntimeError("unexpected Conda package filename: " + filename)
    return str(url)


def complete_record(raw):
    if not isinstance(raw, dict):
        raise RuntimeError("invalid Conda package record")
    name, version = raw.get("name"), raw.get("version")
    build = raw.get("build_string") or raw.get("build")
    fn = raw.get("fn")
    url = raw.get("url")
    if not url and isinstance(raw.get("channel"), str) and isinstance(fn, str):
        channel=raw["channel"].rstrip("/")
        subdir=raw.get("subdir")
        if isinstance(subdir,str) and Path(urllib.parse.urlsplit(channel).path).name!=subdir:
            channel += "/" + subdir
        url = channel + "/" + fn
    if not all(isinstance(value, str) and value for value in (name, version, build, url)):
        raise RuntimeError("incomplete Conda package identity")
    url = validate_url(url)
    sha = raw.get("sha256")
    if not isinstance(sha, str) or SHA.fullmatch(sha) is None:
        print("[conda-lock] SHA-256 absent from image metadata; hashing " + url, flush=True)
        request = urllib.request.Request(url, headers={"User-Agent":"gpt-trace-conda-lock/1"})
        h = hashlib.sha256()
        with urllib.request.urlopen(request, timeout=180) as response:
            if urllib.parse.urlsplit(response.url).scheme != "https":
                raise RuntimeError("untrusted Conda redirect")
            for chunk in iter(lambda: response.read(1048576), b""):
                h.update(chunk)
        sha = h.hexdigest()
    filename = Path(urllib.parse.urlsplit(url).path).name
    expected = f"{name}-{version}-{build}"
    if filename not in (expected + ".conda", expected + ".tar.bz2"):
        raise RuntimeError("Conda archive identity differs from package metadata: " + filename)
    subdir = raw.get("subdir")
    if subdir not in ("linux-64", "noarch"):
        raise RuntimeError("unsupported Conda subdir: " + str(subdir))
    return {"name":name,"version":version,"build":build,"url":url,
            "sha256":sha,"channel":raw.get("channel"),"subdir":subdir}


def dist_name(record):
    return f"{record['name']}-{record['version']}-{record['build']}"


def parse_history(history, records):
    blocks=[]
    current=[]
    for line in history.splitlines():
        if line.startswith("==>") and line.endswith("<=="):
            if current:
                blocks.append(current); current=[]
            continue
        if line[:1] not in ("+", "-"):
            continue
        dist=line[1:].strip().split("::",1)[-1]
        if dist not in records:
            raise RuntimeError("history references package without cache metadata: " + dist)
        current.append((line[0],dist))
    if current:
        blocks.append(current)
    state={}
    snapshots=[]
    for events in blocks:
        for operation,dist in events:
            record=records[dist]
            name=record["name"]
            if operation=="-":
                if state.get(name)!=dist:
                    raise RuntimeError("Conda history removal does not match current state: " + dist)
                del state[name]
            else:
                state[name]=dist
        snapshots.append(tuple(state[name] for name in sorted(state)))
    return snapshots


def image_digest(docker, image):
    result=command(docker,"image","inspect",image,capture=True,timeout=60)
    data=json.loads(result.stdout)
    if not isinstance(data,list) or len(data)!=1:
        raise RuntimeError("invalid Docker image inspection")
    digests=data[0].get("RepoDigests") or []
    values=[]
    for value in digests:
        if isinstance(value,str) and "@sha256:" in value:
            values.append(value.split("@",1)[1])
    values=sorted(set(values))
    if not values or any(re.fullmatch(r"sha256:[0-9a-f]{64}",x) is None for x in values):
        raise RuntimeError("pulled image has no immutable repository digest: " + image)
    # The content ID is what matters; multiple aliases to the same image are OK.
    if len(set(values))!=1:
        raise RuntimeError("image inspection returned conflicting content digests: " + image)
    return values[0]


def image_exists_locally(docker,image):
    return command(docker,"image","inspect",image,capture=True,check=False,timeout=30).returncode==0


def choose_image(docker, instance_ids):
    # The first published candidate is deterministic. A shared env may have many
    # task images; all must contain the same environment recipe hash.
    for instance_id in sorted(instance_ids):
        image=image_name(instance_id)
        probe=command(docker,"manifest","inspect",image,capture=True,check=False,timeout=120)
        if probe.returncode==0:
            return instance_id,image
    raise RuntimeError("no published SWE-Gym evaluation image for environment candidates")


def extract_image(docker,image):
    result=command(docker,"run","--rm","--network","none","--read-only",
        "-e","PYTHONDONTWRITEBYTECODE=1","--entrypoint","/opt/miniconda3/bin/python",
        image,"-c",EXTRACTOR,capture=True,timeout=300)
    try:
        data=json.loads(result.stdout)
    except Exception as exc:
        raise RuntimeError("image Conda metadata extractor returned invalid JSON") from exc
    if data.get("missing"):
        raise RuntimeError("image package cache lacks historical metadata: " + str(data["missing"][:10]))
    return data


def canonical_lock_bytes(lock):
    return (json.dumps(lock,sort_keys=True,indent=2,ensure_ascii=False)+"\n").encode()


def main(argv=None):
    parser=argparse.ArgumentParser()
    parser.add_argument("--repo-root",type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument("--keep-images",action="store_true")
    args=parser.parse_args(argv)
    root=args.repo_root.resolve()
    adapter=root/ADAPTER
    contract_path=adapter/"contract.json"
    pins_path=adapter/"pins.json"
    lock_path=adapter/"conda-lock.json"
    contract=json.loads(contract_path.read_bytes())
    pins=json.loads(pins_path.read_bytes())
    contract_sha=digest(contract_path)
    if contract_sha!=pins.get("contract_sha256"):
        raise RuntimeError("pinned SWE-Gym contract changed")
    tasks=contract.get("tasks")
    environments=contract.get("environments")
    if not isinstance(tasks,dict) or not isinstance(environments,dict) or len(tasks)!=230 or len(environments)!=25:
        raise RuntimeError("unexpected SWE-Gym Lite contract coverage")
    # Conda mutations after environment creation would make an image-derived
    # environment lock ambiguous. The pinned 230 task setup recipes currently
    # contain none; fail closed if that ever changes.
    for logical,task in tasks.items():
        for command_text in task.get("repo_script_list",[]):
            if re.search(r"\bconda\s+(?:create|install|update|remove)\b",command_text):
                raise RuntimeError("task repo setup mutates Conda: "+logical)
    task_ids={env:[] for env in environments}
    for logical,task in tasks.items():
        env=task.get("env_hash")
        if env not in task_ids:
            raise RuntimeError("task references unknown environment: "+logical)
        task_ids[env].append(logical)
    if any(not rows for rows in task_ids.values()):
        raise RuntimeError("environment has no task image candidate")

    docker=docker_command()
    artifacts={}
    locked_envs={}
    for index,(env_hash,entry) in enumerate(sorted(environments.items()),1):
        script=entry.get("original_script")
        if not isinstance(script,list) or any(not isinstance(x,str) for x in script):
            raise RuntimeError("invalid environment recipe: "+env_hash)
        expected_keys=transaction_keys(env_hash,script)
        instance_id,image=choose_image(docker,task_ids[env_hash])
        existed=image_exists_locally(docker,image)
        print(f"[conda-lock] {index}/25 {env_hash} <- {instance_id}",flush=True)
        try:
            command(docker,"pull",image,timeout=7200)
            immutable=image_digest(docker,image)
            payload=extract_image(docker,image)
        finally:
            if not args.keep_images and not existed:
                command(docker,"image","rm",image,check=False,timeout=300)
        raw_records=payload.get("records")
        if not isinstance(raw_records,dict) or not raw_records:
            raise RuntimeError("image contains no historical Conda package metadata")
        records={dist:complete_record(raw) for dist,raw in raw_records.items()}
        for dist,record in records.items():
            if dist_name(record)!=dist:
                raise RuntimeError("history distribution identity differs from repodata: "+dist)
        snapshots=parse_history(payload.get("history",""),records)
        if len(snapshots)!=len(expected_keys):
            raise RuntimeError(
                f"{env_hash}: expected {len(expected_keys)} Conda transactions from contract, "
                f"image history contains {len(snapshots)}"
            )
        final_payload=payload.get("final")
        if not isinstance(final_payload,list) or not final_payload:
            raise RuntimeError("image final Conda metadata is empty")
        final_records=[complete_record(row) for row in final_payload]
        if {dist_name(x) for x in final_records} != set(snapshots[-1]):
            raise RuntimeError("image final conda-meta differs from replayed Conda history: "+env_hash)

        transactions=[]
        for key,snapshot in zip(expected_keys,snapshots):
            shas=[]
            names=set()
            for dist in snapshot:
                record=records[dist]
                sha=record["sha256"]
                if record["name"] in names:
                    raise RuntimeError("duplicate package name in Conda environment state")
                names.add(record["name"])
                previous=artifacts.setdefault(sha,record)
                if previous!=record:
                    raise RuntimeError("same SHA-256 has conflicting Conda package metadata")
                shas.append(sha)
            py=[records[dist]["version"] for dist in snapshot if records[dist]["name"]=="python"]
            if len(py)!=1:
                raise RuntimeError("Conda transaction does not contain exactly one Python package")
            match=re.match(r"^(\d+)\.(\d+)",py[0])
            if not match:
                raise RuntimeError("invalid Python version in Conda transaction")
            major_minor=match.group(1)+"."+match.group(2)
            transactions.append({"key":key,"python":major_minor,"packages":shas})
        if transactions[-1]["python"]!=python_version(script):
            raise RuntimeError("image final Python differs from pinned environment recipe: "+env_hash)
        locked_envs[env_hash]={
            "instance_id":instance_id,
            "image":image,
            "image_digest":immutable,
            "recipe_sha256":fingerprint(script),
            "transactions":transactions,
        }

    referenced={sha for row in locked_envs.values() for tx in row["transactions"] for sha in tx["packages"]}
    if referenced!=set(artifacts):
        raise RuntimeError("Conda lock contains unreferenced or missing artifact records")
    lock={
        "schema":1,
        "kind":"swe-gym-lite-conda-image-lock",
        "platform":"linux-x86_64",
        "contract_sha256":contract_sha,
        "image_prefix":IMAGE_PREFIX,
        "artifacts":{key:artifacts[key] for key in sorted(artifacts)},
        "environments":{key:locked_envs[key] for key in sorted(locked_envs)},
    }
    data=canonical_lock_bytes(lock)
    fd,temporary=tempfile.mkstemp(prefix=".conda-lock.",dir=adapter)
    try:
        with os.fdopen(fd,"wb") as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.chmod(temporary,0o644)
        os.replace(temporary,lock_path)
    finally:
        try:os.unlink(temporary)
        except FileNotFoundError:pass
    print("[conda-lock] wrote",lock_path,flush=True)
    print("[conda-lock] sha256",hashlib.sha256(data).hexdigest(),flush=True)
    print("[conda-lock] environments",len(locked_envs),"transactions",
          sum(len(x["transactions"]) for x in locked_envs.values()),
          "unique archives",len(artifacts),flush=True)


if __name__=="__main__":
    main()
