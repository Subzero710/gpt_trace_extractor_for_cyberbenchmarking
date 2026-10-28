#!/usr/bin/env python3
"""Host-only SWE-Gym Lite dependency acquisition. No execution of task recipes.

The downloader runs as a dedicated non-root account. The privileged broker owns
publication. Fetch resolves deterministic build/download inputs only; it never
starts a VM, invokes a task script, installs software or deletes persisted data.
"""
from __future__ import annotations
import argparse
import concurrent.futures
import base64
import configparser
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import stat
import tempfile
import subprocess
import sys
import time
import tomllib
import urllib.parse
import urllib.request
import http.client
import ssl
import urllib.error
from collections import defaultdict
from pathlib import Path

PYTHONS = ('3.8','3.9','3.10','3.11','3.12')
REPO = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z')
COMMIT = re.compile(r'[a-f0-9]{40}\Z')
SHA = re.compile(r'[a-f0-9]{64}\Z')
KALI_SIGNING_FPR = '827C8569F2518CC677FECA1AED65462EC8D5E4C5'
MAX_SOURCE = 12 * 1024 * 1024
NPM_NODE18_VERSION = '10.9.9'
GOLDEN_SYSTEM_PYTHON = '3.13'  # Kali 2026.2 pinned by infra/workstation/image/build.py
DOWNLOAD_ATTEMPTS = 5
DOWNLOAD_RETRY_HTTP = frozenset({408, 425, 429, 500, 502, 503, 504})
DOWNLOAD_RETRY_BACKOFF = (1, 2, 4, 8)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1048576), b''): h.update(chunk)
    return h.hexdigest()


def invoke(argv, *, cwd=None, capture=False, env=None, timeout=3600):
    command = [str(v) for v in argv]
    print('[pool]', ' '.join(command), flush=True)
    try:
        result = subprocess.run(command, cwd=cwd, env=env, check=True,
                                text=True, stdout=subprocess.PIPE if capture else None, timeout=timeout)
    except subprocess.CalledProcessError as exc:
        # Captured stdout is otherwise lost from the durable preparation log.
        # Some dependency tools report structured failure diagnostics there.
        if capture and exc.stdout:
            output = exc.stdout if len(exc.stdout) <= 65536 else exc.stdout[-65536:]
            if len(output) != len(exc.stdout):
                print('[pool] failed command stdout truncated to final 65536 characters',
                      file=sys.stderr, flush=True)
            print('[pool] failed command captured stdout:', file=sys.stderr, flush=True)
            sys.stderr.write(output)
            if not output.endswith('\n'):
                sys.stderr.write('\n')
            sys.stderr.flush()
        raise
    return result.stdout if capture else None


def write_new(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(data if isinstance(data, bytes) else data.encode())
        stream.flush()
        os.fsync(stream.fileno())


def sri_parts(sri):
    if sri is None:
        return None
    if not isinstance(sri, str):
        raise RuntimeError('invalid package integrity token')
    candidates = []
    for token in sri.split():
        algorithm, sep, encoded = token.partition('-')
        if not sep or algorithm not in ('sha256', 'sha384', 'sha512'):
            raise RuntimeError('unsupported package integrity token')
        try:
            expected = base64.b64decode(encoded, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise RuntimeError('invalid package integrity base64') from exc
        if len(expected) != hashlib.new(algorithm).digest_size:
            raise RuntimeError('invalid package integrity length')
        candidates.append((algorithm, expected))
    if not candidates:
        raise RuntimeError('missing package integrity token')
    return candidates


def verify_sri(path, sri):
    candidates = sri_parts(sri)
    if candidates is None:
        return
    checks = [(hashlib.new(algorithm), expected) for algorithm, expected in candidates]
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            for h, _ in checks: h.update(block)
    if not any(h.digest() == expected for h, expected in checks):
        raise RuntimeError('integrity mismatch for cached package')


def _discard_partial_download(path):
    path=Path(path)
    try: info=path.lstat()
    except FileNotFoundError: return
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise RuntimeError('unsafe partial download path: '+str(path))
    path.unlink()


class DownloadIntegrityError(RuntimeError):
    """A completed transfer did not match its pinned integrity identity."""
    pass


def _retryable_network_error(exc):
    if isinstance(exc, DownloadIntegrityError):
        # A transport can terminate cleanly after delivering truncated/corrupted
        # bytes, so urllib may expose no network exception. Retry from byte zero;
        # the artifact is still accepted only after exact integrity verification.
        return True
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code in DOWNLOAD_RETRY_HTTP
    if isinstance(exc, ssl.SSLCertVerificationError):
        return False
    if isinstance(exc, (TimeoutError, ConnectionError, http.client.IncompleteRead,
                        http.client.BadStatusLine, ssl.SSLEOFError)):
        return True
    if isinstance(exc, urllib.error.URLError):
        reason=exc.reason
        if isinstance(reason, ssl.SSLCertVerificationError): return False
        return isinstance(reason, (TimeoutError, ConnectionError, OSError))
    return False


def _network_retry(label, operation, *, cleanup=None):
    for attempt in range(1, DOWNLOAD_ATTEMPTS+1):
        if cleanup is not None: cleanup()
        try:
            return operation()
        except Exception as exc:
            if not _retryable_network_error(exc): raise
            if cleanup is not None: cleanup()
            if attempt >= DOWNLOAD_ATTEMPTS: raise
            delay=DOWNLOAD_RETRY_BACKOFF[attempt-1]
            detail=('HTTP '+str(exc.code)) if isinstance(exc, urllib.error.HTTPError) else type(exc).__name__
            print(f'[pool] network retry {attempt+1}/{DOWNLOAD_ATTEMPTS} in {delay}s after {detail}: {label}',
                  file=sys.stderr, flush=True)
            time.sleep(delay)
    raise AssertionError('unreachable network retry loop')


def _read_https(url, *, timeout, limit, user_agent, expected_host=None):
    parsed=urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise RuntimeError('untrusted HTTPS endpoint: '+str(url))
    label=(parsed.hostname or '')+parsed.path
    def read_once():
        request=urllib.request.Request(url, headers={'User-Agent':user_agent})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            redirected=urllib.parse.urlsplit(response.url)
            if redirected.scheme != 'https': raise RuntimeError('untrusted HTTPS redirect')
            if expected_host is not None and redirected.hostname != expected_host:
                raise RuntimeError('untrusted HTTPS redirect host')
            length=response.headers.get('Content-Length','')
            if length.isdigit() and int(length)>limit: raise RuntimeError('HTTPS response exceeds limit')
            raw=response.read(limit+1)
        if len(raw)>limit: raise RuntimeError('HTTPS response exceeds limit')
        return raw
    return _network_retry(label, read_once)


def fetch(url, path, *, sha=None, sri=None, limit=2**37, integrity_digests=None):
    parsed=urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise RuntimeError('untrusted download endpoint: '+str(url))
    path=Path(path)
    label=(parsed.hostname or '')+parsed.path
    def transfer():
        request=urllib.request.Request(url,headers={'User-Agent':'gpt-trace-dependency-pool/2'})
        with urllib.request.urlopen(request,timeout=180) as response:
            if urllib.parse.urlsplit(response.url).scheme != 'https':
                raise RuntimeError('untrusted download redirect')
            if response.headers.get('Content-Length','').isdigit() and int(response.headers['Content-Length'])>limit:
                raise RuntimeError('download exceeds limit')
            h=hashlib.sha256(); size=0
            other_hashes={algorithm:hashlib.new(algorithm) for algorithm in ('sha384','sha512')} if integrity_digests is not None else {}
            checks=[(hashlib.new(algo),expected) for algo,expected in (sri_parts(sri) or ())]
            with path.open('xb') as stream:
                for block in iter(lambda:response.read(1048576),b''):
                    size+=len(block)
                    if size>limit: raise RuntimeError('download exceeds limit; partial retained')
                    stream.write(block); h.update(block)
                    for other in other_hashes.values(): other.update(block)
                    for sri_hash,_ in checks: sri_hash.update(block)
                stream.flush(); os.fsync(stream.fileno())
        actual=h.hexdigest()
        if sha and actual != sha:
            raise DownloadIntegrityError('download sha256 mismatch: '+str(path))
        if checks and not any(h.digest()==expected for h,expected in checks):
            raise DownloadIntegrityError('download integrity mismatch: '+str(path))
        if integrity_digests is not None:
            integrity_digests.update({algo:h.digest() for algo,h in other_hashes.items()})
        return actual
    return _network_retry(label, transfer, cleanup=lambda:_discard_partial_download(path))


def git_file(mirror, commit, path, *, required=False):
    path=path.removeprefix('./')
    if not path or path.startswith('/') or '\\' in path or '\x00' in path or '..' in Path(path).parts:
        raise ValueError('unsafe Git dependency file: '+path)
    raw=invoke(['git','--git-dir',mirror,'ls-tree',commit,'--',path],capture=True).strip()
    if not raw:
        if required: raise RuntimeError('missing source input '+path+' @ '+commit)
        return None
    if not re.fullmatch(r'100(?:644|755) blob [0-9a-f]{40}\t.+',raw):
        raise RuntimeError('dependency source is not a regular Git file: '+path)
    result=subprocess.check_output(['git','--git-dir',str(mirror),'show',commit+':'+path],timeout=60)
    if len(result)>MAX_SOURCE: raise RuntimeError('source metadata too large: '+path)
    return result.decode('utf-8')


def mirror_commits(root, repo, commits, *, label='git'):
    if not REPO.fullmatch(repo) or not commits or any(not COMMIT.fullmatch(x) for x in commits):
        raise RuntimeError('untrusted Git repo/commit')
    folder=root/label/(repo.replace('/','_')+'.git')
    folder.parent.mkdir(exist_ok=True)
    # Reuse only actual pinned commits already present in the copied mirror.
    # A stale/incomplete Git directory is never accepted as proof of a commit.
    retained_mirror=folder.exists()
    if retained_mirror:
        if folder.is_symlink() or not folder.is_dir():
            raise RuntimeError('unsafe retained Git mirror')
        if invoke(['git','--git-dir',folder,'rev-parse','--is-bare-repository'],capture=True).strip()!='true':
            raise RuntimeError('retained Git repository is not bare')
        missing=[commit for commit in sorted(commits) if subprocess.run(
            ['git','--git-dir',str(folder),'cat-file','-e',commit+'^{commit}'],
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode]
    else:
        invoke(['git','init','--bare',folder])
        missing=sorted(commits)
    if missing:
        # Fetch missing pinned commits only; never follow a moving branch.
        invoke(['git','-c','protocol.file.allow=never','--git-dir',folder,'fetch','--no-tags',
                '--depth=1','https://github.com/'+repo+'.git',*missing])
    if repo in {'bokeh/bokeh','pandas-dev/pandas'} and label=='git':
        tags=invoke(['git','--git-dir',folder,'tag','--list'],capture=True).splitlines()
        if not retained_mirror or not tags or (repo=='bokeh/bokeh' and len(tags)<5):
            invoke(['git','-c','protocol.file.allow=never','--git-dir',folder,
                    'fetch','--depth=1','--no-recurse-submodules',
                    'https://github.com/'+repo+'.git','+refs/tags/*:refs/tags/*'])
            tags=invoke(['git','--git-dir',folder,'tag','--list'],capture=True).splitlines()
        if repo=='bokeh/bokeh' and len(tags)<5:
            raise RuntimeError('Bokeh build requires at least five Git tags')
    for commit in commits:
        invoke(['git','--git-dir',folder,'cat-file','-e',commit+'^{commit}'])
    return folder


def ensure_commit(stage,repo,commit,*,label='git-extra'):
    folder=stage/label/(repo.replace('/','_')+'.git')
    if not folder.exists():return mirror_commits(stage,repo,{commit},label=label)
    probe=subprocess.run(['git','--git-dir',str(folder),'cat-file','-e',commit+'^{commit}'],
                         stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    if probe.returncode:
        invoke(['git','-c','protocol.file.allow=never','--git-dir',folder,'fetch',
                '--no-tags','--depth=1','https://github.com/'+repo+'.git',commit])
    invoke(['git','--git-dir',folder,'cat-file','-e',commit+'^{commit}'])
    return folder


def vcs_reference(value):
    """Recognize both pip legacy URLs and PEP 508 direct Git references."""
    value = value.strip()
    match = re.fullmatch(r'(?:[A-Za-z0-9_.-]+(?:\[[^]\n]+\])?\s*@\s*)?(git\+https://[^\s]+)', value)
    if match:
        return match.group(1)
    return None


def parse_requirements(text, filename, get_file, *, seen=None, constraint=False):
    """Return requirements, VCS references and CONSTRAINTS independently."""
    seen = set() if seen is None else seen
    key = (filename, constraint)
    if key in seen: return set(), set(), set()
    seen.add(key)
    specs, git, constraints = set(), set(), set()
    for original in text.replace('\\\n', '').splitlines():
        value = original.strip()
        if not value or value.startswith('#'): continue
        if value.startswith(('-r ', '--requirement ', '-c ', '--constraint ')):
            flag, child = value.split(maxsplit=1)
            if child.startswith(('/', 'http')) or '..' in Path(child).parts:
                raise RuntimeError('unsafe pip included requirements: ' + value)
            sub = str(Path(filename).parent / child)
            is_constraint = constraint or flag in ('-c', '--constraint')
            a, b, c = parse_requirements(get_file(sub, required=True), sub, get_file,
                                          seen=seen, constraint=is_constraint)
            specs.update(a); git.update(b); constraints.update(c)
            continue
        if value.startswith(('-e ', '--editable ')):
            target = value.split(maxsplit=1)[1]
            ref = vcs_reference(target)
            if ref:
                if constraint: raise RuntimeError('VCS dependency in constraints')
                git.add(ref)
                continue
            if target in ('.', './') or target.startswith(('./', '.[', '/testbed')):
                continue
            raise RuntimeError('unresolved editable dependency: ' + value)
        ref = vcs_reference(value)
        if ref:
            if constraint: raise RuntimeError('VCS dependency in constraints')
            git.add(ref)
            continue
        if value.startswith('-') or value.startswith(('https://', 'http://')):
            raise RuntimeError('unsupported pip requirement directive: ' + value)
        # A comment after whitespace is not part of a PEP 508 requirement.
        value = re.split(r'\s+#', value, maxsplit=1)[0].strip()
        (constraints if constraint else specs).add(value)
    return specs, git, constraints



def _poetry_version_spec(name, value):
    """Translate the finite Poetry constraint forms used by pinned inputs to PEP 440."""
    if not isinstance(value, str):
        raise ValueError('Poetry dependency version is not a string: ' + name)
    value = value.strip()
    if value in ('', '*'):
        return name
    if '||' in value:
        raise ValueError('unsupported Poetry disjunction for ' + name)
    if value.startswith('^'):
        base = value[1:]
        if not re.fullmatch(r'\d+(?:\.\d+){0,3}(?:[A-Za-z0-9.+-]*)?', base):
            raise ValueError('unsupported Poetry caret version for ' + name + ': ' + value)
        release = base.split('-', 1)[0].split('+', 1)[0]
        numeric = []
        for part in release.split('.'):
            match = re.match(r'(\d+)', part)
            if not match: break
            numeric.append(int(match.group(1)))
        while len(numeric) < 3: numeric.append(0)
        major, minor, patch = numeric[:3]
        if major:
            upper = f'{major + 1}.0.0'
        elif minor:
            upper = f'0.{minor + 1}.0'
        else:
            upper = f'0.0.{patch + 1}'
        return name + '>=' + base + ',<' + upper
    if value.startswith('~') and not value.startswith('~='):
        base = value[1:]
        if not re.fullmatch(r'\d+(?:\.\d+){0,3}(?:[A-Za-z0-9.+-]*)?', base):
            raise ValueError('unsupported Poetry tilde version for ' + name + ': ' + value)
        numeric = [int(x) for x in re.findall(r'^\d+|\.(\d+)', base) if x != '']
        # re.findall with a capture is awkward for the first component; derive
        # the release again without ever evaluating project code.
        release = base.split('-', 1)[0].split('+', 1)[0]
        parts = [int(re.match(r'\d+', x).group()) for x in release.split('.') if re.match(r'\d+', x)]
        if len(parts) <= 1:
            upper = f'{parts[0] + 1}.0.0'
        else:
            upper = f'{parts[0]}.{parts[1] + 1}.0'
        return name + '>=' + base + ',<' + upper
    if re.fullmatch(r'\d+(?:\.\d+)*(?:[A-Za-z0-9.+-]*)?', value):
        return name + '==' + value
    if re.fullmatch(r'\d+(?:\.\d+)*\.\*', value):
        return name + '==' + value
    if value.startswith(('=', '<', '>', '!', '~=')):
        return name + value
    # Comma-separated standard constraints such as ">=1,<2".
    if any(value.startswith(prefix) for prefix in ('>=', '<=', '!=', '==')):
        return name + value
    raise ValueError('unsupported Poetry dependency version for ' + name + ': ' + value)


def _normalized_package_name(value):
    return re.sub(r'[-_.]+', '-', str(value)).lower()


def _self_extra_reference(requirement, project_name):
    """Return extras for a local self-reference, or None for a normal requirement."""
    if not isinstance(requirement, str) or not isinstance(project_name, str) or not project_name:
        return None
    head = requirement.split(';', 1)[0].strip()
    match = re.fullmatch(r'([A-Za-z0-9_.-]+)(?:\[([^]]*)\])?', head)
    if not match or _normalized_package_name(match.group(1)) != _normalized_package_name(project_name):
        return None
    extras = tuple(x.strip() for x in (match.group(2) or '').split(',') if x.strip())
    return extras


def static_project(file, *, extra_groups=()):
    """Interpret declarative pyproject metadata without executing a backend.

    PEP 621 self-referential extras (for example ``dvc[tests]`` inside DVC's
    own ``dev`` extra) are recursively expanded from the same pinned file. They
    must never cause the fetcher to resolve a different, published copy of the
    project from PyPI.
    """
    if not file: return set(),set(),[]
    issues=[]; deps=set();git=set()
    data=tomllib.loads(file)
    project=data.get('project',{})
    if not isinstance(project, dict):
        return set(),set(),['invalid PEP621 project table']
    raw_dependencies = project.get('dependencies', [])
    if not isinstance(raw_dependencies, list):
        issues.append('invalid PEP621 dependencies')
    else:
        deps.update(raw_dependencies)
    build_requires = data.get('build-system',{}).get('requires',[])
    if isinstance(build_requires, list): deps.update(build_requires)
    else: issues.append('invalid build-system requires')
    for k in ('dependencies','optional-dependencies'):
        if k in project.get('dynamic',[]):issues.append('dynamic PEP621 '+k)

    optional = project.get('optional-dependencies',{})
    if optional is None: optional = {}
    if not isinstance(optional, dict):
        issues.append('invalid PEP621 optional-dependencies table')
        optional = {}
    project_name = project.get('name')
    visited=set()
    def add_pep621_group(group, stack=()):
        if group in stack:
            issues.append('recursive PEP621 self extra: '+' -> '.join((*stack,group)))
            return
        if group in visited:
            return
        items=optional.get(group)
        if items is None:
            return
        if not isinstance(items,list):
            issues.append('invalid PEP621 optional dependency group '+group)
            return
        visited.add(group)
        for item in items:
            if not isinstance(item,str):
                issues.append('non-string PEP621 optional dependency in '+group)
                continue
            nested=_self_extra_reference(item,project_name)
            if nested is not None:
                for child in nested:
                    add_pep621_group(child,(*stack,group))
                continue
            deps.add(item)
    requested_groups = set(optional) if '*' in extra_groups else set(extra_groups)
    for group in sorted(requested_groups):
        add_pep621_group(group)

    pdm=data.get('tool',{}).get('pdm',{})
    for group,items in pdm.get('dev-dependencies',{}).items():
        if group in extra_groups or '*' in extra_groups:
            if isinstance(items, list): deps.update(items)
            else: issues.append('invalid PDM dependency group '+group)
    poetry=data.get('tool',{}).get('poetry',{})
    poetry_extras = poetry.get('extras', {}) if isinstance(poetry.get('extras', {}), dict) else {}
    selected_optional = set()
    for group,names in poetry_extras.items():
        if group in extra_groups or '*' in extra_groups:
            if isinstance(names,list): selected_optional.update(str(name) for name in names)
            else: issues.append('invalid Poetry extra '+group)
    poetry_dependencies = poetry.get('dependencies', {})
    if isinstance(poetry_dependencies, dict):
        for name,spec in poetry_dependencies.items():
            if name=='python':continue
            optional_dep = isinstance(spec,dict) and spec.get('optional') is True
            if optional_dep and name not in selected_optional:
                continue
            try:
                if isinstance(spec,str):
                    deps.add(_poetry_version_spec(name,spec))
                elif isinstance(spec,dict):
                    if 'git' in spec:
                        url = spec.get('git')
                        ref = spec.get('rev') or spec.get('tag') or spec.get('branch')
                        if (not isinstance(url,str) or
                                not re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?',url)):
                            raise ValueError('untrusted Poetry Git dependency '+name)
                        direct = name+' @ git+'+url
                        if isinstance(ref,str) and ref: direct += '@'+ref
                        git.add(vcs_reference(direct) or direct)
                    elif isinstance(spec.get('version'),str):
                        deps.add(_poetry_version_spec(name,spec['version']))
                    else:
                        raise ValueError('unresolved Poetry dependency '+name)
                else:
                    raise ValueError('unresolved Poetry dependency '+name)
            except ValueError as exc:
                issues.append(str(exc))
    elif poetry_dependencies:
        issues.append('invalid Poetry dependencies table')
    poetry_dev = poetry.get('dev-dependencies',{})
    if ('dev' in extra_groups or 'test' in extra_groups or '*' in extra_groups):
        if isinstance(poetry_dev,dict):
            for name,spec in poetry_dev.items():
                try:
                    if isinstance(spec,str): deps.add(_poetry_version_spec(name,spec))
                    elif isinstance(spec,dict) and isinstance(spec.get('version'),str):
                        deps.add(_poetry_version_spec(name,spec['version']))
                    else: issues.append('unresolved Poetry dev dependency '+name)
                except ValueError as exc: issues.append(str(exc))
        elif poetry_dev:
            issues.append('invalid Poetry dev dependency table')
    for row in list(deps):
        if not isinstance(row,str):
            deps.remove(row); issues.append('non-string Python dependency metadata'); continue
        ref=vcs_reference(row)
        if ref:
            deps.remove(row);git.add(ref)
    return deps,git,issues

def setup_cfg_static(source, *, extras=()):
    """Read declarative setuptools requirements (no package execution)."""
    if not source: return set(), []
    parsed = configparser.ConfigParser(interpolation=None)
    try: parsed.read_string(source)
    except configparser.Error as exc: return set(), ['invalid setup.cfg: ' + str(exc)]
    specs = set()
    def add(section, key):
        for raw in parsed.get(section, key, fallback='').splitlines():
            value = raw.strip()
            if value and not value.startswith('#'): specs.add(value)
    add('options', 'install_requires')
    add('options', 'setup_requires')
    if parsed.has_section('options.extras_require'):
        for group in parsed.options('options.extras_require'):
            if group in extras or '*' in extras: add('options.extras_require', group)
    return specs, []


def setup_static(source, *, extras=(), get_file=None, python_version=None):
    """Evaluate a bounded subset of setuptools metadata without executing it.

    Supported constructs are literals, top-level names/list concatenation,
    selected ``extras_require`` groups, literal ``Path(...).read_text()`` chains
    backed by the pinned Git reader, and simple ``append``/``extend`` mutations
    guarded by target-Python ``sys.version_info`` conditions. Anything else
    remains fail-closed.
    """
    import ast
    import copy
    if not source: return set(), []
    try: tree = ast.parse(source)
    except SyntaxError: return set(), ['unparseable setup.py']

    env = {}
    unresolved = object()
    target_version = None
    if python_version is not None:
        match = re.fullmatch(r'(\d+)\.(\d+)(?:\.(\d+))?', str(python_version))
        if not match:
            return set(), ['invalid target Python version for setup.py: '+str(python_version)]
        target_version = tuple(int(x or 0) for x in match.groups())

    def safe_path(name):
        if not isinstance(name,str) or not name or Path(name).is_absolute() or '..' in Path(name).parts:
            raise ValueError('unsafe setup.py metadata path')
        if get_file is None:
            raise ValueError('setup.py file-backed metadata requires pinned source reader')
        value=get_file(name,required=True)
        if not isinstance(value,str):
            raise ValueError('setup.py metadata file is not text: '+name)
        return value

    def evaluate(node, visiting=frozenset()):
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bool, int, float, type(None))):
            return node.value
        if isinstance(node, ast.Name):
            if node.id in visiting or node.id not in env or env[node.id] is unresolved:
                raise ValueError('unresolved setup.py name ' + node.id)
            return copy.deepcopy(env[node.id])
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            values=[evaluate(item,visiting) for item in node.elts]
            return tuple(values) if isinstance(node,ast.Tuple) else values
        if isinstance(node, ast.Dict):
            result={}
            for key,value in zip(node.keys,node.values):
                key_value=evaluate(key,visiting)
                if not isinstance(key_value,str):
                    raise ValueError('non-string setup.py mapping key')
                result[key_value]=evaluate(value,visiting)
            return result
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return evaluate(node.left,visiting)+evaluate(node.right,visiting)
        if isinstance(node, ast.Attribute) and isinstance(node.value,ast.Name):
            if node.value.id=='sys' and node.attr=='version_info':
                if target_version is None:
                    raise ValueError('target Python required for sys.version_info')
                return target_version
        if isinstance(node, ast.Subscript):
            base=evaluate(node.value,visiting)
            index=evaluate(node.slice,visiting)
            return base[index]
        if isinstance(node, ast.UnaryOp) and isinstance(node.op,ast.USub):
            value=evaluate(node.operand,visiting)
            if not isinstance(value,(int,float)): raise ValueError('non-numeric setup.py unary expression')
            return -value
        if isinstance(node, ast.Call):
            if isinstance(node.func,ast.Name) and node.func.id=='str' and len(node.args)==1 and not node.keywords:
                return str(evaluate(node.args[0],visiting))
            if isinstance(node.func,ast.Name) and node.func.id=='Path' and len(node.args)==1 and not node.keywords:
                value=evaluate(node.args[0],visiting)
                if not isinstance(value,str): raise ValueError('non-string setup.py Path')
                return ('__pinned_path__',value)
            if isinstance(node.func,ast.Attribute) and not node.keywords:
                owner=evaluate(node.func.value,visiting)
                method=node.func.attr
                if method=='read_text' and isinstance(owner,tuple) and len(owner)==2 and owner[0]=='__pinned_path__':
                    if node.args: raise ValueError('setup.py read_text arguments are unsupported')
                    return safe_path(owner[1])
                if method=='strip' and isinstance(owner,str) and not node.args:
                    return owner.strip()
                if method=='splitlines' and isinstance(owner,str) and not node.args:
                    return owner.splitlines()
            raise ValueError('dynamic setup.py metadata expression')
        raise ValueError('dynamic setup.py metadata expression')

    def condition(node):
        if isinstance(node,ast.Constant) and isinstance(node.value,bool): return node.value
        if isinstance(node,ast.UnaryOp) and isinstance(node.op,ast.Not): return not condition(node.operand)
        if isinstance(node,ast.BoolOp):
            values=[condition(v) for v in node.values]
            return all(values) if isinstance(node.op,ast.And) else any(values)
        if isinstance(node,ast.Compare) and len(node.ops)==len(node.comparators)==1:
            left=evaluate(node.left);right=evaluate(node.comparators[0]);op=node.ops[0]
            if isinstance(op,ast.Eq): return left==right
            if isinstance(op,ast.NotEq): return left!=right
            if isinstance(op,ast.Lt): return left<right
            if isinstance(op,ast.LtE): return left<=right
            if isinstance(op,ast.Gt): return left>right
            if isinstance(op,ast.GtE): return left>=right
        raise ValueError('dynamic setup.py condition')

    # GPT_TRACE_STATIC_DEPENDENCY_BRANCH_MERGE_V1
    def merge_static_dependency_branches(node):
        """Conservatively include every literal dependency from either branch.

        Only accept complete if/else branches consisting entirely of safe
        assignments to the same setuptools requirement fields. Never execute
        upstream code and never guess the value of a dynamic expression.
        """
        allowed = {'install_requires', 'setup_requires'}

        def assignments(statements):
            values = {}
            if not statements:
                return None
            for statement in statements:
                if (not isinstance(statement, ast.Assign)
                        or len(statement.targets) != 1
                        or not isinstance(statement.targets[0], ast.Name)):
                    return None
                name = statement.targets[0].id
                if name not in allowed or name in values:
                    return None
                try:
                    requirements = evaluate(statement.value)
                except (TypeError, ValueError, KeyError, IndexError):
                    return None
                if (not isinstance(requirements, (list, tuple))
                        or not all(isinstance(req, str) for req in requirements)):
                    return None
                values[name] = requirements
            return values

        true_branch = assignments(node.body)
        false_branch = assignments(node.orelse)
        if (true_branch is None or false_branch is None
                or true_branch.keys() != false_branch.keys()):
            return False
        for name in true_branch:
            env[name] = list(dict.fromkeys((*true_branch[name], *false_branch[name])))
        return True

    def apply_statement(node):
        if isinstance(node,ast.Assign):
            try:value=evaluate(node.value)
            except (TypeError,ValueError,KeyError,IndexError): value=unresolved
            for target in node.targets:
                if isinstance(target,ast.Name): env[target.id]=copy.deepcopy(value)
            return
        if isinstance(node,ast.AnnAssign) and isinstance(node.target,ast.Name) and node.value is not None:
            try:env[node.target.id]=evaluate(node.value)
            except (TypeError,ValueError,KeyError,IndexError):env[node.target.id]=unresolved
            return
        if isinstance(node,ast.Expr) and isinstance(node.value,ast.Call):
            call=node.value
            if (isinstance(call.func,ast.Attribute) and isinstance(call.func.value,ast.Name)
                    and call.func.attr in ('append','extend') and not call.keywords
                    and call.func.value.id in env and env[call.func.value.id] is not unresolved):
                current=env[call.func.value.id]
                if not isinstance(current,list) or len(call.args)!=1:
                    env[call.func.value.id]=unresolved;return
                try:value=evaluate(call.args[0])
                except (TypeError,ValueError,KeyError,IndexError):
                    env[call.func.value.id]=unresolved;return
                if call.func.attr=='append': current.append(value)
                elif isinstance(value,(list,tuple)): current.extend(value)
                else: env[call.func.value.id]=unresolved
            return
        if isinstance(node,ast.If):
            try:selected=node.body if condition(node.test) else node.orelse
            except (TypeError,ValueError,KeyError,IndexError):
                # A finite literal dependency choice has a safe conservative union.
                if merge_static_dependency_branches(node):
                    return
                # Only variables mutated by an unresolved branch become unsafe.
                names=set()
                for child in ast.walk(node):
                    if (isinstance(child,ast.Call) and isinstance(child.func,ast.Attribute)
                            and isinstance(child.func.value,ast.Name)
                            and child.func.attr in ('append','extend')):
                        names.add(child.func.value.id)
                for name in names:
                    if name in env: env[name]=unresolved
                return
            for child in selected: apply_statement(child)

    # Evaluate only module-level state; function/class bodies are never run.
    for statement in tree.body:
        apply_statement(statement)

    deps,issues=set(),[]

    def fields_from_call(call):
        fields={kw.arg:kw.value for kw in call.keywords if kw.arg is not None}
        for kw in call.keywords:
            if kw.arg is not None: continue
            try:mapping=evaluate(kw.value)
            except (TypeError,ValueError,KeyError,IndexError) as exc:
                # Never silently discard an unresolved **kwargs mapping: it may
                # contain install_requires/setup_requires/extras_require. Known
                # pinned projects with audited file-backed mappings are handled
                # by setup_requirements_from_sources below.
                issues.append('setup.py computes **kwargs dynamically: '+str(exc))
                continue
            if not isinstance(mapping,dict):
                issues.append('setup.py **kwargs is not a mapping')
                continue
            for key,value in mapping.items():
                if key in fields:continue
                if value is unresolved:
                    fields[key]=ast.Name(id='__unresolved_setup_kwarg__',ctx=ast.Load())
                else:
                    # The mapping contains already-evaluated values; wrap
                    # them in a literal AST so the same validation path below
                    # can be used without executing code. Non-literal sentinels
                    # remain explicitly unresolved.
                    try:fields[key]=ast.parse(repr(value),mode='eval').body
                    except SyntaxError:
                        fields[key]=ast.Name(id='__unresolved_setup_kwarg__',ctx=ast.Load())
        return fields
    for node in ast.walk(tree):
        if not isinstance(node,ast.Call) or getattr(node.func,'id',None)!='setup': continue
        fields=fields_from_call(node)
        for name in ('install_requires','setup_requires'):
            if name not in fields: continue
            try:values=evaluate(fields[name])
            except (TypeError,ValueError,KeyError,IndexError) as exc:
                issues.append('setup.py computes '+name+' dynamically: '+str(exc));continue
            if isinstance(values,(list,tuple)) and all(isinstance(v,str) for v in values):deps.update(values)
            else:issues.append('setup.py unexpected '+name)
        if extras and 'extras_require' in fields:
            try:mapping=evaluate(fields['extras_require'])
            except (TypeError,ValueError,KeyError,IndexError) as exc:
                issues.append('setup.py computes extras_require dynamically: '+str(exc));continue
            if not isinstance(mapping,dict):
                issues.append('setup.py computes extras_require dynamically: extras_require is not a mapping');continue
            for group,values in mapping.items():
                if group not in extras and '*' not in extras: continue
                if isinstance(values,(list,tuple)) and all(isinstance(v,str) for v in values):deps.update(values)
                else:issues.append('setup.py computes extras_require dynamically: dynamic setup.py extra '+str(group))
    return deps,issues

def setup_requirements_from_sources(source, get_file, *, extras=(), python_version=None):
    """Resolve audited file-backed setuptools patterns without executing project code.

    Unsupported dynamic metadata fails closed. Only literal source reads whose
    filenames are pinned Git inputs are recognized.
    """
    deps, issues = setup_static(source, extras=extras, get_file=get_file, python_version=python_version)
    vcs = set()
    if not source:
        return deps, vcs, issues
    if get_file is None:
        return deps, vcs, issues

    def add_requirements(name):
        data = get_file(name, required=True)
        normal, remote, limits = parse_requirements(data, name, get_file)
        if limits:
            raise RuntimeError('requirements constraints not valid as install metadata: '+name)
        deps.update(normal); vcs.update(remote)

    # Hydra 1.x reads its runtime requirements with pkg_resources.
    if ('install_requires=install_requires' in source
            and 'pkg_resources.parse_requirements(requirements_txt)' in source
            and 'pathlib.Path("requirements/requirements.txt").open()' in source):
        try: add_requirements('requirements/requirements.txt')
        except RuntimeError as exc: return deps, vcs, [str(exc)]
        return deps, vcs, []

    # Conan 1.x has two pinned layouts in SWE-Gym Lite. Older commits read only
    # conans/requirements.txt; newer commits extend it with requirements_server.
    # Both use the same literal get_requires helper and assign the result to
    # install_requires. Development/test extras come from requirements_dev.txt.
    conan_runtime = re.search(
        r'\bproject_requirements\s*=\s*get_requires\(["\']conans/requirements\.txt["\']\)',
        source)
    conan_install = re.search(r'\binstall_requires\s*=\s*project_requirements\b', source)
    if conan_runtime and conan_install:
        try:
            add_requirements('conans/requirements.txt')
            if re.search(
                    r'project_requirements\.extend\(get_requires\(["\']conans/requirements_server\.txt["\']\)\)',
                    source):
                add_requirements('conans/requirements_server.txt')
            if 'dev' in extras or 'test' in extras or '*' in extras:
                add_requirements('conans/requirements_dev.txt')
        except RuntimeError as exc: return deps, vcs, [str(exc)]
        return deps, vcs, []

    # iterative/mock-ssh-server HEAD reads a fixed requirements.txt helper.
    if ('install_requires=read_requirements()' in source
            and 'requirements.txt' in source and 'def read_requirements' in source):
        try: add_requirements('requirements.txt')
        except RuntimeError as exc: return deps, vcs, [str(exc)]
        return deps, vcs, []

    # modin-spreadsheet@49ffd89 stores runtime dependencies in a fixed
    # requirements.txt, then passes a larger setup_args mapping via **setup_args.
    # The mapping also contains dynamic non-runtime metadata, so the generic AST
    # evaluator intentionally flags it. Resolve only the audited pinned runtime
    # file here; JavaScript build dependencies are handled from js/package.json.
    if (re.search(r'\breqs\s*=\s*read_requirements\(["\']requirements\.txt["\']\)', source)
            and re.search(r'["\']install_requires["\']\s*:\s*reqs\b', source)
            and '**setup_args' in source):
        try: add_requirements('requirements.txt')
        except RuntimeError as exc: return deps, vcs, [str(exc)]
        return deps, vcs, []

    if not issues:
        return deps, vcs, []
    return deps, vcs, issues


def git_requirements(mirror, commit, *, python_version=None):
    """Combine all declarative metadata sources, including tool-only pyprojects."""
    get_file = lambda path, required=False: git_file(mirror, commit, path, required=required)
    specs, vcs, issues = set(), set(), []
    pyproject = get_file('pyproject.toml')
    if pyproject:
        try:
            deps, remote, errors = static_project(pyproject)
            specs.update(deps); vcs.update(remote); issues.extend(errors)
        except (ValueError, TypeError) as exc:
            issues.append('invalid VCS pyproject.toml: '+str(exc))
    cfg, errors = setup_cfg_static(get_file('setup.cfg'))
    specs.update(cfg); issues.extend(errors)
    source = get_file('setup.py')
    if source:
        deps, remote, errors = setup_requirements_from_sources(
            source, get_file, python_version=python_version)
        specs.update(deps); vcs.update(remote); issues.extend(errors)
    if not (pyproject or source or get_file('setup.cfg')):
        issues.append('VCS source lacks Python build metadata')
    return specs, vcs, issues


def shell_segments(line):
    """Split a literal shell line on control operators while respecting quotes."""
    lexer = shlex.shlex(line, posix=True, punctuation_chars=';&|')
    lexer.whitespace_split = True
    lexer.commenters = ''
    tokens = list(lexer)
    segments=[]; current=[]; previous=None
    for token in tokens:
        if token in (';', '&&', '||', '|'):
            if current:
                segments.append((current, previous, token))
                current=[]
            previous=token
        else:
            current.append(token)
    if current:
        segments.append((current, previous, None))
    return segments


def pip_commands(commands):
    """Parse ordered pip installs, preserving shell optionality and --no-deps."""
    specs, files, vcs, issues, local_extras, constraints, steps = set(), set(), set(), [], set(), set(), []
    for line in commands:
        try:
            segments=shell_segments(line)
        except ValueError:
            issues.append('unparseable shell command')
            continue
        for index,(tokens,previous,next_operator) in enumerate(segments):
            pip_index=None
            for pos, token in enumerate(tokens):
                base=Path(token).name
                if base in ('pip','pip3') and pos+1 < len(tokens) and tokens[pos+1]=='install':
                    pip_index=pos
                    break
                if (base in ('python','python3') or re.fullmatch(r'python3\.\d+',base)) and pos+3 < len(tokens):
                    if tokens[pos+1:pos+3]==['-m','pip'] and tokens[pos+3]=='install':
                        pip_index=pos+2
                        break
            if pip_index is None:
                continue
            start = pip_index + 2
            parts=tokens[start:]
            optional = False
            if next_operator == '||' and index + 1 < len(segments):
                follower=segments[index+1][0]
                optional = follower in (['true'], [':'])
            ss, ff, vv, cc, ee = set(), set(), set(), set(), set()
            no_deps = False
            i = 0
            while i < len(parts):
                arg = parts[i]
                if arg == '--no-deps':
                    no_deps = True; i += 1; continue
                if arg in ('-r', '--requirement', '-c', '--constraint'):
                    if i + 1 >= len(parts): issues.append('pip requirements filename absent'); break
                    (cc if arg in ('-c', '--constraint') else ff).add(parts[i+1]); i += 2; continue
                if arg.startswith('-r') and len(arg) > 2: ff.add(arg[2:]); i += 1; continue
                if arg.startswith('-c') and len(arg) > 2 and not arg.startswith('-config'):
                    cc.add(arg[2:]); i += 1; continue
                if arg in ('-e', '--editable', '-ve', '-ev'):
                    if i + 1 >= len(parts): issues.append('editable dependency missing'); break
                    target = parts[i+1]
                    ref = vcs_reference(target)
                    if ref: vv.add(ref)
                    elif target in ('.', './') or target.startswith('.['):
                        if '[' in target:
                            match=re.findall(r'\[([^]]+)\]', target)
                            if match: ee.update(t.strip() for t in match[0].split(',') if t.strip())
                    else: issues.append('unknown editable target ' + target)
                    i += 2; continue
                if arg in ('--no-build-isolation', '--no-use-pep517', '--upgrade',
                           '-U', '-q', '--quiet', '-v', '--verbose', '--prefer-binary',
                           '--no-warn-script-location', '--no-input'):
                    i += 1; continue
                if arg in ('--config-settings', '--upgrade-strategy', '--index-url', '--extra-index-url'):
                    if i + 1 >= len(parts): issues.append('pip option value absent: '+arg); break
                    if arg in ('--index-url', '--extra-index-url'):
                        issues.append('untrusted custom package index: ' + arg)
                    i += 2; continue
                if arg.startswith(('-C', '--config-settings=')):
                    i += 1; continue
                if arg.startswith('-'):
                    issues.append('unresolved pip option ' + arg); break
                if arg in ('.', './') or arg.startswith('./'):
                    i += 1; continue
                ref = vcs_reference(arg)
                if ref: vv.add(ref)
                elif arg.startswith(('https://', 'http://')):
                    issues.append('unresolved remote pip target ' + arg)
                else: ss.add(arg)
                i += 1
            specs.update(ss); files.update(ff); vcs.update(vv)
            constraints.update(cc); local_extras.update(ee)
            command = shlex.join(tokens[pip_index-2 if pip_index>=2 and tokens[pip_index-2:pip_index]==['-m','pip'] else pip_index:])
            steps.append({'requirements': ss, 'files': ff, 'constraints': cc,
                           'vcs': vv, 'local_extras': ee, 'no_deps': no_deps,
                           'optional': optional, 'command': command})
    return specs, files, vcs, issues, local_extras, constraints, steps



def make_commands(text, target, *, visiting=None):
    visiting=set() if visiting is None else visiting
    if target in visiting:raise RuntimeError('recursive Make dependency')
    visiting.add(target)
    rows={};current=None
    for line in text.splitlines():
        m=re.match(r'^([A-Za-z0-9_.-]+)\s*:\s*([^#]*)(?:#.*)?$',line)
        if m:current=m.group(1);rows[current]=(m.group(2).split(),[])
        elif line.startswith('\t') and current:
            rows[current][1].append(line[1:].lstrip('@-+'))
        elif line and not line.startswith((' ', '#')):current=None
    if target not in rows:raise RuntimeError('Make target not defined: '+target)
    commands=[]
    for dependency in rows[target][0]:
        if dependency in rows:commands+=make_commands(text,dependency,visiting=visiting.copy())
    return commands+rows[target][1]


def read_submodules(mirror, commit):
    conf=git_file(mirror,commit,'.gitmodules')
    if not conf:return []
    parser=configparser.ConfigParser(interpolation=None)
    parser.read_string(conf)
    result=[]
    for section in parser.sections():
        path=parser.get(section,'path',fallback='')
        url=parser.get(section,'url',fallback='')
        if not path or url.startswith(('.', 'git@')):raise RuntimeError('relative/untrusted Git submodule URL')
        match=re.fullmatch(r'https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?',url)
        if not match:raise RuntimeError('unsupported Git submodule URL: '+url)
        row=invoke(['git','--git-dir',mirror,'ls-tree',commit,'--',path],capture=True).strip()
        m=re.fullmatch(r'160000 commit ([a-f0-9]{40})\t.+',row)
        if not m:raise RuntimeError('submodule Gitlink missing: '+path)
        result.append((path,match.group(1),m.group(1)))
    return result


def transformed_source(repo, path, value, commands):
    """Mirror deterministic, literal in-recipe source edits without executing shell."""
    if value is None: return value
    joined = '\n'.join(commands)
    if repo == 'facebookresearch/hydra':
        if path == 'requirements/dev.txt' and 'isort@git+git://' in joined:
            value = value.replace('isort@git+git://github.com/timothycrosley/isort',
                                  'isort@git+https://github.com/timothycrosley/isort')
        if path == 'requirements/requirements.txt' and '"pip==24.0" >> requirements/requirements.txt' in joined:
            value = value.rstrip('\n') + '\npip==24.0\n'
    elif repo == 'Project-MONAI/MONAI' and path == 'requirements-dev.txt':
        if "sed -i '/^git+https:" in joined:
            value = '\n'.join(line for line in value.split('\n')
                              if not line.startswith('git+https://github.com/Project-MONAI/'))
    elif repo == 'python/mypy' and path == 'test-requirements.txt':
        if "1i types-typing-extensions==3.7.3" in joined:
            value = 'types-typing-extensions==3.7.3\n' + value
    elif repo == 'iterative/dvc' and path == 'setup.py':
        if "s/pyarrow==0.15.1/pyarrow==0.16/" in joined:
            value = value.replace('pyarrow==0.15.1', 'pyarrow==0.16')
        if "s/boto3==1.9.115/boto3==1.9.201/" in joined:
            value = value.replace('boto3==1.9.115', 'boto3==1.9.201')
        if 'moto==' in joined and '.dev' in joined:
            value = re.sub(r'moto==(\d+\.\d+\.\d+)\.dev\d+', r'moto==\1', value)
    return value


def conda_yaml(script):
    for command in script:
        match=re.search(r"cat <<'([^']+)' > environment\.yml\n(.*?)\n\1(?:\n|$)",command,re.S)
        if match:return match.group(2)+'\n'
    return None


def conda_pip_split(content):
    lines=content.splitlines(keepends=True); out=[];pip=[];inside=False
    for line in lines:
        if re.match(r'^\s+- pip:\s*$',line):inside=True;continue
        if inside and re.match(r'^\s{4,}-\s*',line):pip.append(line.split('-',1)[1].strip());continue
        if inside and (not line.strip() or line.lstrip().startswith('#')):continue
        inside=False;out.append(line)
    return ''.join(out),pip


def python_version(script):
    values=re.findall(r'\bpython\s*[= ]\s*(3\.(?:8|9|10|11|12))(?!\d)','\n'.join(script))
    if not values:raise RuntimeError('Conda environment has no Python constraint')
    return values[-1]



def conda_direct_specs(script):
    """Return literal package specs from a direct `conda create -n testbed ...`."""
    found=[]
    for command in script:
        try: segments=shell_segments(command)
        except ValueError: continue
        for tokens,_,_ in segments:
            if not tokens or Path(tokens[0]).name != 'conda' or len(tokens)<2 or tokens[1] != 'create':
                continue
            specs=[];i=2
            while i < len(tokens):
                token=tokens[i]
                if token in ('-n','--name','-p','--prefix'):
                    i += 2; continue
                if token in ('-y','--yes','-q','--quiet'):
                    i += 1; continue
                if token.startswith('-'):
                    raise RuntimeError('unsupported direct Conda create option: '+token)
                specs.append(token);i+=1
            if specs: found.append(specs)
    if len(found)>1: raise RuntimeError('multiple direct Conda create commands in one environment')
    return found[0] if found else None


def conda_post_install_specs(script):
    """Return package specs from literal post-create `conda install` transactions."""
    result=[]
    for command in script:
        try: segments=shell_segments(command)
        except ValueError: continue
        for tokens,_,_ in segments:
            try: pos=next(i for i,t in enumerate(tokens) if Path(t).name=='conda' and i+1<len(tokens) and tokens[i+1]=='install')
            except StopIteration: continue
            specs=[];i=pos+2
            while i<len(tokens):
                token=tokens[i]
                if token in ('-n','--name','-p','--prefix'):
                    i+=2;continue
                if token in ('-y','--yes','-q','--quiet'):
                    i+=1;continue
                if token.startswith('-'):
                    raise RuntimeError('unsupported post-create Conda option: '+token)
                specs.append(token);i+=1
            if specs: result.append(specs)
    return result



def apt_recipe_operations(commands):
    """Extract install package names and upgrade intent from literal apt-get calls."""
    packages=set(); upgrades=[]
    for command in commands:
        try: segments=shell_segments(command)
        except ValueError:
            raise RuntimeError('unparseable APT shell command')
        for tokens,_,_ in segments:
            for pos,token in enumerate(tokens):
                if Path(token).name != 'apt-get':
                    continue
                i=pos+1
                while i<len(tokens) and tokens[i].startswith('-'):
                    # All task recipes use flag-only options before the verb.
                    if tokens[i] in ('-o','--option'):
                        if i+1>=len(tokens): raise RuntimeError('APT option value absent')
                        i+=2
                    else:i+=1
                if i>=len(tokens): raise RuntimeError('APT operation absent')
                verb=tokens[i];rest=tokens[i+1:]
                if verb=='install':
                    j=0
                    while j<len(rest):
                        value=rest[j]
                        if value in ('-o','--option'):
                            j+=2;continue
                        if value.startswith('-'):
                            j+=1;continue
                        if not re.fullmatch(r'[A-Za-z0-9+._:-]+',value):
                            raise RuntimeError('untrusted APT package token: '+value)
                        packages.add(value);j+=1
                elif verb in ('upgrade','dist-upgrade','full-upgrade'):
                    upgrades.append(verb)
                elif verb in ('update','clean','autoclean'):
                    pass
                else:
                    raise RuntimeError('unsupported apt-get operation: '+verb)
    return packages,upgrades


class Pool:
    def __init__(self, stage):
        self.stage = Path(stage)
        self.objects = self.stage / 'objects' / 'sha256'
        self.objects.mkdir(parents=True,exist_ok=True)
        self.links = {}
        self.provenance = {}
        self.issues = []
        # Per-attempt indexes are rebuilt from verified retained content.
        self.by_url = {}
        self.by_sri = {}
        self.sri_verified = set()
        self.verified_objects = set()  # SHA-256 verified at acquisition or recovery

    def reference(self, sha, category, identity, size):
        target = self.objects / sha[:2] / sha
        if not target.is_file() or target.is_symlink() or target.stat().st_size != size:
            raise RuntimeError('missing/invalid content-addressed dependency')
        self.links.setdefault(sha, {'path': target.relative_to(self.stage).as_posix(),
                                    'size': size, 'sha256': sha})
        refs = self.provenance.setdefault(category, {}).setdefault(identity, [])
        if sha not in refs:
            refs.append(sha)
        return sha

    def put(self, path, category, identity, *, verified_sha=None):
        """Register one immutable artifact with a content-addressed hardlink.

        A digest is computed here only for third-party tools' output. Direct
        downloads already supplied their SHA-256 during streaming.
        """
        path = Path(path)
        if path.is_symlink() or not path.is_file():
            raise RuntimeError('unsafe downloaded artifact: ' + str(path))
        sha = verified_sha if verified_sha is not None else digest(path)
        if not SHA.fullmatch(sha):
            raise RuntimeError('invalid artifact SHA-256')
        size = path.stat().st_size
        target = self.objects / sha[:2] / sha
        target.parent.mkdir(exist_ok=True)
        if not target.exists():
            os.link(path, target)
        elif target.is_symlink() or not target.is_file() or target.stat().st_size != size:
            raise RuntimeError('content-addressed pool collision/changed object')
        self.verified_objects.add(sha)
        return self.reference(sha, category, identity, size)

    def coalesce_stage_file(self, path, sha):
        """Coalesce completed, disposable acquisition files immediately.

        Never use on writable Git refs, logs, or other mutable application state.
        The broker alone performs final verification and publishes ready/.
        """
        path = Path(path)
        target = self.objects / sha[:2] / sha
        if path.samefile(target):
            return
        import secrets
        temporary = path.parent / ('.pool-link-' + secrets.token_hex(16))
        os.link(target, temporary)
        try:
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()

    def download(self, url, category, identity, *, sha=None, sri=None):
        """Download once by SHA-256, SRI or URL, then share by reference.

        Trust a known digest before fetching bytes. If a URL is requested again
        under another task/recipe, record another reference instead of refetching.
        Distinct URLs with the same SRI share their existing content as well.
        """
        if sha is not None and not SHA.fullmatch(str(sha)):
            raise RuntimeError('invalid expected artifact SHA-256')
        sri_value = tuple(sri_parts(sri) or ())
        cached = None
        if sha is not None and (self.objects / sha[:2] / sha).is_file():
            cached = sha
        elif sri_value:
            for item in sri_value:
                if item in self.by_sri:
                    cached = self.by_sri[item]
                    break
        elif url in self.by_url:
            cached = self.by_url[url]
        # Even when the known digest is new, a previously fetched URL may exist.
        if cached is None:
            cached = self.by_url.get(url)
        if cached is not None:
            target = self.objects / cached[:2] / cached
            if (target.is_symlink() or not target.is_file()
                    or cached not in self.verified_objects and digest(target)!=cached):
                raise RuntimeError('retained CAS bytes fail SHA-256 verification: '+cached)
            self.verified_objects.add(cached)
            if sha is not None and cached != sha:
                raise RuntimeError('conflicting expected checksum for existing download URL/SRI')
            target = self.objects / cached[:2] / cached
            if sri_value and not any((cached, part) in self.sri_verified for part in sri_value):
                verify_sri(target, sri)
                self.sri_verified.update((cached, part) for part in sri_value)
            self.by_url[url] = cached
            for part in sri_value:
                existing = self.by_sri.setdefault(part, cached)
                if existing != cached:
                    raise RuntimeError('conflicting SRI artifact identity')
            return self.reference(cached, category, identity, target.stat().st_size)

        # Independent of task/category: one stable URL gets one acquisition path.
        raw = self.stage / 'downloads' / hashlib.sha256(url.encode()).hexdigest()
        raw.parent.mkdir(exist_ok=True)
        known_hashes = {}
        # A URL-based old download can be reused ONLY when an independent
        # pinned digest/SRI verifies it. Unpinned bytes are fetched anew.
        actual = None
        if raw.exists() or raw.is_symlink():
            if raw.is_symlink() or not raw.is_file():
                raise RuntimeError('unsafe retained URL download')
            if sha is not None or sri is not None:
                candidate = digest(raw)
                try:
                    if (sha is not None and sha != candidate):
                        raise ValueError('retained checksum mismatch')
                    if sri is not None: verify_sri(raw,sri)
                except (ValueError,RuntimeError):
                    raw.unlink()  # Only our new, private candidate stage.
                else:
                    actual = candidate
            else:
                raw.unlink()
        if actual is None:
            actual = fetch(url, raw, sha=sha, sri=sri, integrity_digests=known_hashes)
        self.put(raw, category, identity, verified_sha=actual)
        self.coalesce_stage_file(raw, actual)
        self.by_url[url] = actual
        for algo, binary in [('sha256', bytes.fromhex(actual)), *known_hashes.items()]:
            token = (algo, binary)
            existing = self.by_sri.setdefault(token, actual)
            if existing != actual:
                raise RuntimeError('conflicting content-addressed identity')
            self.sri_verified.add((actual, token))
        for part in sri_value:
            existing = self.by_sri.setdefault(part, actual)
            if existing != actual:
                raise RuntimeError('conflicting SRI artifact identity')
            self.sri_verified.add((actual, part))
        return actual

    def issue(self, where, description):
        self.issues.append(f'{where}: {description}')


# GPT_TRACE_SWEGYM_VERIFIED_RESUME_V1
# Copy a FAILED stage into a fresh candidate. Never modify the original.
def salvage_verified_stage(old, new):
    old, new = Path(old), Path(new)
    if (old.resolve()==new.resolve() or new.resolve().is_relative_to(old.resolve())
            or old.resolve().is_relative_to(new.resolve())):
        raise RuntimeError('source and candidate recovery stages must be distinct')
    if old.is_symlink() or not old.is_dir() or new.is_symlink():
        raise RuntimeError('unsafe interrupted dependency pool')
    if not (old/'STAGING').is_file() or (old/'STAGING').is_symlink():
        raise RuntimeError('unidentified interrupted dependency pool')
    # Check all paths before copying, including files we do not plan to reuse.
    # A mount/symlink/device may not redirect the trusted downloader elsewhere.
    for path in old.rglob('*'):
        if path.is_symlink() or path.is_mount() or not (path.is_dir() or path.is_file()):
            raise RuntimeError('unsafe retained dependency entry: '+str(path))
    old_cas=old/'objects'/'sha256'
    good={}
    count=0
    if old_cas.is_dir():
        for obj in old_cas.glob('*/*'):
            sha=obj.name
            if (not SHA.fullmatch(sha) or obj.parent.name!=sha[:2]
                    or not obj.is_file()):
                raise RuntimeError('invalid retained CAS object path')
            if digest(obj)!=sha:
                print('[pool] skipping corrupt retained CAS object '+sha,flush=True)
                continue
            target=new/'objects'/'sha256'/sha[:2]/sha
            target.parent.mkdir(parents=True,exist_ok=True)
            os.link(obj,target)  # Verified immutable bytes, zero-copy reuse.
            good[(obj.stat().st_dev,obj.stat().st_ino)]=(sha,target)
            count+=1
    # Git refs/packed objects can be mutated by a later fetch: COPY them, never
    # hardlink mutable Git objects to the failed stage.
    for kind in ('git','git-extra'):
        source=old/kind
        if source.is_dir():
            shutil.copytree(source,new/kind,dirs_exist_ok=True,copy_function=shutil.copy2)
    # Retain only files already hardlinked to a SHA-verified old CAS object.
    # Partial HTTP transfers, unconstrained downloads and pip scratch files
    # are deliberately excluded.
    for kind in ('downloads','wheels/shared'):
        source=old/kind
        if not source.is_dir():continue
        for file in source.rglob('*'):
            if not file.is_file():continue
            identity=(file.stat().st_dev,file.stat().st_ino)
            if identity not in good:continue
            dest=new/kind/file.relative_to(source)
            dest.parent.mkdir(parents=True,exist_ok=True)
            os.link(good[identity][1],dest)
    # APT will verify these archives again against signed Kali indexes.
    # They are writable APT cache entries, so COPY instead of hardlinking them.
    old_debs=old/'apt'/'archives'
    if old_debs.is_dir():
        for deb in old_debs.glob('*.deb'):
            if (deb.stat().st_dev,deb.stat().st_ino) not in good:continue
            dest=new/'apt'/'archives'/deb.name
            dest.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(deb,dest)
    print('[pool] verified resume: '+str(count)+' CAS artifacts and retained Git mirrors',flush=True)
    return {value[0] for value in good.values()}


# GPT_TRACE_SWEGYM_CONDA_LOCK_V1
CONDA_LOCK_SCHEMA = 1
CONDA_LOCK_WORKERS = 8
CONDA_LOCK_HOSTS = frozenset({'conda.anaconda.org', 'repo.anaconda.com'})


def conda_recipe_fingerprint(script):
    return hashlib.sha256(json.dumps(script,sort_keys=True,separators=(',',':'),
        ensure_ascii=False).encode()).hexdigest()


def conda_expected_transaction_keys(env,script):
    post=conda_post_install_specs(script)
    if not post:return ['env-'+env]
    result=['env-'+env+'-base']
    for index in range(1,len(post)+1):
        result.append('env-'+env if index==len(post) else 'env-'+env+'-step'+str(index))
    return result


def _validate_conda_lock_url(url,name,version,build):
    parsed=urllib.parse.urlsplit(str(url))
    if (parsed.scheme!='https' or parsed.hostname not in CONDA_LOCK_HOSTS or parsed.username
            or parsed.password or parsed.query or parsed.fragment):
        raise RuntimeError('untrusted Conda lock URL: '+str(url))
    filename=Path(parsed.path).name
    expected=str(name)+'-'+str(version)+'-'+str(build)
    if filename not in (expected+'.conda',expected+'.tar.bz2'):
        raise RuntimeError('Conda lock package identity/URL mismatch: '+filename)
    return str(url)


def load_conda_lock(adapter,pins,contract):
    path=Path(adapter)/'conda-lock.json'
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('missing pinned SWE-Gym Conda lock; run scripts/generate_swegym_conda_lock.py')
    raw=path.read_bytes();lock_sha=hashlib.sha256(raw).hexdigest()
    try:lock=json.loads(raw)
    except ValueError as exc:raise RuntimeError('invalid SWE-Gym Conda lock JSON') from exc
    if (not isinstance(lock,dict) or lock.get('schema')!=CONDA_LOCK_SCHEMA
            or lock.get('kind')!='swe-gym-lite-conda-image-lock'
            or lock.get('platform')!='linux-x86_64'
            or lock.get('contract_sha256')!=pins.get('contract_sha256')
            or lock.get('image_prefix')!='xingyaoww/sweb.eval.x86_64.'):
        raise RuntimeError('SWE-Gym Conda lock header differs from pinned contract')
    artifacts=lock.get('artifacts');environments=lock.get('environments')
    if (not isinstance(artifacts,dict) or not artifacts or len(artifacts)>50000
            or not isinstance(environments,dict)
            or set(environments)!=set(contract.get('environments',{}))):
        raise RuntimeError('SWE-Gym Conda lock coverage differs')
    by_url={}
    checked={}
    for sha,item in artifacts.items():
        if not isinstance(sha,str) or not SHA.fullmatch(sha) or not isinstance(item,dict):
            raise RuntimeError('invalid Conda lock artifact identity')
        if item.get('sha256')!=sha:
            raise RuntimeError('Conda lock artifact key/SHA mismatch')
        name=item.get('name');version=item.get('version');build=item.get('build')
        if not all(isinstance(value,str) and value for value in (name,version,build)):
            raise RuntimeError('incomplete Conda lock package identity')
        if item.get('subdir') not in ('linux-64','noarch'):
            raise RuntimeError('unsupported Conda lock package subdir')
        url=_validate_conda_lock_url(item.get('url'),name,version,build)
        previous=by_url.setdefault(url,sha)
        if previous!=sha:raise RuntimeError('Conda lock URL maps to conflicting SHA-256 values')
        checked[sha]={'name':name,'version':version,'build':build,'url':url,'sha256':sha,
                      'channel':item.get('channel'),'subdir':item.get('subdir')}
    tasks_by_env=defaultdict(list)
    for logical,task in contract.get('tasks',{}).items():tasks_by_env[task.get('env_hash')].append(logical)
    referenced=set()
    normalized_envs={}
    for env,recipe in contract['environments'].items():
        row=environments.get(env)
        if not isinstance(row,dict):raise RuntimeError('invalid Conda lock environment '+env)
        candidates=sorted(tasks_by_env.get(env,[]))
        instance=row.get('instance_id')
        if instance not in candidates:
            raise RuntimeError('Conda lock environment references unrelated task image: '+env)
        expected_image='xingyaoww/sweb.eval.x86_64.'+instance.replace('__','_s_')
        if row.get('image')!=expected_image or re.fullmatch(r'sha256:[0-9a-f]{64}',str(row.get('image_digest'))) is None:
            raise RuntimeError('invalid Conda lock image provenance: '+env)
        script=recipe.get('original_script')
        if row.get('recipe_sha256')!=conda_recipe_fingerprint(script):
            raise RuntimeError('Conda lock recipe fingerprint differs: '+env)
        expected_keys=conda_expected_transaction_keys(env,script)
        transactions=row.get('transactions')
        if not isinstance(transactions,list) or [x.get('key') if isinstance(x,dict) else None for x in transactions]!=expected_keys:
            raise RuntimeError('Conda lock transaction sequence differs: '+env)
        normalized=[]
        for transaction in transactions:
            python=transaction.get('python');packages=transaction.get('packages')
            if python not in PYTHONS or not isinstance(packages,list) or not packages or len(packages)!=len(set(packages)):
                raise RuntimeError('invalid Conda lock transaction: '+transaction.get('key','?'))
            names=set();solution=[]
            for sha in packages:
                if sha not in checked:raise RuntimeError('Conda lock transaction references unknown archive')
                item=checked[sha]
                if item['name'] in names:raise RuntimeError('duplicate package name in Conda lock transaction')
                names.add(item['name']);solution.append(item)
                referenced.add(sha)
            if conda_solution_python(solution)!=python:
                raise RuntimeError('Conda lock transaction Python metadata differs')
            normalized.append({'key':transaction['key'],'python':python,'packages':list(packages)})
        if normalized[-1]['python']!=python_version(script):
            raise RuntimeError('Conda lock final Python differs from contract: '+env)
        normalized_envs[env]={**row,'transactions':normalized}
    if referenced!=set(checked):raise RuntimeError('Conda lock has unreferenced archive records')
    return {**lock,'artifacts':checked,'environments':normalized_envs},lock_sha


def acquire_locked_conda(pool,lock):
    """Acquire each immutable Conda archive once, then materialize transaction snapshots."""
    artifacts=lock['artifacts'];references=defaultdict(set)
    for env,row in lock['environments'].items():
        for transaction in row['transactions']:
            for sha in transaction['packages']:references[sha].add(transaction['key'])
    missing=[sha for sha in sorted(references)
             if not (pool.objects/sha[:2]/sha).is_file()]
    print('[pool] Conda lock: '+str(len(lock['environments']))+' environments, '
          +str(sum(len(row['transactions']) for row in lock['environments'].values()))
          +' transactions, '+str(len(references))+' unique archives',flush=True)
    downloaded={}
    def transfer(sha):
        raw=pool.stage/'downloads'/('conda-'+sha)
        actual=fetch(artifacts[sha]['url'],raw,sha=sha)
        if actual!=sha:raise RuntimeError('Conda lock download identity changed')
        return sha,raw
    if missing:
        workers=min(CONDA_LOCK_WORKERS,len(missing))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers,
                                                   thread_name_prefix='conda-lock') as executor:
            futures={executor.submit(transfer,sha):sha for sha in missing}
            for future in concurrent.futures.as_completed(futures):
                sha,raw=future.result();downloaded[sha]=raw
    # Pool's provenance dictionaries remain single-threaded. Only byte transfer
    # occurs concurrently; CAS registration and reference sharing are serialized.
    for sha in sorted(references):
        item=artifacts[sha];identities=sorted(references[sha])
        if sha in downloaded:
            raw=downloaded[sha]
            pool.put(raw,'conda',identities[0],verified_sha=sha)
            raw.unlink()
        for identity in identities:
            pool.download(item['url'],'conda',identity,sha=sha)
    plans={};base_python={}
    for env,row in sorted(lock['environments'].items()):
        keys=[]
        for transaction in row['transactions']:
            key=transaction['key'];keys.append(key)
            solution=[artifacts[sha] for sha in transaction['packages']]
            write_new(pool.stage/'metadata'/('conda-'+key+'.json'),
                      json.dumps(solution,sort_keys=True,separators=(',',':')))
        plans[env]=keys;base_python[env]=row['transactions'][0]['python']
    return plans,base_python


def conda_solution_python(resolved):
    """Return the major.minor Python actually selected by one Conda transaction."""
    rows=[row for row in resolved if _normalized_package_name(row.get('name',''))=='python']
    if len(rows)!=1:raise RuntimeError('Conda solution does not contain exactly one Python package')
    match=re.match(r'^(\d+)\.(\d+)',str(rows[0].get('version','')))
    if not match:raise RuntimeError('Conda solution has invalid Python version')
    return match.group(1)+'.'+match.group(2)


def apt_closure(pool,packages):
    """Signed Kali APT metadata; isolated empty package-status DB; download-only."""
    stage=pool.stage;apt=stage/'apt';apt.mkdir(exist_ok=True)
    for name in ('lists','archives','partial','sourceparts'):(apt/name).mkdir(exist_ok=True)
    (apt/'lists'/'partial').mkdir(exist_ok=True)
    (apt/'archives'/'partial').mkdir(exist_ok=True)
    key_sha = pool.download('https://archive.kali.org/archive-key.asc','apt','signing-key')
    key_path = pool.objects / key_sha[:2] / key_sha
    imported=invoke(['gpg','--show-keys','--with-colons',key_path],capture=True)
    if KALI_SIGNING_FPR not in [line.split(':')[9] for line in imported.splitlines() if line.startswith('fpr:')]:
        raise RuntimeError('Kali archive key fingerprint mismatch')
    ring=apt/'kali.gpg'
    with ring.open('xb') as dest:
        subprocess.run(['gpg','--dearmor'],input=key_path.read_bytes(),stdout=dest,check=True)
    sources=apt/'sources.list'
    write_new(sources,'deb [arch=amd64 signed-by='+str(ring)+'] https://http.kali.org/kali kali-last-snapshot main contrib non-free non-free-firmware\n')
    status=apt/'status';write_new(status,'')
    opts=['-o','Dir::Etc::sourcelist='+str(sources),'-o','Dir::Etc::sourceparts=-',
          '-o','Dir::State::Lists='+str(apt/'lists'),'-o','Dir::State::status='+str(status),
          '-o','Dir::Cache::Archives='+str(apt/'archives'),
          '-o','APT::Get::AllowUnauthenticated=false','-o','Acquire::AllowInsecureRepositories=false',
          '-o','APT::Architectures=amd64','-o','APT::Get::Assume-Yes=true']
    invoke(['apt-get',*opts,'update'])
    # Empty status DB means dependencies are resolved independently of Ubuntu host.
    invoke(['apt-get',*opts,'--download-only','--reinstall','-y','--no-remove','install',*sorted(packages)])
    debs=sorted((apt/'archives').glob('*.deb'))
    if not debs:raise RuntimeError('APT closure did not download any .deb')
    meta=[]
    for path in debs:
        control = subprocess.check_output(['dpkg-deb','-f',str(path)], text=True, timeout=90)
        fields = {}
        for field in ('Package','Version','Architecture'):
            found = re.search(r'^'+field+r':\s*(\S+)\s*$', control, flags=re.M)
            if not found: raise RuntimeError('APT archive missing '+field+': '+path.name)
            fields[field] = found.group(1)
        sha=pool.put(path,'apt','kali-last-snapshot')
        meta.append({'sha256':sha,'package':fields['Package'],
                     'version':fields['Version'], 'architecture':fields['Architecture']})
    write_new(stage/'metadata'/'apt-closure.json',json.dumps({'requested':sorted(packages),'resolved':meta},sort_keys=True))


def _packaging_symbols():
    """Use packaging if installed, otherwise pip's vendored copy already required here."""
    try:
        from packaging.markers import default_environment
        from packaging.requirements import Requirement
        from packaging.specifiers import SpecifierSet
        from packaging.version import Version, InvalidVersion
    except ImportError:
        from pip._vendor.packaging.markers import default_environment
        from pip._vendor.packaging.requirements import Requirement
        from pip._vendor.packaging.specifiers import SpecifierSet
        from pip._vendor.packaging.version import Version, InvalidVersion
    return Requirement, SpecifierSet, Version, InvalidVersion, default_environment


def _target_marker_environment(python_version):
    _,_,_,_,default_environment=_packaging_symbols()
    env=default_environment()
    version=str(python_version)
    if not re.fullmatch(r'\d+\.\d+(?:\.\d+)?',version):
        raise RuntimeError('invalid target Python version: '+version)
    short='.'.join(version.split('.')[:2])
    full=version if version.count('.')==2 else version+'.0'
    env.update({'python_version':short,'python_full_version':full,
                'implementation_name':'cpython','platform_python_implementation':'CPython',
                'sys_platform':'linux','platform_system':'Linux','platform_machine':'x86_64',
                'os_name':'posix'})
    return env


def _pypi_json(url, *, limit=16*1024*1024):
    raw=_read_https(url,timeout=90,limit=limit,user_agent='gpt-trace-dependency-pool/3',
                    expected_host='pypi.org')
    try:return json.loads(raw)
    except ValueError as exc:raise RuntimeError('invalid PyPI metadata JSON') from exc


def _constraint_specifiers(name, constraints, python_version):
    Requirement,_,_,_,_=_packaging_symbols()
    env=_target_marker_environment(python_version)
    result=[]
    normalized=_normalized_package_name(name)
    for row in constraints:
        try:req=Requirement(row)
        except Exception as exc:raise RuntimeError('invalid pip constraint: '+row) from exc
        if _normalized_package_name(req.name)!=normalized:continue
        if req.url:raise RuntimeError('URL constraints are unsupported for source fallback')
        if req.marker is not None and not req.marker.evaluate(env):continue
        result.append(req.specifier)
    return result


def _select_source_release(requirement, python_version, constraints=()):
    Requirement,SpecifierSet,Version,InvalidVersion,_=_packaging_symbols()
    try:req=Requirement(requirement)
    except Exception as exc:raise RuntimeError('invalid source fallback requirement: '+requirement) from exc
    if req.url:raise RuntimeError('source fallback does not accept URL requirements')
    env=_target_marker_environment(python_version)
    if req.marker is not None and not req.marker.evaluate(env):
        raise RuntimeError('source fallback selected an inactive marker: '+requirement)
    project=_pypi_json('https://pypi.org/pypi/'+urllib.parse.quote(req.name,safe='')+'/json')
    releases=project.get('releases')
    if not isinstance(releases,dict):raise RuntimeError('PyPI project has no releases: '+req.name)
    constraint_specs=_constraint_specifiers(req.name,constraints,python_version)
    target=Version(env['python_full_version'])
    candidates=[]
    for text,files in releases.items():
        try:version=Version(text)
        except InvalidVersion:continue
        if req.specifier and not req.specifier.contains(version,prereleases=None):continue
        if any(spec and not spec.contains(version,prereleases=None) for spec in constraint_specs):continue
        if not isinstance(files,list):continue
        source=[]
        for item in files:
            if not isinstance(item,dict) or item.get('packagetype')!='sdist' or item.get('yanked') is True:continue
            digests=item.get('digests') or {};sha=str(digests.get('sha256',''))
            if not SHA.fullmatch(sha):continue
            requires_python=item.get('requires_python')
            if requires_python:
                try:
                    if not SpecifierSet(str(requires_python)).contains(target,prereleases=True):continue
                except Exception:continue
            url=item.get('url')
            if not isinstance(url,str) or urllib.parse.urlsplit(url).hostname!='files.pythonhosted.org':continue
            filename=str(item.get('filename') or '')
            rank=0 if filename.endswith('.tar.gz') else 1 if filename.endswith('.zip') else 2
            source.append((rank,filename,item))
        if source:
            source.sort(key=lambda x:(x[0],x[1]))
            candidates.append((version,text,source[0][2]))
    if not candidates:
        raise RuntimeError('no compatible signed source distribution: '+requirement)
    candidates.sort(key=lambda row:row[0],reverse=True)
    _,version_text,item=candidates[0]
    return req,version_text,item


def _source_archive_files(path, filename):
    """Read only small root metadata/requirements files from a pinned source archive."""
    import tarfile
    import zipfile
    wanted={'PKG-INFO','setup.py','setup.cfg','pyproject.toml'}
    result={}
    def accept(rel,size):
        if len(rel.parts)!=2 or size>2*1024*1024:return False
        name=rel.name
        return (name in wanted or
                (name.lower().endswith('.txt') and re.fullmatch(r'[A-Za-z0-9_.-]*(?:requirements?|requires?)[A-Za-z0-9_.-]*\.txt',name,re.I)))
    if filename.endswith(('.tar.gz','.tar.bz2','.tar.xz','.tgz')):
        with tarfile.open(path,'r:*') as archive:
            for member in archive:
                rel=Path(member.name)
                if not member.isfile() or not accept(rel,member.size):continue
                stream=archive.extractfile(member)
                if stream is not None:result[rel.name]=stream.read(2*1024*1024+1)
    elif filename.endswith('.zip'):
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                rel=Path(name);info=archive.getinfo(name)
                if not accept(rel,info.file_size):continue
                result[rel.name]=archive.read(name)
    else:raise RuntimeError('unsupported source archive: '+filename)
    return result


def acquire_source_distribution(pool, requirement, plan_key, python_version, *, constraints=()):
    """Acquire one compatible PyPI sdist by SHA and inspect metadata statically."""
    import email.parser
    req,selected,item=_select_source_release(requirement,python_version,constraints)
    version_url='https://pypi.org/pypi/'+urllib.parse.quote(req.name,safe='')+'/'+urllib.parse.quote(selected,safe='')+'/json'
    metadata=_pypi_json(version_url)
    urls=metadata.get('urls') or []
    expected_sha=str((item.get('digests') or {}).get('sha256',''))
    exact=[row for row in urls if isinstance(row,dict) and row.get('packagetype')=='sdist'
           and str((row.get('digests') or {}).get('sha256',''))==expected_sha]
    if not exact:raise RuntimeError('selected PyPI source disappeared: '+requirement)
    source_item=sorted(exact,key=lambda row:str(row.get('filename','')))[0]
    url=source_item.get('url');filename=str(source_item.get('filename') or '')
    if urllib.parse.urlsplit(str(url)).hostname!='files.pythonhosted.org':
        raise RuntimeError('untrusted PyPI source archive host: '+str(url))
    sha=pool.download(url,'python-source',plan_key,sha=expected_sha)
    source=pool.objects/sha[:2]/sha
    candidates=_source_archive_files(source,filename)
    requirements=set();provides_extra=set()
    info=metadata.get('info') or {}
    requirements.update(info.get('requires_dist') or [])
    provides_extra.update(info.get('provides_extra') or [])
    if 'PKG-INFO' in candidates:
        parsed=email.parser.Parser().parsestr(candidates['PKG-INFO'].decode('utf-8',errors='replace'),headersonly=True)
        requirements.update(parsed.get_all('Requires-Dist') or [])
        provides_extra.update(parsed.get_all('Provides-Extra') or [])
    text_files={name:data.decode('utf-8',errors='replace') for name,data in candidates.items()}
    get_file=lambda name,required=False:text_files.get(Path(name).name)
    if 'setup.py' in text_files:
        deps,remote,issues=setup_requirements_from_sources(
            text_files['setup.py'],get_file,extras=set(req.extras),python_version=python_version)
        if remote:raise RuntimeError('sdist setup.py contains VCS dependency: '+requirement)
        if issues and not requirements:
            raise RuntimeError('cannot statically close source metadata for '+requirement+': '+'; '.join(issues))
        requirements.update(deps)
    if 'setup.cfg' in text_files:
        deps,issues=setup_cfg_static(text_files['setup.cfg'],extras=set(req.extras))
        if issues:raise RuntimeError('invalid source setup.cfg: '+repr(issues))
        requirements.update(deps)
    if 'pyproject.toml' in text_files:
        deps,remote,issues=static_project(text_files['pyproject.toml'],extra_groups=set(req.extras))
        if remote:raise RuntimeError('sdist pyproject contains VCS dependency: '+requirement)
        if issues:raise RuntimeError('dynamic source build requirements: '+repr(issues))
        requirements.update(deps)
    Requirement,_,_,_,_=_packaging_symbols()
    clean=[]
    for row in sorted(requirements):
        if not isinstance(row,str):raise RuntimeError('non-string source dependency: '+requirement)
        try:Requirement(row)
        except Exception as exc:raise RuntimeError('invalid source dependency metadata: '+row) from exc
        clean.append(row)
    extras=sorted(x for x in provides_extra|set(req.extras) if isinstance(x,str) and re.fullmatch(r'[A-Za-z0-9_.-]+',x))
    if not clean and not ({'setup.py','PKG-INFO','setup.cfg','pyproject.toml'}&text_files.keys()):
        raise RuntimeError('source archive has no inspectable dependency metadata')
    return {'name':info.get('name') or req.name,'version':selected,'requested':requirement,
            'filename':filename,'sha256':sha,'requirements':clean,'provides_extra':extras}


def acquire_pinned_sdist(pool, requirement, plan_key, python_version='3.10', *, constraints=()):
    """Backward-compatible exact-pin wrapper around the generic source resolver."""
    Requirement,_,_,_,_=_packaging_symbols()
    try:req=Requirement(requirement)
    except Exception as exc:raise RuntimeError('invalid pinned source requirement: '+requirement) from exc
    if len(list(req.specifier))!=1 or not str(req.specifier).startswith('==') or '*' in str(req.specifier):
        raise RuntimeError('sdist fallback requires an exact pinned version: '+requirement)
    return acquire_source_distribution(pool,requirement,plan_key,python_version,constraints=constraints)


def _write_resolver_stub(directory, source):
    """Create a metadata-only wheel used solely to let pip resolve around an sdist."""
    import zipfile
    name=str(source['name']);version=str(source['version'])
    wheel_name=re.sub(r'[-_.]+','_',name)
    wheel_version=re.sub(r'[-]+','_',version)
    dist_info=wheel_name+'-'+wheel_version+'.dist-info'
    path=Path(directory)/(wheel_name+'-'+wheel_version+'-py3-none-any.whl')
    metadata=['Metadata-Version: 2.1','Name: '+name,'Version: '+version]
    for extra in source.get('provides_extra',[]):metadata.append('Provides-Extra: '+extra)
    for requirement in source.get('requirements',[]):metadata.append('Requires-Dist: '+requirement)
    metadata.extend(['',''])
    wheel='Wheel-Version: 1.0\nGenerator: swegym-static-source-resolver\nRoot-Is-Purelib: true\nTag: py3-none-any\n'
    record=dist_info+'/METADATA,,\n'+dist_info+'/WHEEL,,\n'+dist_info+'/RECORD,,\n'
    with zipfile.ZipFile(path,'w',compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(dist_info+'/METADATA','\n'.join(metadata))
        archive.writestr(dist_info+'/WHEEL',wheel)
        archive.writestr(dist_info+'/RECORD',record)
    return path


def _pip_missing_requirement(output):
    patterns=(r'No matching distribution found for\s+([^\r\n]+)',
              r'Could not find a version that satisfies the requirement\s+(.+?)(?:\s+\(from versions:|\r?$)')
    for pattern in patterns:
        matches=re.findall(pattern,output,flags=re.M)
        if matches:
            value=matches[-1].strip()
            value=re.split(r'\s+\(from\s+',value,maxsplit=1)[0].strip()
            if value:return value
    return None


def pip_closure(pool, version, reqs, key, *, constraints=(), no_deps=False):
    if not reqs:return
    stage=pool.stage
    outfile=stage/'metadata'/('pip-'+key+'.txt')
    write_new(outfile,'\n'.join(sorted(reqs))+'\n')
    constraint_file=stage/'metadata'/('constraints-'+key+'.txt')
    if constraints:write_new(constraint_file,'\n'.join(sorted(constraints))+'\n')
    shared=stage/'wheels'/'shared';shared.mkdir(exist_ok=True)
    dest=stage/'wheels'/key;dest.mkdir()
    sources={};attempt=0
    with tempfile.TemporaryDirectory(prefix='swegym-pip-stubs-') as stub_tmp:
        stubdir=Path(stub_tmp);stub_names=set()
        while True:
            attempt+=1
            if attempt>33:raise RuntimeError('pip source fallback exceeded finite bound')
            for existing in list(dest.iterdir()):
                if existing.is_file() or existing.is_symlink():existing.unlink()
                elif existing.exists():raise RuntimeError('unexpected directory in pip destination')
            needed_file=stage/'metadata'/('binary-'+key+'-'+str(attempt)+'.txt')
            write_new(needed_file,'\n'.join(sorted(reqs))+'\n')
            command=[sys.executable,'-m','pip','download','--disable-pip-version-check',
                     '--no-cache-dir','--only-binary=:all:','--implementation','cp',
                     '--python-version',version,'--abi','cp'+version.replace('.',''),
                     '--platform','manylinux2014_x86_64','--find-links',str(shared),
                     '--find-links',str(stubdir),'--dest',str(dest),'-r',str(needed_file),
                     *(['--no-deps'] if no_deps else []),
                     *(['--constraint',str(constraint_file)] if constraints else [])]
            print('[pool]',' '.join(command),flush=True)
            result=subprocess.run(command,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            if result.returncode==0:break
            output=result.stdout or ''
            missing=_pip_missing_requirement(output)
            if not missing:
                tail=' | '.join(line.strip() for line in output.splitlines()[-8:] if line.strip())
                raise RuntimeError('pip binary dependency solve failed: '+tail[:1800])
            try:
                Requirement,_,_,_,_=_packaging_symbols();parsed=Requirement(missing)
            except Exception as exc:
                raise RuntimeError('pip reported an unparseable missing requirement: '+missing) from exc
            normalized=_normalized_package_name(parsed.name)
            if normalized in sources:
                tail=' | '.join(line.strip() for line in output.splitlines()[-8:] if line.strip())
                raise RuntimeError('pip still rejects statically stubbed source '+missing+': '+tail[:1200])
            source=acquire_source_distribution(pool,missing,key,version,constraints=constraints)
            stub=_write_resolver_stub(stubdir,source)
            stub_names.add(stub.name);sources[normalized]=source

        names=[]
        for file in sorted(dest.iterdir()):
            if file.name in stub_names:
                file.unlink();continue
            if not file.is_file() or file.is_symlink():raise RuntimeError('unsafe pip closure artifact')
            sha=pool.put(file,'python',key);pool.coalesce_stage_file(file,sha)
            common=shared/file.name
            if common.exists():
                if common.is_symlink() or not common.is_file():raise RuntimeError('unsafe wheelhouse entry')
                if not common.samefile(pool.objects/sha[:2]/sha):
                    raise RuntimeError('same wheel filename resolved to different bytes: '+file.name)
            else:os.link(pool.objects/sha[:2]/sha,common)
            names.append({'filename':file.name,'sha256':sha})
    source_rows=sorted(sources.values(),key=lambda row:(_normalized_package_name(row['name']),row['version']))
    if not names and not source_rows:raise RuntimeError('pip closure has no downloadable packages')
    write_new(stage/'metadata'/('pip-plan-'+key+'.json'),json.dumps({
        'python':version,'requested':sorted(reqs),'constraints':sorted(constraints),
        'no_deps':no_deps,'files':names,'source_archives':source_rows},sort_keys=True))

def npm_lock_urls(lock, label, *, workspace_checker=None):
    """Extract trusted registry tarballs from npm lockfile v1/v2/v3."""
    urls={}
    packages=lock.get('packages')
    dependencies=lock.get('dependencies')
    if isinstance(packages,dict) and packages:
        records=list(packages.values())
    elif isinstance(dependencies,dict):
        records=list(dependencies.values())
    else:
        raise RuntimeError('npm lockfile has no package records: '+label)
    for item in records:
        if not isinstance(item,dict) or not item.get('resolved'):
            continue
        url=item['resolved'];integ=item.get('integrity')
        if item.get('link') is True:
            if workspace_checker is None:
                raise RuntimeError('unexpected npm workspace link: '+label)
            workspace_checker(url)
            continue
        if (not isinstance(url,str) or not url.startswith('https://registry.npmjs.org/')
                or not isinstance(integ,str) or not integ):
            raise RuntimeError('npm package has no trusted registry source/SRI: '+label)
        if url in urls and urls[url] != integ:
            raise RuntimeError('conflicting npm lockfile integrity for '+url)
        urls[url]=integ
    return urls


def _npm_cli_metadata():
    """Fetch immutable-version npm registry metadata; never use the moving `latest` tag."""
    metadata_url='https://registry.npmjs.org/npm/'+NPM_NODE18_VERSION
    raw=_read_https(metadata_url,timeout=90,limit=4*1024*1024,
                    user_agent='gpt-trace-dependency-pool/3',expected_host='registry.npmjs.org')
    try:info=json.loads(raw)
    except ValueError as exc:raise RuntimeError('invalid npm CLI metadata') from exc
    if info.get('version')!=NPM_NODE18_VERSION:
        raise RuntimeError('npm registry returned unexpected CLI version')
    engine=(info.get('engines') or {}).get('node')
    if not isinstance(engine,str) or '18.17.0' not in engine:
        raise RuntimeError('pinned npm CLI no longer advertises Node 18.17 compatibility')
    dist=info.get('dist') or {};tarball,sri=dist.get('tarball'),dist.get('integrity')
    if (not isinstance(tarball,str) or
            not tarball.startswith('https://registry.npmjs.org/npm/-/npm-'+NPM_NODE18_VERSION)):
        raise RuntimeError('untrusted npm CLI archive')
    if not isinstance(sri,str) or not sri:raise RuntimeError('npm CLI lacks SRI')
    return {'version':NPM_NODE18_VERSION,'engine':engine,'url':tarball,'integrity':sri}


def npm_cli_artifact(pool, category, identity):
    """Acquire the one pinned npm CLI tarball and register per-use provenance."""
    metadata_path=pool.stage/'metadata'/'npm-cli.json'
    if metadata_path.exists():
        try:meta=json.loads(metadata_path.read_bytes())
        except ValueError as exc:raise RuntimeError('invalid retained npm CLI metadata') from exc
        if (meta.get('version')!=NPM_NODE18_VERSION or not isinstance(meta.get('url'),str)
                or not isinstance(meta.get('integrity'),str)):
            raise RuntimeError('retained npm CLI metadata does not match pin')
    else:
        meta=_npm_cli_metadata()
    sha=pool.download(meta['url'],category,identity,sri=meta['integrity'])
    if metadata_path.exists():
        if meta.get('sha256')!=sha:raise RuntimeError('retained npm CLI CAS identity changed')
    else:
        meta={**meta,'sha256':sha}
        write_new(metadata_path,json.dumps(meta,sort_keys=True))
    return sha,meta


def _run_pinned_npm(pool, args, *, cwd, env, timeout=1800):
    """Run npm 10.9.9 from its verified tarball; host npm version is irrelevant."""
    import tarfile
    sha,_=npm_cli_artifact(pool,'npm-resolver-cli','npm-'+NPM_NODE18_VERSION)
    archive_path=pool.objects/sha[:2]/sha
    node=shutil.which('node')
    if not node:raise RuntimeError('Node.js executable missing on fetch host')
    version_text=invoke([node,'--version'],capture=True).strip()
    match=re.fullmatch(r'v(\d+)\.(\d+)\.(\d+)',version_text)
    if not match:raise RuntimeError('unrecognized Node.js version: '+version_text)
    major,minor,_patch=map(int,match.groups())
    if major<18 or (major==18 and minor<17):
        raise RuntimeError('pinned npm resolver requires Node >=18.17')
    with tempfile.TemporaryDirectory(prefix='swegym-npm-cli-') as temp:
        root=Path(temp)
        total=0
        with tarfile.open(archive_path,'r:*') as archive:
            for member in archive:
                rel=Path(member.name)
                if (rel.is_absolute() or '..' in rel.parts or '\\' in member.name
                        or member.issym() or member.islnk() or member.isdev()):
                    raise RuntimeError('unsafe entry in pinned npm CLI archive')
                if member.isfile():
                    total+=member.size
                    if member.size>16*1024*1024 or total>128*1024*1024:
                        raise RuntimeError('oversized pinned npm CLI archive')
            archive.extractall(root)
        cli=root/'package'/'bin'/'npm-cli.js'
        if cli.is_symlink() or not cli.is_file():raise RuntimeError('npm CLI archive lacks npm-cli.js')
        return invoke([node,str(cli),*args],cwd=cwd,env=env,timeout=timeout)


def npm_package_json_closure(pool, mirror, commit, repo_ref, identity):
    """Resolve a pinned VCS package.json with pinned npm; never run package scripts."""
    package_text=git_file(mirror,commit,'js/package.json') or git_file(mirror,commit,'package.json')
    if not package_text:raise RuntimeError('npm-backed VCS source lacks package.json: '+repo_ref)
    try:package=json.loads(package_text)
    except ValueError as exc:raise RuntimeError('invalid VCS package.json: '+repo_ref) from exc
    for table in ('dependencies','devDependencies'):
        value=package.get(table,{})
        if value is not None and not isinstance(value,dict):
            raise RuntimeError('invalid npm dependency table in '+repo_ref)
        for name,spec in (value or {}).items():
            if not isinstance(name,str) or not isinstance(spec,str):
                raise RuntimeError('non-string npm dependency in '+repo_ref)
            if spec.startswith(('git','http:','https:','file:','link:','workspace:')):
                raise RuntimeError('non-registry npm dependency requires explicit pin: '+name)
    key=hashlib.sha256((repo_ref+'\0'+commit+'\0'+identity).encode()).hexdigest()[:20]
    work=pool.stage/'npm'/('resolve-'+key);work.mkdir()
    write_new(work/'package.json',json.dumps(package,sort_keys=True,indent=2)+'\n')
    cache=work/'cache';env=dict(os.environ)
    env.update({'npm_config_cache':str(cache),'npm_config_registry':'https://registry.npmjs.org/',
                'npm_config_audit':'false','npm_config_fund':'false','npm_config_ignore_scripts':'true'})
    _run_pinned_npm(pool,['install','--package-lock-only','--ignore-scripts','--no-audit','--no-fund',
                          '--registry=https://registry.npmjs.org/'],cwd=work,env=env,timeout=1800)
    if (work/'node_modules').exists():raise RuntimeError('npm resolver unexpectedly installed node_modules')
    lock_path=work/'package-lock.json'
    if lock_path.is_symlink() or not lock_path.is_file():raise RuntimeError('npm resolver produced no lockfile')
    lock=json.loads(lock_path.read_bytes());urls=npm_lock_urls(lock,repo_ref)
    if not urls:raise RuntimeError('npm resolver produced empty archive closure: '+repo_ref)
    artifacts=[]
    for url,sri in sorted(urls.items()):
        sha=pool.download(url,'npm-vcs',identity,sri=sri)
        artifacts.append({'url':url,'integrity':sri,'sha256':sha})
    write_new(pool.stage/'metadata'/('npm-vcs-'+key+'.json'),json.dumps({
        'repo':repo_ref,'commit':commit,'identity':identity,
        'resolver_npm':NPM_NODE18_VERSION,
        'package_sha256':hashlib.sha256(package_text.encode()).hexdigest(),
        'lockfile':lock,'artifacts':artifacts},sort_keys=True))
    shutil.rmtree(work)
    return artifacts


def npm_global_bootstrap(pool):
    """Freeze the exact npm CLI used by the benchmark's global npm upgrade."""
    sha,meta=npm_cli_artifact(pool,'npm-global-cli','npm')
    path=pool.stage/'metadata'/'npm-global.json'
    if not path.exists():
        write_new(path,json.dumps({'version':meta['version'],'url':meta['url'],
                                   'sha256':sha,'integrity':meta['integrity']},sort_keys=True))

def audit_inventory(pool,task_plan,envplan,gitplan,operation_id, *, contract_tasks=None,
                    conda_transactions=None,conda_lock_sha256=None):
    stage=pool.stage
    files=[];seen_inodes={}
    for path in sorted(stage.rglob('*')):
        if path.is_symlink():
            raise RuntimeError('symlink in dependency pool: '+str(path))
        if not path.is_file():continue
        rel=path.relative_to(stage).as_posix()
        info=path.stat();identity=(info.st_dev,info.st_ino)
        if identity in seen_inodes:
            row={'path':rel,'size':info.st_size,'sha256':seen_inodes[identity]}
        else:
            row={'path':rel,'size':info.st_size,'sha256':digest(path)}
            seen_inodes[identity]=row['sha256']
        files.append(row)

    file_digests={entry['path']:entry['sha256'] for entry in files}

    def reject(label,detail):
        pool.issue('inventory:'+label,detail)

    if not pool.links:reject('CAS','no acquired content-addressed objects')
    if len(task_plan)!=230 or len(envplan)!=25 or len(gitplan)!=11:
        reject('contract','unexpected 230/25/11 contract coverage')
    for kind in ('conda','git','apt'):
        if not pool.provenance.get(kind):
            reject('provenance','no acquired '+kind+' artifacts')
    for sha,row in pool.links.items():
        if not SHA.fullmatch(sha) or row.get('sha256')!=sha:
            reject('CAS','invalid object identity '+str(sha));continue
        expected='objects/sha256/'+sha[:2]+'/'+sha
        target=stage/expected
        if (row.get('path')!=expected or not target.is_file() or target.is_symlink()
                or type(row.get('size')) is not int or target.stat().st_size!=row['size']
                or file_digests.get(expected)!=sha):
            reject('CAS','missing/bad object '+sha)
    for category,groups_ in pool.provenance.items():
        for identity,digests in groups_.items():
            if not isinstance(digests,list) or not digests:
                reject(category,'empty artifact provenance '+identity);continue
            for sha in digests:
                if sha not in pool.links:reject(category,'unregistered artifact '+sha)

    if contract_tasks is not None and set(task_plan)!=set(contract_tasks):
        reject('tasks','missing or extra task identity')

    def validate_pip(logical,key,*,optional):
        metadata=stage/'metadata'/('pip-plan-'+key+'.json')
        if not metadata.is_file():
            reject(logical,('missing optional ' if optional else 'missing ')+'pip closure '+key)
            return
        try:
            closure=json.loads(metadata.read_bytes())
            failed=closure.get('optional_failed')
            if failed:
                if not optional or not isinstance(failed,str):
                    raise ValueError('failure marker on required closure')
                return
            if not closure.get('files') and not closure.get('source_archives'):
                raise ValueError('empty closure')
            for artifact in closure.get('files',[]):
                if artifact.get('sha256') not in pool.links:
                    raise ValueError('unregistered wheel '+str(artifact))
            for artifact in closure.get('source_archives',[]):
                if artifact.get('sha256') not in pool.links:
                    raise ValueError('unregistered source '+str(artifact))
        except (ValueError,TypeError,KeyError) as exc:
            reject(logical,'invalid pip closure '+key+': '+str(exc))

    for logical,plan in task_plan.items():
        if contract_tasks is not None and logical in contract_tasks:
            expected=contract_tasks[logical]
            if (plan.get('repo')!=expected['repo'] or plan.get('base_commit')!=expected['base_commit']
                    or plan.get('env_hash')!=expected['env_hash']):
                reject(logical,'task identity diverges from pinned contract')
        repo,commit,env=plan.get('repo'),plan.get('base_commit'),plan.get('env_hash')
        if (repo not in gitplan or commit not in gitplan[repo].get('commits',[])
                or env not in envplan or plan.get('python')!=envplan[env]):
            reject(logical,'unresolved repo/commit/Conda environment')
        primary=plan.get('pip_plan')
        if primary is not None and primary not in plan.get('pip_steps',[]):
            reject(logical,'primary pip closure is not referenced by pip_steps')
        for key in plan.get('pip_steps',[]):validate_pip(logical,key,optional=False)
        for key in plan.get('environment_pip_steps',[]):validate_pip(logical,key,optional=False)
        for key in plan.get('pip_optional_steps',[]):validate_pip(logical,key,optional=True)

    if conda_transactions is None:
        conda_transactions={env:['env-'+env] for env in envplan}
    if set(conda_transactions)!=set(envplan):
        reject('Conda','transaction plan does not cover all environments')
    conda_keys=[]
    for env in envplan:
        keys=conda_transactions.get(env)
        if not isinstance(keys,list) or not keys or keys[-1]!='env-'+env:
            reject(env,'invalid Conda transaction sequence');continue
        conda_keys.extend(keys)
    for key in dict.fromkeys(conda_keys):
        metadata=stage/'metadata'/('conda-'+key+'.json')
        if not metadata.is_file():
            reject(key,'missing Conda solution');continue
        try:
            solution=json.loads(metadata.read_bytes())
            if not isinstance(solution,list) or not solution:
                raise ValueError('empty Conda package list')
            for artifact in solution:
                if artifact.get('sha256') not in pool.links or not artifact.get('url'):
                    raise ValueError('Conda archive not acquired')
        except (ValueError,TypeError,AttributeError) as exc:
            reject(key,'invalid Conda solution: '+str(exc))
    for logical,plan in task_plan.items():
        if not plan.get('environment_pip_steps'):continue
        env=plan.get('env_hash');keys=conda_transactions.get(env) or []
        if not keys:
            reject(logical,'environment pip phase has no base Conda transaction');continue
        try:
            base=json.loads((stage/'metadata'/('conda-'+keys[0]+'.json')).read_bytes())
            actual=conda_solution_python(base)
            if plan.get('environment_pip_python')!=actual:
                raise ValueError('environment pip interpreter does not match base Conda solve')
        except (OSError,ValueError,TypeError,RuntimeError) as exc:
            reject(logical,'invalid environment pip phase: '+str(exc))

    apt_path=stage/'metadata'/'apt-closure.json'
    try:
        apt=json.loads(apt_path.read_bytes())
        if not apt.get('requested') or not apt.get('resolved'):
            raise ValueError('empty APT package resolution')
        for item in apt['resolved']:
            if (item.get('sha256') not in pool.links or not item.get('package')
                    or not item.get('version') or item.get('architecture') not in ('all','amd64')):
                raise ValueError('incomplete/bad APT archive metadata')
    except (OSError,ValueError,TypeError,AttributeError) as exc:
        reject('APT','missing/bad signed Kali closure: '+str(exc))

    # `apt-get upgrade` in upstream setup is deliberately not replayed against
    # the immutable Golden. Make the suppression explicit and contract-checked
    # rather than silently pretending an empty-status APT solve covers upgrades.
    try:
        policy=json.loads((stage/'metadata'/'apt-policy.json').read_bytes())
        flagged={logical for logical,plan in task_plan.items() if plan.get('apt_upgrade_suppressed') is True}
        expected=set()
        if contract_tasks is not None:
            for logical,task in contract_tasks.items():
                _,upgrades=apt_recipe_operations(task.get('repo_script_list',[]))
                if upgrades:expected.add(logical)
        if (policy.get('schema')!=1 or policy.get('upgrade_policy')!='suppress-on-frozen-golden'
                or set(policy.get('suppressed_tasks',[]))!=flagged
                or (contract_tasks is not None and flagged!=expected)):
            raise ValueError('APT upgrade suppression does not match pinned recipes')
    except (OSError,ValueError,TypeError) as exc:
        reject('APT-policy','missing/bad frozen-Golden upgrade policy: '+str(exc))

    frozen_path=stage/'metadata'/'vcs-frozen.json'
    try:
        frozen=json.loads(frozen_path.read_bytes())
        if not isinstance(frozen,dict):
            raise ValueError('VCS manifest is not a mapping')
        for ref,commit in frozen.items():
            if not isinstance(ref,str) or not isinstance(commit,str) or not COMMIT.fullmatch(commit):
                raise ValueError('invalid frozen VCS entry')
        for logical,plan in task_plan.items():
            for ref in plan.get('vcs',[]):
                if ref not in frozen:
                    reject(logical,'VCS source not frozen: '+ref)
    except (OSError,ValueError,TypeError) as exc:
        reject('VCS','missing/bad VCS pin manifest: '+str(exc))

    try:
        optional_failures=json.loads((stage/'metadata'/'vcs-optional-failures.json').read_bytes())
        required_refs={ref for plan in task_plan.values() for ref in plan.get('vcs',[])}
        optional_refs={ref for plan in task_plan.values() for ref in plan.get('optional_vcs',[])}
        if not isinstance(optional_failures,dict):
            raise ValueError('optional VCS failures are not a mapping')
        if any(ref in required_refs or ref not in optional_refs for ref in optional_failures):
            raise ValueError('required/unknown VCS source marked optional')
    except (OSError,ValueError,TypeError) as exc:
        reject('VCS-optional','bad optional VCS failure manifest: '+str(exc))

    if any('modin-project/modin-spreadsheet' in ref
           for plan in task_plan.values() for ref in plan.get('vcs',[])):
        if not pool.provenance.get('npm-vcs'):
            reject('npm-vcs','modin-spreadsheet JavaScript build closure missing')

    issues=sorted(set(pool.issues))
    summary={'schema':2,'kind':'download-only-pool','complete':not issues,
             'operation_id':operation_id,'tasks':len(task_plan),'repos':len(gitplan),
             'conda_recipes':len(envplan),'python_versions':list(PYTHONS),
             'files':files,'issues':issues,'objects':pool.links,
             'provenance':pool.provenance,'task_plan':task_plan,
             'environment_plan':envplan,'conda_transactions':conda_transactions,
             'conda_lock_sha256':conda_lock_sha256,'git_plan':gitplan}
    write_new(stage/'inventory.json',json.dumps(summary,sort_keys=True,indent=2)+'\n')
    print('[pool] objects=',len(pool.links),'files=',len(files),'issues=',len(issues),flush=True)
    if issues:raise RuntimeError('incomplete dependency closure: '+issues[0]+
                                 '; inspect inventory.json; a later explicit fetch can reuse verified artifacts')
    return summary


def main(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument('--repo-root',required=True,type=Path)
    p.add_argument('--stage',required=True,type=Path)
    p.add_argument('--operation-id',required=True)
    p.add_argument('--reuse-from',type=Path)
    args=p.parse_args(argv)
    if os.geteuid()==0:raise RuntimeError('refusing privileged fetch account')
    if not SHA.fullmatch(args.operation_id):raise RuntimeError('invalid operation ID')
    if args.stage.exists() or args.stage.is_symlink():raise RuntimeError('candidate stage already exists; refusing overwrite')
    repo_root=args.repo_root.resolve(strict=True)
    adapter=repo_root/'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym'
    pins=json.loads((adapter/'pins.json').read_bytes())
    if digest(adapter/'contract.json')!=pins['contract_sha256']:
        raise RuntimeError('pinned SWE-Gym Lite contract changed')
    contract=json.loads((adapter/'contract.json').read_bytes())
    conda_lock,conda_lock_sha256=load_conda_lock(adapter,pins,contract)
    tasks=contract['tasks'];environments=contract['environments']
    if len(tasks)!=230 or len(environments)!=25 or len({r['repo'] for r in tasks.values()})!=11:
        raise RuntimeError('unexpected SWE-Gym Lite coverage')
    stage=args.stage
    stage.mkdir(mode=0o700)
    for name in ('git','git-extra','conda','wheels','metadata','downloads','npm','apt','objects'):
        (stage/name).mkdir(exist_ok=True)
    write_new(stage/'STAGING','Uncommitted, verified-resumable dependency acquisition.\n')
    verified=set()
    if args.reuse_from is not None:
        verified=salvage_verified_stage(args.reuse_from,stage)
    pool=Pool(stage)
    pool.verified_objects.update(verified)
    grouped=defaultdict(set)
    for task in tasks.values():grouped[task['repo']].add(task['base_commit'])
    mirrors={};gitplan={}
    for i,(repo,commits) in enumerate(sorted(grouped.items()),1):
        print(f'[pool] Git {i}/11: {repo} ({len(commits)} pinned commits)',flush=True)
        mirror=mirror_commits(stage,repo,commits)
        mirrors[repo]=mirror
        gitplan[repo]={'commits':sorted(commits),'submodules':{}}
    for repo,commits in sorted(grouped.items()):
        for commit in sorted(commits):
            # Only gitlinks required by an actual repository setup are in scope.
            if repo=='python/mypy':
                for path,subrepo,sha in read_submodules(mirrors[repo],commit):
                    if path=='mypy/typeshed':
                        gitplan[repo]['submodules'][path]={'repo':subrepo,'commit':sha}
                        ensure_commit(stage,subrepo,sha,label='git-extra')
    # Git files must not be linked to CAS while Git may still mutate refs.
    envplan={};requirements_by_env=defaultdict(set);vcs=set()
    vcs_by_env=defaultdict(set);environment_pip_python={}
    conda_transaction_plan,locked_base_python=acquire_locked_conda(pool,conda_lock)
    for i,(env,entry) in enumerate(sorted(environments.items()),1):
        script=entry['original_script']
        version=python_version(script);envplan[env]=version
        locked=conda_lock['environments'][env]
        if locked['transactions'][-1]['python']!=version:
            raise RuntimeError('locked final Python differs from environment recipe: '+env)
        content=conda_yaml(script)
        pips=[]
        print(f'[pool] Conda lock {i}/25, final Python {version}',flush=True)
        if content:
            _,pips=conda_pip_split(content)
            # The official upstream Dask recipe removes the pip section before
            # Conda sees it. Do not fetch packages from instructions it deletes.
            if any("sed -i '/- pip:/,/^ *-/d' environment.yml" in command
                   for command in script):
                pips=[]
            if conda_expected_transaction_keys(env,script)!=conda_transaction_plan[env]:
                raise RuntimeError('locked Conda transaction shape differs: '+env)
            if pips:
                environment_pip_python[env]=locked_base_python[env]
        else:
            direct=conda_direct_specs(script)
            if not direct:
                raise RuntimeError('environment has neither YAML nor direct Conda create: '+env)
            if conda_transaction_plan[env]!=['env-'+env]:
                raise RuntimeError('direct Conda environment has unexpected locked transactions: '+env)
        for dep in pips:
            if not dep or dep.startswith('#'):continue
            if vcs_reference(dep):
                canonical=vcs_reference(dep)
                vcs.add(canonical)
                vcs_by_env[env].add(canonical)
            else:requirements_by_env[env].add(dep)
    # Trusted, pinned upstream spec table contains the evaluator prelude only.
    constants_file=adapter/'upstream'/'constants.py'
    if digest(constants_file)!=pins['upstream_files']['constants.py']:
        raise RuntimeError('untrusted evaluator setup constants')
    import importlib.util
    spec=importlib.util.spec_from_file_location('swe_gym_fetch_specs',constants_file)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    specs_table=module.MAP_REPO_VERSION_TO_SPECS
    task_plan={};groups={};apt_requested=set();apt_upgrade_tasks=set()
    for index,(logical,task) in enumerate(sorted(tasks.items()),1):
        repo=task['repo'];commit=task['base_commit'];mirror=mirrors[repo]
        version=envplan[task['env_hash']]
        commands=list(task['repo_script_list'])
        spec=specs_table[repo.lower()][task['version']]
        # Installation-relevant evaluator commands are public pinned spec data;
        # no patch, oracle, test command or private evaluator material is exported.
        commands.extend(spec.get('eval_commands',[]))
        for package in spec.get('pip_packages',[]):commands.append('pip install '+package)
        get_file = lambda path,required=False: transformed_source(
            repo, path, git_file(mirror,commit,path,required=required), commands)
        for command in list(commands):
            for match in re.finditer(r'(?<![\w-])make\s+(init|install)\b',command):
                try:
                    makefile=get_file('Makefile',required=True)
                    commands.extend(make_commands(makefile,match.group(1)))
                except (ValueError,RuntimeError) as exc:pool.issue(logical,str(exc))
        env_hash=task['env_hash'];env_pip_version=environment_pip_python.get(env_hash,version)
        env_requirements=set(requirements_by_env[env_hash]);env_vcs=set(vcs_by_env[env_hash])
        reqs=set();vcs_task=set();vcs_optional=set()
        explicit,reqfiles,_external,problems,extras,constraint_files,steps=pip_commands(commands)
        inline_constraints = set()
        for command in commands:
            if 'PIP_CONSTRAINT' in command:
                inline_constraints.update(re.findall(
                    r"echo\s+['\"]([A-Za-z0-9_.-]+[<>=!~][^'\"]+)['\"]\s*>", command))
        for problem in problems:pool.issue(logical,problem)
        # Project metadata is read at the pinned commit and after the recipe's
        # explicitly supported textual transformations.
        raw=get_file('pyproject.toml')
        if raw:
            try:
                dep,git,problem=static_project(raw,extra_groups=extras)
                reqs.update(dep);vcs_task.update(git)
                for ptext in problem:pool.issue(logical,ptext)
            except (ValueError,TypeError) as exc:pool.issue(logical,'invalid pyproject.toml: '+str(exc))
        cfg_deps,cfg_problems=setup_cfg_static(get_file('setup.cfg'),extras=extras)
        reqs.update(cfg_deps)
        for ptext in cfg_problems:pool.issue(logical,ptext)
        setup=get_file('setup.py')
        deps,remote,problems=setup_requirements_from_sources(
            setup,get_file,extras=extras,python_version=version)
        reqs.update(deps); vcs_task.update(remote)
        for ptext in problems:pool.issue(logical,ptext)

        task_steps=[];environment_steps=[];optional_steps=[];optional_skips=[]
        def register(req, constraints, name, *, no_deps=False, optional=False,
                     resolver_version=None, bucket='task'):
            if not req:return None
            selected_version=resolver_version or version
            key=hashlib.sha256(json.dumps(
                [selected_version,sorted(req),sorted(constraints),no_deps,optional],
                sort_keys=True).encode()).hexdigest()[:20]
            group=groups.setdefault(key,{'version':selected_version,'requirements':sorted(req),
                                          'constraints':sorted(constraints),'no_deps':no_deps,
                                          'optional':optional,'tasks':[],'steps':[]})
            if logical not in group['tasks']:group['tasks'].append(logical)
            group['steps'].append(name)
            if optional:optional_steps.append(key)
            elif bucket=='environment':environment_steps.append(key)
            else:task_steps.append(key)
            return key

        # `pip:` entries embedded in environment.yml execute during the base
        # Conda transaction, not after a later Python override.
        register(env_requirements,set(),'conda-environment-pip',
                 resolver_version=env_pip_version,bucket='environment')

        for step in steps:
            dependencies=set(step['requirements']);step_constraints=set(inline_constraints)
            step_vcs=set(step['vcs']);skip=False
            for filename in sorted(step['files']):
                try:
                    source=get_file(filename,required=not step['optional'])
                    if source is None and step['optional']:
                        optional_skips.append(step['command']+' [missing '+filename+']')
                        skip=True;break
                    a,b,c=parse_requirements(source,filename,get_file)
                    dependencies.update(a);step_vcs.update(b);step_constraints.update(c)
                except (ValueError,RuntimeError) as exc:
                    if step['optional']:
                        optional_skips.append(step['command']+' ['+str(exc)+']')
                        skip=True;break
                    pool.issue(logical,str(exc))
            if skip: continue
            for filename in sorted(step['constraints']):
                try:
                    source=get_file(filename,required=not step['optional'])
                    if source is None and step['optional']:
                        optional_skips.append(step['command']+' [missing '+filename+']')
                        skip=True;break
                    a,b,c=parse_requirements(source,filename,get_file,constraint=True)
                    if a or b:raise RuntimeError('constraints incorrectly contain install targets')
                    step_constraints.update(c)
                except (ValueError,RuntimeError) as exc:
                    if step['optional']:
                        optional_skips.append(step['command']+' ['+str(exc)+']')
                        skip=True;break
                    pool.issue(logical,str(exc))
            if skip: continue
            (vcs_optional if step['optional'] else vcs_task).update(step_vcs)
            # Local editable/develop is a separate installation against the
            # static package metadata. Remote VCS input is fetched separately.
            if step['local_extras'] or re.search(r'(^|\s)(?:-e|--editable|-ve|-ev)\s+\.',step['command']):
                if not step['no_deps']:
                    dependencies.update(reqs)
            register(dependencies,step_constraints,step['command'],
                     no_deps=step['no_deps'],optional=step['optional'])

        try:
            packages,upgrades=apt_recipe_operations(commands)
            apt_requested.update(packages)
            if upgrades:apt_upgrade_tasks.add(logical)
        except RuntimeError as exc:
            pool.issue(logical,str(exc))
        for command in commands:
            for match in re.finditer(r'\bpipx\s+install\s+([\w.-]+)',command):
                # pipx creates its application venv from Kali's system Python,
                # not from the active historical Conda testbed interpreter.
                register({match.group(1)},set(),'pipx-application',
                         resolver_version=GOLDEN_SYSTEM_PYTHON)
            if re.search(r'\bpdm\s+add\s+pre-commit',command):
                register({'pre-commit'},set(),'pdm-add')
            if re.search(r'\b(?:curl|wget)\b\s+https?://',command):
                pool.issue(logical,'shell download needs explicit pinned hash: '+command[:90])

        primary=register(reqs,set(),'declarative-project-metadata')
        normalized_vcs={vcs_reference(item) or item for item in vcs_task}
        normalized_env_vcs={vcs_reference(item) or item for item in env_vcs}
        normalized_optional={vcs_reference(item) or item for item in vcs_optional}
        required_vcs=normalized_vcs|normalized_env_vcs
        vcs_versions={}
        for ref in sorted(normalized_vcs):vcs_versions.setdefault(ref,set()).add(version)
        for ref in sorted(normalized_env_vcs):vcs_versions.setdefault(ref,set()).add(env_pip_version)
        for ref in sorted(normalized_optional):vcs_versions.setdefault(ref,set()).add(version)
        task_plan[logical]={'repo':repo,'base_commit':commit,'env_hash':task['env_hash'],
                            'python':version,'environment_pip_python':env_pip_version,
                            'pip_plan':primary,'pip_steps':task_steps,
                            'environment_pip_steps':environment_steps,
                            'pip_optional_steps':optional_steps,
                            'pip_optional_skips':optional_skips,
                            'vcs':sorted(required_vcs),
                            'optional_vcs':sorted(normalized_optional),
                            'vcs_python_versions':{ref:sorted(values) for ref,values in sorted(vcs_versions.items())},
                            # Frozen Golden policy: official blanket upgrades are
                            # suppressed during eventual offline replay. Explicit
                            # apt-get install packages are still acquired below.
                            'apt_upgrade_suppressed':logical in apt_upgrade_tasks}
        vcs.update(required_vcs);vcs.update(normalized_optional)
        if index%25==0:print(f'[pool] Static task recipes {index}/230',flush=True)

    write_new(stage/'metadata'/'apt-policy.json',json.dumps({
        'schema':1,'upgrade_policy':'suppress-on-frozen-golden',
        'suppressed_tasks':sorted(apt_upgrade_tasks),
        'requested_install_packages':sorted(apt_requested)},sort_keys=True,indent=2)+'\n')

    # Reject known-invalid pinned metadata BEFORE costly pip / VCS / npm / APT downloads.
    if pool.issues:
        write_new(stage/'metadata'/'static-errors.json', json.dumps(sorted(set(pool.issues)), indent=2))
        raise RuntimeError('static dependency closure rejected before network resolution: '+pool.issues[0])
    for key,group in sorted(groups.items()):
        try:
            pip_closure(pool,group['version'],group['requirements'],key,
                        constraints=group['constraints'],no_deps=group['no_deps'])
        except (subprocess.CalledProcessError,RuntimeError) as exc:
            if group['optional']:
                write_new(stage/'metadata'/('pip-plan-'+key+'.json'),json.dumps({
                    'python':group['version'],'requested':group['requirements'],
                    'constraints':group['constraints'],'no_deps':group['no_deps'],
                    'optional_failed':str(exc),'files':[],'source_archives':[]},sort_keys=True))
            else:
                pool.issue('pip:'+key,'dependency solve unavailable: '+str(exc))
    # Pin VCS inputs, resolve metadata from pyproject/setup.cfg/setup.py, and
    # propagate nested VCS references only to tasks that depend on them.
    vcs_frozen={};vcs_optional_failures={}
    vcs_required_tasks=defaultdict(set);vcs_optional_tasks=defaultdict(set)
    for logical,plan in task_plan.items():
        for value in plan['vcs']:vcs_required_tasks[value].add(logical)
        for value in plan.get('optional_vcs',[]):vcs_optional_tasks[value].add(logical)
    pending=set(vcs)
    while pending:
        if len(vcs_frozen) + len(pending) > 256:
            raise RuntimeError('VCS closure exceeds the audited finite bound')
        value=sorted(pending)[0];pending.remove(value)
        if value in vcs_frozen:continue
        required=bool(vcs_required_tasks[value])
        def vcs_failure(detail):
            if required:pool.issue('VCS:'+value,detail)
            else:vcs_optional_failures[value]=detail
        canonical=vcs_reference(value)
        if canonical is None:
            vcs_failure('unrecognized Git reference');continue
        raw=canonical.removeprefix('git+').split('#',1)[0]
        parsed=urllib.parse.urlsplit(raw)
        repo_ref=parsed.path.strip('/')
        pinned=None
        if '@' in repo_ref:repo_ref,pinned=repo_ref.rsplit('@',1)
        repo_ref=repo_ref.removesuffix('.git')
        if parsed.scheme!='https' or parsed.hostname!='github.com' or not REPO.fullmatch(repo_ref):
            vcs_failure('unsupported source');continue
        if pinned and not COMMIT.fullmatch(pinned):
            if not re.fullmatch(r'[a-f0-9]{7,39}',pinned):
                vcs_failure('unresolved Git ref');continue
            api='https://api.github.com/repos/'+repo_ref+'/commits/'+pinned
            try:
                response=json.loads(_read_https(api,timeout=60,limit=1048576,
                    user_agent='gpt-trace-dependency-pool/2',expected_host='api.github.com'))
                resolved=response.get('sha')
                if not isinstance(resolved,str) or not COMMIT.fullmatch(resolved) or not resolved.startswith(pinned):
                    raise ValueError('GitHub returned a different commit identity')
                pinned=resolved
            except (OSError,ValueError) as exc:
                vcs_failure('unable to freeze abbreviated Git reference: '+str(exc));continue
        if not pinned:
            try:
                ref=invoke(['git','ls-remote','https://github.com/'+repo_ref+'.git','HEAD'],capture=True)
            except (RuntimeError,subprocess.CalledProcessError) as exc:
                vcs_failure('HEAD lookup failed: '+str(exc));continue
            match=re.fullmatch(r'([a-f0-9]{40})\s+HEAD\s*',ref)
            if not match:
                vcs_failure('HEAD could not be frozen');continue
            pinned=match.group(1)
        try:
            folder=ensure_commit(stage,repo_ref,pinned,label='git-extra')
            required_dependants=set(vcs_required_tasks[value])
            optional_dependants=set(vcs_optional_tasks[value])
            def ref_versions(logical,ref):
                plan=task_plan[logical]
                rows=plan.get('vcs_python_versions',{}).get(ref)
                return set(rows or [plan['python']])
            relevant=set()
            for logical in required_dependants|optional_dependants:
                relevant.update(ref_versions(logical,value))
            if not relevant:
                raise RuntimeError('VCS source has no target Python phase')
            deps_by_version={};nested_by_version={}
            for target_version in sorted(relevant):
                deps,nested,problems=git_requirements(
                    folder,pinned,python_version=target_version)
                if problems:raise RuntimeError('; '.join(problems))
                deps_by_version[target_version]=deps
                nested_by_version[target_version]=nested
            vcs_frozen[value]=pinned
            for target_version,nested in nested_by_version.items():
                for remote in nested:
                    normalized=vcs_reference(remote)
                    if normalized is None:raise RuntimeError('invalid nested VCS reference: '+remote)
                    for logical in required_dependants:
                        if target_version not in ref_versions(logical,value):continue
                        vcs_required_tasks[normalized].add(logical)
                        plan=task_plan[logical]
                        if normalized not in plan['vcs']:plan['vcs']=sorted([*plan['vcs'],normalized])
                        versions=set(plan.setdefault('vcs_python_versions',{}).get(normalized,[]))
                        versions.add(target_version);plan['vcs_python_versions'][normalized]=sorted(versions)
                    for logical in optional_dependants:
                        if target_version not in ref_versions(logical,value):continue
                        vcs_optional_tasks[normalized].add(logical)
                        plan=task_plan[logical]
                        if normalized not in plan['vcs'] and normalized not in plan['optional_vcs']:
                            plan['optional_vcs']=sorted([*plan['optional_vcs'],normalized])
                        versions=set(plan.setdefault('vcs_python_versions',{}).get(normalized,[]))
                        versions.add(target_version);plan['vcs_python_versions'][normalized]=sorted(versions)
                    if normalized not in vcs_frozen:pending.add(normalized)
            for target_version,deps in sorted(deps_by_version.items()):
                if not deps:continue
                key=hashlib.sha256((value+target_version).encode()).hexdigest()[:20]
                try:pip_closure(pool,target_version,deps,key)
                except (RuntimeError,subprocess.CalledProcessError) as exc:
                    required_for_version=any(target_version in ref_versions(item,value)
                                             for item in required_dependants)
                    if required_for_version:
                        raise RuntimeError('VCS transitive solve: '+str(exc)) from exc
                    vcs_optional_failures[value]='optional VCS transitive solve unavailable: '+str(exc)
            setup_source=git_file(folder,pinned,'setup.py') or ''
            if re.search(r'check_call\(\s*\[\s*["\']npm["\']\s*,\s*["\']install["\']',setup_source):
                try:npm_package_json_closure(pool,folder,pinned,repo_ref,value)
                except (RuntimeError,subprocess.CalledProcessError,OSError,ValueError) as exc:
                    if required_dependants:
                        raise RuntimeError('VCS npm closure: '+str(exc)) from exc
                    vcs_optional_failures[value]='optional VCS npm closure unavailable: '+str(exc)
        except (RuntimeError,subprocess.CalledProcessError,OSError,ValueError) as exc:
            # Do not retain a freeze proof for a source whose required closure
            # could not be inspected. Optional `|| true` sources may fail exactly
            # as the upstream recipe permits.
            vcs_frozen.pop(value,None)
            vcs_failure('VCS fetch/closure failed: '+str(exc))
    write_new(stage/'metadata'/'vcs-optional-failures.json',
              json.dumps(vcs_optional_failures,sort_keys=True,indent=2)+'\n')
    write_new(stage/'metadata'/'vcs-frozen.json',json.dumps(vcs_frozen,sort_keys=True,indent=2))
    # Freeze Git metadata only after all commits/tags/refs have been fetched.
    # Git FETCH_HEAD and refs are mutable during acquisition and must never be
    # hardlinked into content-addressed objects before that point.
    for kind in ('git','git-extra'):
        for path in sorted((stage/kind).rglob('*')):
            if path.is_file() and not path.is_symlink():
                pool.put(path,kind,path.relative_to(stage/kind).parts[0])
    # NPM lockfiles pinned via Subresource Integrity; no package scripts execute.
    npm_urls={}
    for repo,commits in sorted(grouped.items()):
        for commit in sorted(commits):
            for filename in ('package-lock.json','bokehjs/package-lock.json'):
                source=git_file(mirrors[repo],commit,filename)
                if not source:continue
                try:lock=json.loads(source)
                except ValueError:pool.issue(repo,'invalid npm lockfile');continue
                def workspace(url, *, _repo=repo, _commit=commit, _filename=filename):
                    if (not isinstance(url,str) or Path(url).is_absolute()
                            or '..' in Path(url).parts or '\\' in url):
                        raise RuntimeError('unsafe npm workspace reference')
                    directory=str(Path(_filename).parent/url)
                    row=invoke(['git','--git-dir',mirrors[_repo],'ls-tree','-d',
                                _commit,'--',directory],capture=True).strip()
                    if not re.fullmatch(r'040000 tree [a-f0-9]{40}\t.+',row):
                        raise RuntimeError('npm workspace missing from pinned Git source: '+directory)
                try:found=npm_lock_urls(lock,repo+':'+filename,workspace_checker=workspace)
                except RuntimeError as exc:
                    pool.issue(repo,str(exc));continue
                for url,integ in found.items():
                    if url in npm_urls and npm_urls[url]!=integ:
                        raise RuntimeError('conflicting npm lockfile integrity for '+url)
                    npm_urls[url]=integ
    for url,sri in sorted(npm_urls.items()):
        pool.download(url,'npm',url,sri=sri)
    # Bokeh runs `npm install --location=global npm` before its lockfile CI.
    # The npm CLI release is outside package-lock.json and must be acquired.
    if any('npm install --location=global npm' in cmd
           for task in tasks.values() for cmd in task['repo_script_list']):
        try: npm_global_bootstrap(pool)
        except (RuntimeError,OSError,ValueError) as exc:
            pool.issue('npm-global', 'npm CLI acquisition failed: ' + str(exc))
    # Signed APT download-only resolution against Kali, never the Ubuntu host.
    os_source=adapter/'os_packages.py'
    import ast
    tree=ast.parse(os_source.read_text())
    rows=[node.value for node in tree.body if isinstance(node,ast.Assign) and any(
          isinstance(target,ast.Name) and target.id=='PACKAGES' for target in node.targets)]
    if len(rows)!=1:raise RuntimeError('missing pinned APT manifest')
    apt_requested.update(ast.literal_eval(rows[0]))
    apt_requested.update(('openjdk-17-jdk','openjdk-17-jre'))
    try:apt_closure(pool,apt_requested)
    except (RuntimeError,subprocess.CalledProcessError,OSError) as exc:
        pool.issue('APT','signed Kali closure unavailable: '+str(exc))
    audit_inventory(pool,task_plan,envplan,gitplan,args.operation_id,contract_tasks=tasks,
                    conda_transactions=conda_transaction_plan,
                    conda_lock_sha256=conda_lock_sha256)


if __name__=='__main__':
    try:main()
    except BaseException as exc:
        print('[pool] FAILED; data retained, no automatic cleanup:',str(exc),file=sys.stderr,flush=True)
        raise
