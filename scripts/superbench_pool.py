#!/usr/bin/env python3
"""Host-only SWE-Gym Lite dependency acquisition. No execution of task recipes.

The downloader runs as a dedicated non-root account. The privileged broker owns
publication. Fetch resolves deterministic build/download inputs only; it never
starts a VM, invokes a task script, installs software or deletes persisted data.
"""
from __future__ import annotations
import argparse
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


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1048576), b''): h.update(chunk)
    return h.hexdigest()


def invoke(argv, *, cwd=None, capture=False, env=None, timeout=3600):
    command = [str(v) for v in argv]
    print('[pool]', ' '.join(command), flush=True)
    result = subprocess.run(command, cwd=cwd, env=env, check=True,
                            text=True, stdout=subprocess.PIPE if capture else None, timeout=timeout)
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


def fetch(url, path, *, sha=None, sri=None, limit=2**37, integrity_digests=None):
    parsed=urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise RuntimeError('untrusted download endpoint: '+str(url))
    path=Path(path)
    request=urllib.request.Request(url,headers={'User-Agent':'gpt-trace-dependency-pool/2'})
    with urllib.request.urlopen(request,timeout=180) as response:
        if urllib.parse.urlsplit(response.url).scheme != 'https':
            raise RuntimeError('untrusted download redirect')
        if response.headers.get('Content-Length','').isdigit() and int(response.headers['Content-Length'])>limit:
            raise RuntimeError('download exceeds limit')
        h=hashlib.sha256(); size=0
        other_hashes = {algorithm: hashlib.new(algorithm) for algorithm in ('sha384', 'sha512')} if integrity_digests is not None else {}
        checks = [(hashlib.new(algo), expected) for algo, expected in (sri_parts(sri) or ())]
        with path.open('xb') as stream:
            for block in iter(lambda: response.read(1048576),b''):
                size += len(block)
                if size>limit: raise RuntimeError('download exceeds limit; partial retained')
                stream.write(block);h.update(block)
                for other in other_hashes.values(): other.update(block)
                for sri_hash, _ in checks: sri_hash.update(block)
            stream.flush(); os.fsync(stream.fileno())
    actual=h.hexdigest()
    if sha and actual != sha: raise RuntimeError('download sha256 mismatch: '+str(path))
    if checks and not any(h.digest() == expected for h, expected in checks):
        raise RuntimeError('download integrity mismatch: '+str(path))
    if integrity_digests is not None:
        integrity_digests.update({algo: h.digest() for algo, h in other_hashes.items()})
    return actual


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
    invoke(['git','init','--bare',folder])
    # Shallow exact-commit fetch avoids the unbounded history of --mirror.
    # All 230 task base commits are explicitly represented by the contract.
    cmd=['git','-c','protocol.file.allow=never','--git-dir',folder,'fetch','--no-tags',
         '--depth=1','https://github.com/'+repo+'.git',*sorted(commits)]
    invoke(cmd)
    if repo in {'bokeh/bokeh', 'pandas-dev/pandas'} and label == 'git':
        # Their real setup/commands require the upstream tags. Retain annotated
        # tag objects and their references, without fetching all branch history.
        invoke(['git', '-c', 'protocol.file.allow=never', '--git-dir', folder,
                'fetch', '--depth=1', '--no-recurse-submodules',
                'https://github.com/'+repo+'.git', '+refs/tags/*:refs/tags/*'])
        tags = invoke(['git','--git-dir',folder,'tag','--list'],capture=True).splitlines()
        if repo == 'bokeh/bokeh' and len(tags) < 5:
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


def static_project(file, *, extra_groups=()):
    """Interpret declarative pyproject metadata without executing a backend."""
    if not file: return set(),set(),[]
    issues=[]; deps=set();git=set()
    data=tomllib.loads(file)
    project=data.get('project',{})
    raw_dependencies = project.get('dependencies', [])
    if not isinstance(raw_dependencies, list):
        issues.append('invalid PEP621 dependencies')
    else:
        deps.update(raw_dependencies)
    # Offline builds also need their declared isolated build backend.
    build_requires = data.get('build-system',{}).get('requires',[])
    if isinstance(build_requires, list): deps.update(build_requires)
    else: issues.append('invalid build-system requires')
    for k in ('dependencies','optional-dependencies'):
        if k in project.get('dynamic',[]):issues.append('dynamic PEP621 '+k)
    for name,items in project.get('optional-dependencies',{}).items():
        if name in extra_groups or '*' in extra_groups:
            if isinstance(items, list): deps.update(items)
            else: issues.append('invalid PEP621 optional dependency group '+name)
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
            optional = isinstance(spec,dict) and spec.get('optional') is True
            if optional and name not in selected_optional:
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


def setup_static(source, *, extras=()):
    """Evaluate literal setuptools metadata and selected extras; never execute it."""
    import ast
    if not source: return set(), []
    try: tree = ast.parse(source)
    except SyntaxError: return set(), ['unparseable setup.py']
    definitions = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name): definitions[target.id] = node.value

    def static(node, visiting=frozenset()):
        if isinstance(node, ast.Name):
            if node.id in visiting or node.id not in definitions:
                raise ValueError('unresolved setup.py name ' + node.id)
            return static(definitions[node.id], visiting | {node.id})
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return [static(e, visiting) for e in node.elts]
        if isinstance(node, ast.Dict):
            result = {}
            for key, value in zip(node.keys, node.values):
                key_value = static(key, visiting)
                if not isinstance(key_value, str):
                    raise ValueError('non-string setup.py mapping key')
                result[key_value] = value
            return result
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bool, int, float)):
            return node.value
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return static(node.left, visiting) + static(node.right, visiting)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'str' and len(node.args)==1:
            return str(static(node.args[0], visiting))
        raise ValueError('dynamic setup.py metadata expression')

    def mapping_fields(node):
        if isinstance(node, ast.Name):
            if node.id not in definitions: return {}
            node = definitions[node.id]
        if not isinstance(node, ast.Dict): return {}
        result = {}
        for key, value in zip(node.keys, node.values):
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                result[key.value] = value
        return result

    deps, issues = set(), []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or getattr(node.func, 'id', None) != 'setup':
            continue
        fields = {kw.arg: kw.value for kw in node.keywords if kw.arg is not None}
        for kw in node.keywords:
            if kw.arg is None:
                fields.update({k:v for k,v in mapping_fields(kw.value).items() if k not in fields})
        for name in ('install_requires', 'setup_requires'):
            if name not in fields: continue
            try: values = static(fields[name])
            except (TypeError, ValueError) as exc:
                issues.append('setup.py computes ' + name + ' dynamically: ' + str(exc))
                continue
            if isinstance(values, list) and all(isinstance(v, str) for v in values):
                deps.update(values)
            else:
                issues.append('setup.py unexpected ' + name)
        if extras and 'extras_require' in fields:
            try:
                mapping = static(fields['extras_require'])
                if not isinstance(mapping, dict):
                    raise ValueError('extras_require is not a mapping')
                for group, value_node in mapping.items():
                    if group not in extras and '*' not in extras:
                        continue
                    values = static(value_node)
                    if not isinstance(values, list) or not all(isinstance(v,str) for v in values):
                        raise ValueError('dynamic setup.py extra '+group)
                    deps.update(values)
            except (TypeError, ValueError) as exc:
                issues.append('setup.py computes extras_require dynamically: ' + str(exc))
    return deps, issues



def setup_requirements_from_sources(source, get_file, *, extras=()):
    """Resolve audited file-backed setuptools patterns without executing project code.

    Unsupported dynamic metadata fails closed. Only literal source reads whose
    filenames are pinned Git inputs are recognized.
    """
    deps, issues = setup_static(source, extras=extras)
    vcs = set()
    if not source:
        return deps, vcs, issues
    if not issues or get_file is None:
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

    # Conan 1.x composes two runtime files and optionally its development file.
    if ('project_requirements = get_requires("conans/requirements.txt")' in source
            and 'project_requirements.extend(get_requires("conans/requirements_server.txt"))' in source
            and 'install_requires=project_requirements' in source):
        try:
            add_requirements('conans/requirements.txt')
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

    # modin-spreadsheet@49ffd89 stores the same fixed file in setup_args and
    # passes that mapping via **setup_args. The JavaScript build closure is
    # handled separately from package.json.
    if ('reqs = read_requirements("requirements.txt")' in source
            and '"install_requires": reqs' in source and '**setup_args' in source):
        try: add_requirements('requirements.txt')
        except RuntimeError as exc: return deps, vcs, [str(exc)]
        return deps, vcs, []

    return deps, vcs, issues


def git_requirements(mirror, commit):
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
        deps, remote, errors = setup_requirements_from_sources(source, get_file)
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
        self.objects.mkdir(parents=True)
        self.links = {}
        self.provenance = {}
        self.issues = []
        # In-memory indexes for this single, non-resumable acquisition job.
        self.by_url = {}
        self.by_sri = {}
        self.sri_verified = set()

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


def conda_resolve(micro, pool, key, args, *, channels=()):
    """Resolve and acquire one Conda transaction without creating an environment."""
    stage=pool.stage
    cmd=[micro,'create','--dry-run','--json',
         '--root-prefix',stage/'conda'/'root','--prefix',stage/'conda'/'proposed'/key]
    for channel in channels:
        cmd.extend(['-c',channel])
    cmd.extend(args)
    raw=invoke(cmd,capture=True)
    try: data=json.loads(raw)
    except ValueError as exc:raise RuntimeError('invalid micromamba solve JSON for '+key) from exc
    if data.get('success') is False:raise RuntimeError('unsatisfiable Conda recipe '+key)
    actions=data.get('actions') or {}
    fetches = actions.get('FETCH') or []
    links = actions.get('LINK') or []
    if not fetches and not links:
        raise RuntimeError('micromamba returned empty closure for '+key)
    # LINK describes the actual solved installation. FETCH alone can be
    # incomplete when an archive is already present in a package cache.
    by_name = {i.get('fn'): i for i in fetches if isinstance(i, dict) and i.get('fn')}
    packages = []
    for item in (links or fetches):
        if not isinstance(item, dict):
            raise RuntimeError('invalid micromamba package record for '+key)
        source = by_name.get(item.get('fn'), {})
        packages.append({**source, **{k: v for k, v in item.items() if v not in (None, '')}})
    if links:
        linked = {i.get('fn') for i in links if isinstance(i, dict)}
        if any(i.get('fn') not in linked for i in fetches):
            raise RuntimeError('micromamba FETCH and LINK disagree for '+key)
    resolved=[]
    for item in packages:
        url=item.get('url')
        hashval=item.get('sha256')
        if not url or not isinstance(hashval,str) or not SHA.fullmatch(hashval):
            raise RuntimeError('Conda closure has unpinned package '+key)
        pool.download(url,'conda',key,sha=hashval)
        resolved.append({'name':item.get('name'),'version':item.get('version'),
                         'build':item.get('build_string') or item.get('build'),
                         'url':url,'sha256':hashval})
    write_new(stage/'metadata'/('conda-'+key+'.json'),json.dumps(resolved,sort_keys=True))
    return resolved


def apt_closure(pool,packages):
    """Signed Kali APT metadata; isolated empty package-status DB; download-only."""
    stage=pool.stage;apt=stage/'apt';apt.mkdir(exist_ok=True)
    for name in ('lists','archives','partial','sourceparts'):(apt/name).mkdir()
    (apt/'lists'/'partial').mkdir()
    (apt/'archives'/'partial').mkdir()
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


def acquire_pinned_sdist(pool, requirement, plan_key):
    """Fetch an exact PyPI source archive by published SHA; never run its setup."""
    import email.parser
    import tarfile
    import zipfile
    match = re.fullmatch(r'([A-Za-z0-9_.-]+)==([A-Za-z0-9][A-Za-z0-9_.!+~-]*)', requirement)
    if not match: raise RuntimeError('sdist fallback requires an exact pinned version: ' + requirement)
    name, version = match.groups()
    index_url = 'https://pypi.org/pypi/' + name + '/' + version + '/json'
    request = urllib.request.Request(index_url, headers={'User-Agent':'gpt-trace-dependency-pool/2'})
    with urllib.request.urlopen(request, timeout=90) as response:
        if urllib.parse.urlsplit(response.url).hostname != 'pypi.org':
            raise RuntimeError('untrusted source metadata redirect')
        data = response.read(8 * 1024 * 1024 + 1)
        if len(data) > 8 * 1024 * 1024: raise RuntimeError('oversized source metadata')
    metadata = json.loads(data)
    options = [row for row in metadata.get('urls', []) if row.get('packagetype') == 'sdist'
               and isinstance(row.get('digests'), dict) and SHA.fullmatch(str(row['digests'].get('sha256', '')))]
    if len(options) != 1: raise RuntimeError('missing or ambiguous pinned source distribution: ' + requirement)
    item = options[0]; url = item.get('url')
    if urllib.parse.urlsplit(url).hostname != 'files.pythonhosted.org':
        raise RuntimeError('untrusted PyPI source archive host: ' + str(url))
    sha = pool.download(url, 'python-source', plan_key, sha=item['digests']['sha256'])
    source = pool.objects / sha[:2] / sha
    archive_name = item.get('filename', '')
    candidates = {}
    if archive_name.endswith(('.tar.gz', '.tar.bz2', '.tar.xz')):
        with tarfile.open(source, 'r:*') as tar:
            for member in tar:
                rel = Path(member.name)
                if not member.isfile() or len(rel.parts) < 2 or rel.name not in (
                        'PKG-INFO', 'setup.py', 'setup.cfg', 'pyproject.toml') or member.size > 2 * 1024 * 1024:
                    continue
                if len(rel.parts) > 2: continue
                stream = tar.extractfile(member)
                if stream is not None: candidates[rel.name] = stream.read(2 * 1024 * 1024 + 1)
    elif archive_name.endswith('.zip'):
        with zipfile.ZipFile(source) as archive:
            for name2 in archive.namelist():
                rel = Path(name2)
                if len(rel.parts) != 2 or rel.name not in ('PKG-INFO','setup.py','setup.cfg','pyproject.toml'):
                    continue
                if archive.getinfo(name2).file_size > 2 * 1024 * 1024: continue
                candidates[rel.name] = archive.read(name2)
    else:
        raise RuntimeError('unsupported pinned source archive: ' + archive_name)
    requirements = set()
    row = metadata.get('info') or {}
    requirements.update(row.get('requires_dist') or [])
    if 'PKG-INFO' in candidates:
        parsed = email.parser.Parser().parsestr(candidates['PKG-INFO'].decode('utf-8', errors='replace'), headersonly=True)
        requirements.update(parsed.get_all('Requires-Dist') or [])
    if 'setup.py' in candidates:
        deps, issues = setup_static(candidates['setup.py'].decode('utf-8', errors='replace'))
        if issues and not requirements:
            raise RuntimeError('cannot statically close source metadata for ' + requirement + ': ' + '; '.join(issues))
        requirements.update(deps)
    if 'setup.cfg' in candidates:
        deps, issues = setup_cfg_static(candidates['setup.cfg'].decode('utf-8', errors='replace'))
        if issues: raise RuntimeError('invalid source setup.cfg: ' + repr(issues))
        requirements.update(deps)
    if 'pyproject.toml' in candidates:
        deps, _, issues = static_project(candidates['pyproject.toml'].decode('utf-8', errors='replace'))
        if issues: raise RuntimeError('dynamic source build requirements: ' + repr(issues))
        requirements.update(deps)
    if not requirements and not ({'setup.py','PKG-INFO','setup.cfg','pyproject.toml'} & candidates.keys()):
        raise RuntimeError('source archive has no inspectable dependency metadata')
    return {'filename': archive_name, 'sha256': sha, 'requirements': sorted(requirements)}


def pip_closure(pool, version, reqs, key, *, constraints=(), no_deps=False):
    if not reqs: return
    stage = pool.stage
    outfile = stage / 'metadata' / ('pip-' + key + '.txt')
    write_new(outfile, '\n'.join(sorted(reqs)) + '\n')
    constraint_file = stage / 'metadata' / ('constraints-' + key + '.txt')
    if constraints: write_new(constraint_file, '\n'.join(sorted(constraints)) + '\n')
    shared = stage / 'wheels' / 'shared'; shared.mkdir(exist_ok=True)
    dest = stage / 'wheels' / key; dest.mkdir()
    def binary_download(needed):
        needed_file = stage / 'metadata' / ('binary-' + key + '-' + hashlib.sha256('\n'.join(sorted(needed)).encode()).hexdigest()[:12] + '.txt')
        write_new(needed_file, '\n'.join(sorted(needed)) + '\n')
        invoke([sys.executable, '-m', 'pip', 'download', '--disable-pip-version-check',
                '--no-cache-dir', '--only-binary=:all:', '--implementation', 'cp',
                '--python-version', version, '--abi', 'cp' + version.replace('.', ''),
                '--platform', 'manylinux2014_x86_64', '--find-links', shared,
                '--dest', dest, '-r', needed_file,
                *(['--no-deps'] if no_deps else []),
                *(['--constraint', str(constraint_file)] if constraints else [])])
    sources = []
    try:
        binary_download(reqs)
    except subprocess.CalledProcessError:
        # A source-only exact pin cannot be resolved by --only-binary. Download
        # the original archive by its PyPI SHA and statically inspect metadata;
        # never build or execute third-party setup code on the host.
        pinned = sorted(x for x in reqs if re.fullmatch(
            r'[A-Za-z0-9_.-]+==[A-Za-z0-9][A-Za-z0-9_.!+~-]*', x))
        if not pinned: raise
        remaining = set(reqs)
        for requirement in pinned:
            info = acquire_pinned_sdist(pool, requirement, key)
            sources.append(info)
            remaining.remove(requirement)
            if not no_deps: remaining.update(info['requirements'])
        if remaining:
            binary_download(remaining)
    names = []
    for file in sorted(dest.iterdir()):
        if not file.is_file() or file.is_symlink():
            raise RuntimeError('unsafe pip closure artifact')
        sha = pool.put(file, 'python', key)
        pool.coalesce_stage_file(file, sha)
        common = shared / file.name
        if common.exists():
            if common.is_symlink() or not common.is_file():
                raise RuntimeError('unsafe wheelhouse entry')
            if not common.samefile(pool.objects / sha[:2] / sha):
                raise RuntimeError('same wheel filename resolved to different bytes: ' + file.name)
        else:
            os.link(pool.objects / sha[:2] / sha, common)
        names.append({'filename': file.name, 'sha256': sha})
    if not names and not sources:
        raise RuntimeError('pip closure has no downloadable packages')
    write_new(stage / 'metadata' / ('pip-plan-' + key + '.json'),
              json.dumps({'python': version, 'requested': sorted(reqs),
                          'constraints': sorted(constraints), 'no_deps': no_deps,
                          'files': names, 'source_archives': sources}, sort_keys=True))



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


def npm_package_json_closure(pool, mirror, commit, repo_ref, identity):
    """Resolve a pinned VCS package.json to a lock only; never run npm scripts/install."""
    package_text=git_file(mirror,commit,'js/package.json') or git_file(mirror,commit,'package.json')
    if not package_text:
        raise RuntimeError('npm-backed VCS source lacks package.json: '+repo_ref)
    try: package=json.loads(package_text)
    except ValueError as exc: raise RuntimeError('invalid VCS package.json: '+repo_ref) from exc
    for key in ('dependencies','devDependencies'):
        value=package.get(key,{})
        if value is not None and not isinstance(value,dict):
            raise RuntimeError('invalid npm dependency table in '+repo_ref)
        for name,spec in (value or {}).items():
            if not isinstance(name,str) or not isinstance(spec,str):
                raise RuntimeError('non-string npm dependency in '+repo_ref)
            if spec.startswith(('git','http:','https:','file:','link:','workspace:')):
                raise RuntimeError('non-registry npm dependency requires explicit pin: '+name)
    key=hashlib.sha256((repo_ref+'\0'+commit+'\0'+identity).encode()).hexdigest()[:20]
    work=pool.stage/'npm'/('resolve-'+key)
    work.mkdir()
    write_new(work/'package.json',json.dumps(package,sort_keys=True,indent=2)+'\n')
    cache=work/'cache'
    env=dict(os.environ)
    env.update({'npm_config_cache':str(cache),'npm_config_registry':'https://registry.npmjs.org/',
                'npm_config_audit':'false','npm_config_fund':'false',
                'npm_config_ignore_scripts':'true'})
    invoke(['npm','install','--package-lock-only','--ignore-scripts','--no-audit','--no-fund',
            '--registry=https://registry.npmjs.org/'],cwd=work,env=env,timeout=1800)
    if (work/'node_modules').exists():
        raise RuntimeError('npm resolver unexpectedly installed node_modules')
    lock_path=work/'package-lock.json'
    if lock_path.is_symlink() or not lock_path.is_file():
        raise RuntimeError('npm resolver produced no lockfile')
    lock=json.loads(lock_path.read_bytes())
    urls=npm_lock_urls(lock,repo_ref)
    if not urls: raise RuntimeError('npm resolver produced empty archive closure: '+repo_ref)
    artifacts=[]
    for url,sri in sorted(urls.items()):
        sha=pool.download(url,'npm-vcs',identity,sri=sri)
        artifacts.append({'url':url,'integrity':sri,'sha256':sha})
    write_new(pool.stage/'metadata'/('npm-vcs-'+key+'.json'),json.dumps({
        'repo':repo_ref,'commit':commit,'identity':identity,
        'package_sha256':hashlib.sha256(package_text.encode()).hexdigest(),
        'lockfile':lock,'artifacts':artifacts},sort_keys=True))
    # Successful resolver scratch has no evidentiary value beyond the retained
    # lock/manifest. Failed scratch is intentionally preserved in the zombie.
    shutil.rmtree(work)
    return artifacts


def npm_global_bootstrap(pool):
    """Freeze an npm 10 CLI compatible with the pinned benchmark's Node >=18.17."""
    metadata_url = 'https://registry.npmjs.org/npm/' + NPM_NODE18_VERSION
    request = urllib.request.Request(metadata_url, headers={'User-Agent':'gpt-trace-dependency-pool/2'})
    with urllib.request.urlopen(request, timeout=90) as response:
        if urllib.parse.urlsplit(response.url).hostname != 'registry.npmjs.org':
            raise RuntimeError('untrusted npm CLI metadata redirect')
        raw = response.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024: raise RuntimeError('oversized npm CLI metadata')
    info = json.loads(raw)
    if info.get('version') != NPM_NODE18_VERSION:
        raise RuntimeError('npm registry returned unexpected CLI version')
    engine = (info.get('engines') or {}).get('node')
    if not isinstance(engine, str) or '18.17.0' not in engine:
        raise RuntimeError('pinned npm CLI no longer advertises Node 18.17 compatibility')
    dist = info.get('dist') or {}
    tarball, sri = dist.get('tarball'), dist.get('integrity')
    if not isinstance(tarball, str) or not tarball.startswith('https://registry.npmjs.org/npm/-/npm-'):
        raise RuntimeError('untrusted npm CLI archive')
    if not sri: raise RuntimeError('npm CLI lacks SRI')
    sha = pool.download(tarball, 'npm-global-cli', 'npm', sri=sri)
    write_new(pool.stage / 'metadata' / 'npm-global.json', json.dumps({
        'version': info.get('version'), 'url': tarball, 'sha256': sha, 'integrity': sri}, sort_keys=True))


def audit_inventory(pool,task_plan,envplan,gitplan,operation_id, *, contract_tasks=None,
                    conda_transactions=None):
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

    def reject(label,detail):
        pool.issue('inventory:'+label,detail)

    if not pool.links:reject('CAS','no acquired content-addressed objects')
    if len(task_plan)!=230 or len(envplan)!=25 or len(gitplan)!=11:
        reject('contract','unexpected 230/25/11 contract coverage')
    for kind in ('tools','conda','git','apt'):
        if not pool.provenance.get(kind):
            reject('provenance','no acquired '+kind+' artifacts')
    for sha,row in pool.links.items():
        if not SHA.fullmatch(sha) or row.get('sha256')!=sha:
            reject('CAS','invalid object identity '+str(sha));continue
        expected='objects/sha256/'+sha[:2]+'/'+sha
        target=stage/expected
        if (row.get('path')!=expected or not target.is_file() or target.is_symlink()
                or type(row.get('size')) is not int or target.stat().st_size!=row['size']):
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
        for key in plan.get('pip_steps',[]):validate_pip(logical,key,optional=False)
        for key in plan.get('pip_optional_steps',[]):validate_pip(logical,key,optional=True)

    if conda_transactions is None:
        conda_transactions={env:['env-'+env] for env in envplan}
    if set(conda_transactions)!=set(envplan):
        reject('Conda','transaction plan does not cover all environments')
    conda_keys=['python-'+version for version in PYTHONS]
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
             'git_plan':gitplan}
    write_new(stage/'inventory.json',json.dumps(summary,sort_keys=True,indent=2)+'\n')
    print('[pool] objects=',len(pool.links),'files=',len(files),'issues=',len(issues),flush=True)
    if issues:raise RuntimeError('incomplete dependency closure: '+issues[0]+
                                 '; inspect inventory.json, manual zombie cleanup required')
    return summary


def main(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument('--repo-root',required=True,type=Path)
    p.add_argument('--stage',required=True,type=Path)
    p.add_argument('--operation-id',required=True)
    args=p.parse_args(argv)
    if os.geteuid()==0:raise RuntimeError('refusing privileged fetch account')
    if not SHA.fullmatch(args.operation_id):raise RuntimeError('invalid operation ID')
    if args.stage.exists() or args.stage.is_symlink():raise RuntimeError('zombie or existing pool stage')
    repo_root=args.repo_root.resolve(strict=True)
    adapter=repo_root/'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym'
    pins=json.loads((adapter/'pins.json').read_bytes())
    if digest(adapter/'contract.json')!=pins['contract_sha256']:
        raise RuntimeError('pinned SWE-Gym Lite contract changed')
    contract=json.loads((adapter/'contract.json').read_bytes())
    tasks=contract['tasks'];environments=contract['environments']
    if len(tasks)!=230 or len(environments)!=25 or len({r['repo'] for r in tasks.values()})!=11:
        raise RuntimeError('unexpected SWE-Gym Lite coverage')
    stage=args.stage
    stage.mkdir(mode=0o700)
    for name in ('git','git-extra','conda','wheels','metadata','downloads','npm','apt','objects'):
        (stage/name).mkdir(exist_ok=True)
    write_new(stage/'STAGING','Uncommitted, non-resumable dependency acquisition.\n')
    pool=Pool(stage)
    resolver=stage/'metadata'/'micromamba'
    fetch('https://github.com/mamba-org/micromamba-releases/releases/download/2.9.0-0/micromamba-linux-64',
          resolver,sha='366cd9cd8be14df1ab8ed50352a82111082a36686b2d389fdb79a92c3fafb3e3',limit=30*1024*1024)
    resolver.chmod(0o500)
    pool.put(resolver,'tools','micromamba-2.9.0')
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
    envplan={};conda_transaction_plan={};requirements_by_env=defaultdict(set);vcs=set()
    vcs_by_env=defaultdict(set)
    for version in PYTHONS:
        print('[pool] Python '+version,flush=True)
        conda_resolve(str(resolver),pool,'python-'+version,['python='+version,'pip'],
                      channels=('conda-forge',))
    default_channels=('https://repo.anaconda.com/pkgs/main',
                      'https://repo.anaconda.com/pkgs/r')
    for i,(env,entry) in enumerate(sorted(environments.items()),1):
        script=entry['original_script']
        version=python_version(script);envplan[env]=version
        content=conda_yaml(script)
        pips=[]
        print(f'[pool] Conda {i}/25, Python {version}',flush=True)
        if content:
            trimmed,pips=conda_pip_split(content)
            # The official upstream Dask recipe removes the pip section before
            # Conda sees it. Do not fetch packages from instructions it deletes.
            if any("sed -i '/- pip:/,/^ *-/d' environment.yml" in command
                   for command in script):
                pips=[]
            trimmed=trimmed.replace('firefox =>96','firefox >=96')
            file=stage/'metadata'/('env-'+env+'.yml');write_new(file,trimmed)
            post=conda_post_install_specs(script)
            if post:
                transaction_keys=['env-'+env+'-base']
                # Acquire the exact initial transaction as well as every later
                # post-create solve. This is intentionally two-phase: merging a
                # later Python override into the initial YAML can omit archives
                # needed by the real first `conda env create`.
                conda_resolve(str(resolver),pool,'env-'+env+'-base',['--file',str(file)])
                cumulative=[]
                for step_index,specs in enumerate(post,1):
                    cumulative.extend(specs)
                    key='env-'+env if step_index==len(post) else 'env-'+env+'-step'+str(step_index)
                    conda_resolve(str(resolver),pool,key,['--file',str(file),*cumulative])
                    transaction_keys.append(key)
                conda_transaction_plan[env]=transaction_keys
            else:
                conda_resolve(str(resolver),pool,'env-'+env,['--file',str(file)])
                conda_transaction_plan[env]=['env-'+env]
        else:
            direct=conda_direct_specs(script)
            if not direct:
                raise RuntimeError('environment has neither YAML nor direct Conda create: '+env)
            # Upstream direct `conda create` uses Miniconda's defaults; do not
            # silently substitute conda-forge.
            conda_resolve(str(resolver),pool,'env-'+env,direct,channels=default_channels)
            conda_transaction_plan[env]=['env-'+env]
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
        reqs=set(requirements_by_env[task['env_hash']]);vcs_task=set(vcs_by_env[task['env_hash']])
        vcs_optional=set()
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
        deps,remote,problems=setup_requirements_from_sources(setup,get_file,extras=extras)
        reqs.update(deps); vcs_task.update(remote)
        for ptext in problems:pool.issue(logical,ptext)

        task_steps=[];optional_steps=[];optional_skips=[]
        def register(req, constraints, name, *, no_deps=False, optional=False,
                     resolver_version=None):
            if not req: return None
            selected_version = resolver_version or version
            key=hashlib.sha256(json.dumps(
                [selected_version,sorted(req),sorted(constraints),no_deps,optional],
                sort_keys=True).encode()).hexdigest()[:20]
            group=groups.setdefault(key,{'version':selected_version,'requirements':sorted(req),
                                          'constraints':sorted(constraints),'no_deps':no_deps,
                                          'optional':optional,'tasks':[],'steps':[]})
            if logical not in group['tasks']:group['tasks'].append(logical)
            group['steps'].append(name)
            (optional_steps if optional else task_steps).append(key)
            return key

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
        normalized_optional={vcs_reference(item) or item for item in vcs_optional}
        task_plan[logical]={'repo':repo,'base_commit':commit,'env_hash':task['env_hash'],
                            'python':version,'pip_plan':primary,'pip_steps':task_steps,
                            'pip_optional_steps':optional_steps,
                            'pip_optional_skips':optional_skips,
                            'vcs':sorted(normalized_vcs),
                            'optional_vcs':sorted(normalized_optional),
                            # Frozen Golden policy: official blanket upgrades are
                            # suppressed during eventual offline replay. Explicit
                            # apt-get install packages are still acquired below.
                            'apt_upgrade_suppressed':logical in apt_upgrade_tasks}
        vcs.update(normalized_vcs);vcs.update(normalized_optional)
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
                with urllib.request.urlopen(urllib.request.Request(
                        api,headers={'User-Agent':'gpt-trace-dependency-pool/2'}),timeout=60) as res:
                    response=json.loads(res.read(1048576))
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
            deps,nested,problems=git_requirements(folder,pinned)
            if problems:
                raise RuntimeError('; '.join(problems))
            vcs_frozen[value]=pinned
            required_dependants=set(vcs_required_tasks[value])
            optional_dependants=set(vcs_optional_tasks[value])
            for remote in nested:
                normalized=vcs_reference(remote)
                if normalized is None:
                    raise RuntimeError('invalid nested VCS reference: '+remote)
                vcs_required_tasks[normalized].update(required_dependants)
                vcs_optional_tasks[normalized].update(optional_dependants)
                for logical in required_dependants:
                    plan=task_plan[logical]
                    if normalized not in plan['vcs']:
                        plan['vcs']=sorted([*plan['vcs'],normalized])
                for logical in optional_dependants:
                    plan=task_plan[logical]
                    if normalized not in plan['vcs'] and normalized not in plan['optional_vcs']:
                        plan['optional_vcs']=sorted([*plan['optional_vcs'],normalized])
                if normalized not in vcs_frozen:pending.add(normalized)
            dependants=required_dependants|optional_dependants
            relevant={task_plan[item]['python'] for item in dependants}
            for version in sorted(relevant):
                if not deps:continue
                key=hashlib.sha256((value+version).encode()).hexdigest()[:20]
                try:pip_closure(pool,version,deps,key)
                except (RuntimeError,subprocess.CalledProcessError) as exc:
                    if required_dependants:
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
                    conda_transactions=conda_transaction_plan)


if __name__=='__main__':
    try:main()
    except BaseException as exc:
        print('[pool] FAILED; data retained, no automatic cleanup:',str(exc),file=sys.stderr,flush=True)
        raise
