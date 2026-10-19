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
import stat
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


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1048576), b''): h.update(chunk)
    return h.hexdigest()


def invoke(argv, *, cwd=None, capture=False, env=None):
    command = [str(v) for v in argv]
    print('[pool]', ' '.join(command), flush=True)
    result = subprocess.run(command, cwd=cwd, env=env, check=True,
                            text=True, stdout=subprocess.PIPE if capture else None)
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


def parse_requirements(text, filename, get_file, *, seen=None):
    seen=set() if seen is None else seen
    if filename in seen: return set(),set()
    seen.add(filename)
    specs=set(); git=set()
    for original in text.replace('\\\n','').splitlines():
        value=original.strip()
        if not value or value.startswith('#'): continue
        if value.startswith(('-r ','--requirement ','-c ','--constraint ')):
            _,child=value.split(maxsplit=1)
            if child.startswith(('/', 'http')) or '..' in Path(child).parts:
                raise RuntimeError('unsafe pip included requirements: '+value)
            sub=str(Path(filename).parent/child)
            s,g=parse_requirements(get_file(sub,required=True),sub,get_file,seen=seen)
            specs.update(s);git.update(g);continue
        if value.startswith(('-e ','--editable ')):
            target=value.split(maxsplit=1)[1]
            if target.startswith('git+https://'):git.add(target);continue
            if target.startswith(('.', '/testbed')):continue
            raise RuntimeError('unresolved editable dependency: '+value)
        if value.startswith('git+https://'):git.add(value);continue
        if value.startswith(('-', 'http://','https://')) or re.search(r'\s@\s(?:git\+|https?://)',value):
            raise RuntimeError('unsupported pip dependency directive: '+value)
        specs.add(value)
    return specs,git


def static_project(file, *, extra_groups=()):
    """Interpret declared metadata without running setup.py or a build backend."""
    if not file: return set(),set(),[]
    issues=[]; deps=set();git=set()
    data=tomllib.loads(file)
    project=data.get('project',{})
    deps.update(project.get('dependencies',[]))
    for k in ('dependencies','optional-dependencies'):
        if k in project.get('dynamic',[]):issues.append('dynamic PEP621 '+k)
    for name,items in project.get('optional-dependencies',{}).items():
        if name in extra_groups or '*' in extra_groups: deps.update(items)
    pdm=data.get('tool',{}).get('pdm',{})
    for group,items in pdm.get('dev-dependencies',{}).items():
        if group in extra_groups or '*' in extra_groups:deps.update(items)
    poetry=data.get('tool',{}).get('poetry',{})
    for name,spec in poetry.get('dependencies',{}).items():
        if name=='python':continue
        if isinstance(spec,str):deps.add(name+(spec if spec.startswith(('=','<','>','!','~')) else ''))
        elif isinstance(spec,dict) and isinstance(spec.get('version'),str):deps.add(name+spec['version'])
        else:issues.append('unresolved Poetry dependency '+name)
    for row in list(deps):
        if 'git+https://' in row:deps.remove(row);git.add(row)
    return deps,git,issues


def setup_static(source):
    """Conservative literal setup.py parsing; report evaluated/dynamic expressions."""
    import ast
    if not source:return set(),[]
    try:tree=ast.parse(source)
    except SyntaxError:return set(),['unparseable setup.py']
    deps=set();issues=[]
    for node in ast.walk(tree):
        if not isinstance(node,ast.Call) or getattr(node.func,'id',None)!='setup':continue
        for kw in node.keywords:
            if kw.arg not in ('install_requires','setup_requires','tests_require'):continue
            try: values=ast.literal_eval(kw.value)
            except (ValueError,TypeError,SyntaxError):
                issues.append('setup.py computes '+kw.arg+' dynamically');continue
            if isinstance(values,(list,tuple)) and all(isinstance(v,str) for v in values):deps.update(values)
            else:issues.append('setup.py unexpected '+kw.arg)
    return deps,issues


def pip_commands(commands):
    """Only recognizes literal install arguments; it never executes command text."""
    specs=set();files=set();vcs=set();issues=[];local_extras=set()
    for line in commands:
        for m in re.finditer(r'(?<![\w-])(?:(?:python(?:3(?:\.\d+)?)?\s+-m\s+))?pip(?:3)?\s+install\s+([^;\n]+)',line):
            fragment=re.split(r'\s*(?:&&|\|\||\|)\s*',m.group(1),maxsplit=1)[0].strip()
            try:parts=shlex.split(fragment)
            except ValueError:issues.append('unparseable pip command');continue
            i=0
            while i<len(parts):
                p=parts[i]
                if p in ('-r','--requirement','-c','--constraint'):
                    if i+1>=len(parts):issues.append('pip requirement filename absent');break
                    files.add(parts[i+1]);i+=2;continue
                if p.startswith('-r') and len(p)>2:files.add(p[2:]);i+=1;continue
                if p in ('-e','--editable'):
                    if i+1>=len(parts):issues.append('missing editable target');break
                    target=parts[i+1]
                    if target.startswith('git+https://'):vcs.add(target)
                    elif target in ('.','./') or target.startswith('.['):
                        local_extras.update(re.findall(r'\[([^\]]+)\]',target)[0].split(',') if '[' in target else ())
                    else:issues.append('unknown editable target '+target)
                    i+=2;continue
                if p in ('--no-deps','--no-build-isolation','--upgrade','-U','-q','--quiet','-v','--verbose','-ve','-ev'):
                    i+=1;continue
                if p.startswith('-C') or p in ('--config-settings',):
                    if p=='--config-settings':i+=2
                    else:i+=1
                    continue
                if p.startswith('-'):
                    issues.append('unresolved pip option '+p);break
                if p in ('.','./') or p.startswith('./'):
                    i+=1;continue
                if p.startswith('git+https://'):vcs.add(p)
                elif p.startswith(('https://','http://')):issues.append('unresolved remote pip target '+p)
                else:specs.add(p)
                i+=1
    return specs,files,vcs,issues,local_extras


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


def conda_resolve(micro, pool, key, args):
    stage=pool.stage
    cmd=[micro,'create','--dry-run','--json','--strict-channel-priority','-c','conda-forge',
         '--root-prefix',stage/'conda'/'root','--prefix',stage/'conda'/'proposed'/key,*args]
    raw=invoke(cmd,capture=True)
    try: data=json.loads(raw)
    except ValueError as exc:raise RuntimeError('invalid micromamba solve JSON for '+key) from exc
    if data.get('success') is False:raise RuntimeError('unsatisfiable Conda recipe '+key)
    actions=data.get('actions') or {}
    packages=actions.get('FETCH',[])
    if not packages:raise RuntimeError('micromamba returned empty closure for '+key)
    resolved=[]
    for item in packages:
        url=item.get('url')
        hashval=item.get('sha256')
        if not url or not isinstance(hashval,str) or not SHA.fullmatch(hashval):
            raise RuntimeError('Conda closure has unpinned package '+key)
        # Micromamba itself may fetch signed metadata, but it never installs packages.
        pool.download(url,'conda',key,sha=hashval)
        resolved.append({'name':item.get('name'),'version':item.get('version'),'sha256':hashval})
    write_new(stage/'metadata'/('conda-'+key+'.json'),json.dumps(resolved,sort_keys=True))


def apt_closure(pool,packages):
    """Signed Kali APT metadata; isolated empty package-status DB; download-only."""
    stage=pool.stage;apt=stage/'apt';apt.mkdir(exist_ok=True)
    for name in ('lists','archives','partial','sourceparts'):(apt/name).mkdir()
    (apt/'lists'/'partial').mkdir()
    (apt/'archives'/'partial').mkdir()
    pool.download('https://archive.kali.org/archive-key.asc','apt','signing-key')
    key_path=stage/'downloads'/hashlib.sha256(('apt\0signing-key\0https://archive.kali.org/archive-key.asc').encode()).hexdigest()
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
        fields=subprocess.check_output(['dpkg-deb','-f',str(path),'Package','Version','Architecture'],text=True).splitlines()
        sha=pool.put(path,'apt','kali-last-snapshot')
        meta.append({'sha256':sha,'package':fields[0] if fields else '',
                     'version':fields[1] if len(fields)>1 else '',
                     'architecture':fields[2] if len(fields)>2 else ''})
    write_new(stage/'metadata'/'apt-closure.json',json.dumps({'requested':sorted(packages),'resolved':meta},sort_keys=True))


def pip_closure(pool, version, reqs, key):
    if not reqs:
        return
    stage = pool.stage
    outfile = stage / 'metadata' / ('pip-' + key + '.txt')
    write_new(outfile, '\n'.join(sorted(reqs)) + '\n')
    # Keep separate solutions for conflicting task pins while advertising all
    # already downloaded wheels as local candidates to pip. No extra pip cache.
    shared = stage / 'wheels' / 'shared'
    shared.mkdir(exist_ok=True)
    dest = stage / 'wheels' / key
    dest.mkdir()
    invoke([sys.executable, '-m', 'pip', 'download', '--disable-pip-version-check',
            '--no-cache-dir', '--only-binary=:all:', '--implementation', 'cp',
            '--python-version', version, '--abi', 'cp' + version.replace('.', ''),
            '--platform', 'manylinux2014_x86_64', '--find-links', shared,
            '--dest', dest, '-r', outfile])
    names = []
    for file in sorted(dest.iterdir()):
        if not file.is_file() or file.is_symlink():
            raise RuntimeError('unsafe pip closure artifact')
        sha = pool.put(file, 'python', key)
        # Dedup in the working stage immediately, not just at publication.
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
    if not names:
        raise RuntimeError('pip closure has no downloadable packages')
    write_new(stage / 'metadata' / ('pip-plan-' + key + '.json'),
              json.dumps({'python': version, 'requested': sorted(reqs),
                          'files': names}, sort_keys=True))


def audit_inventory(pool,task_plan,envplan,gitplan):
    stage=pool.stage
    files=[];seen_inodes={}
    for path in sorted(stage.rglob('*')):
        if path.is_symlink():
            # Reject symlinks, including package-manager caches.
            raise RuntimeError('symlink in dependency pool: '+str(path))
        if not path.is_file():continue
        rel=path.relative_to(stage).as_posix()
        info=path.stat(); identity=(info.st_dev,info.st_ino)
        if identity in seen_inodes:
            row={'path':rel,'size':info.st_size,'sha256':seen_inodes[identity]}
        else:
            row={'path':rel,'size':info.st_size,'sha256':digest(path)}
            seen_inodes[identity]=row['sha256']
        files.append(row)
    issues=sorted(set(pool.issues))
    summary={'schema':2,'kind':'download-only-pool','complete':not issues,
             'tasks':len(task_plan),'repos':len(gitplan),'conda_recipes':len(envplan),
             'python_versions':list(PYTHONS),'files':files,'issues':issues,
             'objects':pool.links,'provenance':pool.provenance,
             'task_plan':task_plan,'environment_plan':envplan,
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
    # Git packs are content-addressed internally and only referenced commits are fetched.
    for path in sorted((stage/'git').rglob('*')):
        if path.is_file() and not path.is_symlink():pool.put(path,'git',path.relative_to(stage/'git').parts[0])
    for path in sorted((stage/'git-extra').rglob('*')):
        if path.is_file() and not path.is_symlink():pool.put(path,'git-extra',path.relative_to(stage/'git-extra').parts[0])
    envplan={};requirements_by_env=defaultdict(set);vcs=set()
    for version in PYTHONS:
        print('[pool] Python '+version,flush=True)
        conda_resolve(str(resolver),pool,'python-'+version,['python='+version,'pip'])
    for i,(env,entry) in enumerate(sorted(environments.items()),1):
        version=python_version(entry['original_script']);envplan[env]=version
        content=conda_yaml(entry['original_script'])
        if content:
            trimmed,pips=conda_pip_split(content)
            # The official upstream Dask recipe removes the pip section before
            # Conda sees it. Do not fetch packages from instructions it deletes.
            if any("sed -i '/- pip:/,/^ *-/d' environment.yml" in command
                   for command in entry['original_script']):
                pips=[]
            trimmed=trimmed.replace('firefox =>96','firefox >=96')
            file=stage/'metadata'/('env-'+env+'.yml');write_new(file,trimmed)
            print(f'[pool] Conda {i}/25, Python {version}',flush=True)
            # --file accepts YAML. It resolves without creating an env or unpacking.
            conda_resolve(str(resolver),pool,'env-'+env,['--file',str(file),'python='+version])
            for dep in pips:
                if not dep or dep.startswith('#'):continue
                if dep.startswith('git+https://'):vcs.add(dep)
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
    task_plan={};groups={};apt_requested=set()
    for index,(logical,task) in enumerate(sorted(tasks.items()),1):
        repo=task['repo'];commit=task['base_commit'];mirror=mirrors[repo]
        version=envplan[task['env_hash']]
        commands=list(task['repo_script_list'])
        spec=specs_table[repo.lower()][task['version']]
        # Installation-relevant evaluator commands are public pinned spec data;
        # no patch, oracle, test command or private evaluator material is exported.
        commands.extend(spec.get('eval_commands',[]))
        for package in spec.get('pip_packages',[]):commands.append('pip install '+package)
        get_file=lambda path,required=False: git_file(mirror,commit,path,required=required)
        # Resolve Make targets as data, without invoking make or project recipes.
        for command in list(commands):
            for match in re.finditer(r'(?<![\w-])make\s+(init|install)\b',command):
                try:
                    makefile=get_file('Makefile',required=True)
                    commands.extend(make_commands(makefile,match.group(1)))
                except (ValueError,RuntimeError) as exc:pool.issue(logical,str(exc))
        reqs=set(requirements_by_env[task['env_hash']]);vcs_task=set()
        explicit,reqfiles,external,problems,extras=pip_commands(commands)
        reqs.update(explicit);vcs_task.update(external)
        for problem in problems:pool.issue(logical,problem)
        # Static PEP 621, Poetry and PDM declarations are interpreted as data.
        for file in ('pyproject.toml','setup.cfg'):
            raw=get_file(file)
            if file=='pyproject.toml' and raw:
                try:
                    dep,git,problem=static_project(raw,extra_groups=extras|{'test','dev'})
                    reqs.update(dep);vcs_task.update(git)
                    for ptext in problem:pool.issue(logical,ptext)
                except (ValueError,TypeError) as exc:pool.issue(logical,'invalid pyproject.toml: '+str(exc))
        setup=get_file('setup.py')
        deps,problems=setup_static(setup)
        reqs.update(deps)
        # Unspecified setup.py variables must be resolved explicitly, not assumed.
        # Static requirements and declarative project metadata cover the common case.
        for ptext in problems:pool.issue(logical,ptext)
        for filename in sorted(reqfiles):
            try:
                specs,git=parse_requirements(get_file(filename,required=True),filename,get_file)
                reqs.update(specs);vcs_task.update(git)
            except (ValueError,RuntimeError) as exc:pool.issue(logical,str(exc))
        # Known declarative commands that do not need to execute to acquire inputs.
        for command in commands:
            # Literal upstream temporary constraints are inputs, not commands to run.
            if 'PIP_CONSTRAINT' in command:
                for constraint in re.findall(r"echo\s+['\"]([A-Za-z0-9_.-]+[<>=!~][^'\"]+)['\"]\s*>",command):
                    reqs.add(constraint)
            for match in re.finditer(r'\bapt-get\s+install\s+([^;\n&]+)',command):
                try:
                    tokens=shlex.split(match.group(1))
                    apt_requested.update(x for x in tokens if not x.startswith('-') and re.fullmatch(r'[A-Za-z0-9+._-]+',x))
                except ValueError:pool.issue(logical,'unparseable apt install command')
            for match in re.finditer(r'\bpipx\s+install\s+([\w.-]+)',command):
                reqs.add(match.group(1))
            if re.search(r'\bpdm\s+add\s+pre-commit',command):reqs.add('pre-commit')
            if re.search(r'\bnpm\s+(?:ci|install)\b',command):
                pass # npm lockfile closure handled separately
            if re.search(r'\b(?:curl|wget)\b\s+https?://',command):
                pool.issue(logical,'shell download needs explicit pinned hash: '+command[:90])
        # Preserve distinct task requirements; do not conflate conflicting pins.
        plan_key=hashlib.sha256(json.dumps([version,sorted(reqs)],sort_keys=True).encode()).hexdigest()[:20]
        groups.setdefault(plan_key,{'version':version,'requirements':sorted(reqs),'tasks':[]})['tasks'].append(logical)
        task_plan[logical]={'repo':repo,'base_commit':commit,'env_hash':task['env_hash'],
                            'python':version,'pip_plan':plan_key,'vcs':sorted(vcs_task)}
        vcs.update(vcs_task)
        if index%25==0:print(f'[pool] Static task recipes {index}/230',flush=True)
    for key,group in sorted(groups.items()):
        try:pip_closure(pool,group['version'],group['requirements'],key)
        except subprocess.CalledProcessError as exc:pool.issue('pip:'+key,'binary dependency solve unavailable: '+str(exc))
        except RuntimeError as exc:pool.issue('pip:'+key,str(exc))
    # Pin VCS inputs to the exact fetched commit; inspect their PEP621 metadata.
    vcs_frozen={}
    for value in sorted(vcs):
        raw=value.removeprefix('git+').split('#',1)[0]
        parsed=urllib.parse.urlsplit(raw)
        repo_ref=parsed.path.strip('/')
        pinned=None
        if '@' in repo_ref:repo_ref,pinned=repo_ref.rsplit('@',1)
        repo_ref=repo_ref.removesuffix('.git')
        if parsed.scheme!='https' or parsed.hostname!='github.com' or not REPO.fullmatch(repo_ref):
            pool.issue('VCS','unsupported source '+value);continue
        if pinned and not COMMIT.fullmatch(pinned):
            pool.issue('VCS','unsupported abbreviated/branch/tag VCS pin: '+value);continue
        if not pinned:
            # Freeze the upstream HEAD to an exact full commit at acquisition.
            # It is never re-resolved after publication.
            ref=invoke(['git','ls-remote','https://github.com/'+repo_ref+'.git','HEAD'],capture=True)
            match=re.fullmatch(r'([a-f0-9]{40})\s+HEAD\s*',ref)
            if not match:pool.issue('VCS','HEAD could not be frozen: '+value);continue
            pinned=match.group(1)
        vcs_frozen[value]=pinned
        try:
            folder=ensure_commit(stage,repo_ref,pinned,label='git-extra')
            rawproj=git_file(folder,pinned,'pyproject.toml')
            if rawproj:
                deps,_,problems=static_project(rawproj)
                for ptext in problems:pool.issue(value,ptext)
                # Do not silently drop transitives: acquire their wheels for every used Python.
                for version in PYTHONS:
                    try:pip_closure(pool,version,deps,hashlib.sha256((value+version).encode()).hexdigest()[:20])
                    except subprocess.CalledProcessError as exc:pool.issue(value,'VCS transitive solve: '+str(exc))
            else:
                src=git_file(folder,pinned,'setup.py')
                if src:
                    deps,problems=setup_static(src)
                    for ptext in problems:pool.issue(value,ptext)
                    for version in PYTHONS:
                        try:pip_closure(pool,version,deps,hashlib.sha256((value+version).encode()).hexdigest()[:20])
                        except subprocess.CalledProcessError as exc:pool.issue(value,'VCS setup.py transitive solve: '+str(exc))
                else:pool.issue(value,'VCS source lacks static Python metadata')
            for path in folder.rglob('*'):
                if path.is_file() and not path.is_symlink():pool.put(path,'git-extra',repo_ref)
        except (RuntimeError,subprocess.CalledProcessError) as exc:pool.issue(value,'VCS fetch failed: '+str(exc))
    write_new(stage/'metadata'/'vcs-frozen.json',json.dumps(vcs_frozen,sort_keys=True,indent=2))
    # NPM lockfiles pinned via Subresource Integrity; no npm install executed.
    npm_urls={}
    for repo,commits in sorted(grouped.items()):
        for commit in sorted(commits):
            for filename in ('package-lock.json','bokehjs/package-lock.json'):
                source=git_file(mirrors[repo],commit,filename)
                if not source:continue
                try:lock=json.loads(source)
                except ValueError:pool.issue(repo,'invalid npm lockfile');continue
                records=list((lock.get('packages') or {}).values()) or list((lock.get('dependencies') or {}).values())
                for item in records:
                    if not isinstance(item,dict) or not item.get('resolved'):continue
                    url=item['resolved'];integ=item.get('integrity')
                    if not isinstance(url,str) or not url.startswith('https://registry.npmjs.org/') or not integ:
                        pool.issue(repo,'npm package has no trusted source/SRI');continue
                    if url in npm_urls and npm_urls[url] != integ:
                        raise RuntimeError('conflicting npm lockfile integrity for ' + url)
                    npm_urls[url]=integ
    for url, sri in sorted(npm_urls.items()):
        # SHA-2 SRI is verified in the same pass as the first HTTP download.
        # Identical SRI across different URLs avoids any subsequent HTTP call.
        pool.download(url, 'npm', url, sri=sri)
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
    audit_inventory(pool,task_plan,envplan,gitplan)


if __name__=='__main__':
    try:main()
    except BaseException as exc:
        print('[pool] FAILED; data retained, no automatic cleanup:',str(exc),file=sys.stderr,flush=True)
        raise
