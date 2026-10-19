#!/usr/bin/env python3
"""Download-only, append-only SWE-Gym Lite dependency pool (execution host).

The fetcher never invokes KVM, executes task recipes, installs packages, builds
wheels, changes live Python environments or removes any persistent file.
It downloads exact Git sources, Conda binary closures, Python wheels and npm
archives. Unsupported dynamic inputs are errors, never silent success.
The root administrative broker owns publication and worker lifecycle; this
module must run as the dedicated unprivileged gpttrace-fetch account.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
import tomllib
import urllib.parse
import urllib.request
from collections import defaultdict
from pathlib import Path

PYTHONS = ('3.8', '3.9', '3.10', '3.11', '3.12')
REPO = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
COMMIT = re.compile(r'^[0-9a-f]{40}$')
PKG_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]*$')
MAX_FILE = 6 * 1024 * 1024


def checksum(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def run(argv, *, cwd=None, stdout=None, timeout=None):
    print('[pool]', ' '.join(map(str, argv)), flush=True)
    subprocess.run([str(s) for s in argv], cwd=cwd, stdout=stdout, check=True,
                   timeout=timeout, env=os.environ)


def write_new(path, content):
    """Never overwrite an existing byte (not even an interrupted partial)."""
    path = Path(path)
    with path.open('xb') as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())


def inventory_file(path, root):
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        raise RuntimeError('unsafe downloaded file: ' + str(p))
    return {'path': p.relative_to(root).as_posix(),
            'size': p.stat().st_size, 'sha256': checksum(p)}


def fetch_url(url, output, *, expected_sha256=None, limit=2**37):
    """HTTPS-only download to a *new* file. Preserve partials on error."""
    p = urllib.parse.urlsplit(url)
    if p.scheme != 'https' or not p.netloc or p.username or p.password or p.fragment:
        raise RuntimeError('non-HTTPS/untrusted dependency origin: ' + url)
    output = Path(output)
    with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent':'gpt-trace-pool/1'}), timeout=180) as resp:
        if urllib.parse.urlsplit(resp.url).scheme != 'https':
            raise RuntimeError('download redirected to non-HTTPS URL')
        length = resp.headers.get('Content-Length')
        if length and length.isdigit() and int(length) > limit:
            raise RuntimeError('dependency download exceeds size limit')
        with output.open('xb') as dest:
            count = 0
            digest = hashlib.sha256()
            while True:
                block = resp.read(1024*1024)
                if not block: break
                count += len(block)
                if count > limit: raise RuntimeError('dependency download exceeds size limit')
                dest.write(block)
                digest.update(block)
            dest.flush()
            os.fsync(dest.fileno())
    actual = digest.hexdigest()
    if expected_sha256 is not None and actual != expected_sha256:
        raise RuntimeError('download checksum mismatch; object retained: ' + str(output))
    return actual


def source_file(mirror, commit, filename, *, required=False):
    """Read a single regular Git blob at the exact commit, without checkout."""
    filename = filename[2:] if filename.startswith('./') else filename
    if (not filename or filename.startswith('/') or '..' in Path(filename).parts
            or '\x00' in filename or '\\' in filename):
        raise ValueError('unsafe dependency file path: ' + filename)
    meta = subprocess.run(['git','--git-dir',str(mirror),'ls-tree',commit,'--',filename],
                          text=True,capture_output=True,check=True).stdout.strip()
    if not meta:
        if required: raise RuntimeError('missing requirements: '+filename+' at '+commit)
        return None
    if not re.fullmatch(r'100644 blob [a-f0-9]{40}\t.+|100755 blob [a-f0-9]{40}\t.+',meta):
        raise RuntimeError('not a regular Git source file: '+filename)
    data = subprocess.check_output(['git','--git-dir',str(mirror),'show',commit+':'+filename],timeout=90)
    if len(data)>MAX_FILE: raise RuntimeError('excessive requirements file: '+filename)
    return data.decode('utf-8')


def parse_requirement_text(text, filename, resolver, *, seen=None):
    """Collect pip requirements safely; never execute pip directives or local code."""
    seen = set() if seen is None else seen
    if filename in seen: return []
    seen.add(filename)
    found=[]
    for raw in text.replace('\\\n','').splitlines():
        value=raw.strip()
        if not value or value.startswith('#'): continue
        if value.startswith(('-r ','--requirement ','-c ','--constraint ')):
            option, target = value.split(maxsplit=1)
            other = str(Path(filename).parent / target.strip())
            if target.startswith(('/', 'http:', 'https:')) or '..' in Path(target).parts:
                raise RuntimeError('external/unsafe pip requirements include: '+value)
            content=resolver(other, True)
            if content is not None:
                found.extend(parse_requirement_text(content, other, resolver,seen=seen))
            continue
        if value.startswith(('--index-url','--extra-index-url','--trusted-host','--find-links', '-f ', '-i ',
                             '--no-index','--pre','--only-binary','--no-binary')):
            raise RuntimeError('unsupported pip index/options in pinned source: '+value)
        if value.startswith(('git+https://', '-e git+https://', '--editable git+https://')):
            found.append(value.split(maxsplit=1)[-1] if value.startswith('-') else value)
            continue
        if value.startswith(('-e ', '--editable ', 'git+')):
            raise RuntimeError('dynamic VCS/editable pip dependency requires explicit source resolution: '+value)
        if value.startswith('-'):
            raise RuntimeError('unsupported pip requirement option: '+value)
        if value.startswith(('https://','http://')):
            raise RuntimeError('unconstrained remote requirements URL: '+value)
        # PEP-508 direct refs should be pinned elsewhere and verified, not executed.
        if re.search(r'\s@\s(?:git\+|https?://)', value):
            raise RuntimeError('dynamic remote PEP508 dependency: '+value)
        found.append(value)
    return found


def repo_pip_directives(item):
    found=set()
    unresolved=[]
    for line in item.get('repo_script_list',[]):
        # These strings are *data*. We extract known literals; NEVER run them.
        for m in re.finditer(r'(?<![\w-])(?:python(?:3)?\s+-m\s+)?pip(?:3)?\s+install\s+([^;\n]+)',line):
            cmd=re.split(r'\s*(?:&&|\|\||\|)\s*',m.group(1),maxsplit=1)[0].strip()
            try: tokens=shlex.split(cmd)
            except ValueError:
                unresolved.append('unparseable pip command: '+cmd);continue
            index=0
            while index<len(tokens):
                token=tokens[index]
                if token in ('-r','--requirement'):
                    if index+1>=len(tokens): unresolved.append('missing -r argument');break
                    found.add(('file',tokens[index+1]));index+=2;continue
                if token.startswith('-r') and len(token)>2:
                    found.add(('file',token[2:]));index+=1;continue
                if token in ('-e','--editable'):
                    # Project itself is already part of the exact Git source mirror.
                    if index+1<len(tokens) and (tokens[index+1] in ('.','./') or tokens[index+1].startswith('.[')):
                        index+=2;continue
                    unresolved.append('non-local editable installation: '+cmd);break
                if token in ('--no-deps','--no-build-isolation','--upgrade','-U','-q','--quiet','-v','--verbose'):
                    index+=1;continue
                if token in ('-c','--constraint'):
                    if index+1>=len(tokens): unresolved.append('missing -c argument');break
                    found.add(('file',tokens[index+1]));index+=2;continue
                if token in ('-ve','-ev') and index+1<len(tokens) and tokens[index+1] in ('.','./'):
                    index+=2;continue
                if token.startswith('-'):
                    unresolved.append('pip install option requires resolution: '+token);break
                if token == '.' or token.startswith('./') or token.startswith('.['):
                    index+=1;continue
                if token.startswith('git+https://'):
                    found.add(('git',token));index+=1;continue
                if token.startswith(('git+','http:','https:')):
                    unresolved.append('non-static pip target: '+token);break
                if token in ('install','pip'):
                    index+=1;continue
                found.add(('specifier',token));index+=1
        for m in re.finditer(r'(?:^|[;& ])(?:-r\s+)([a-zA-Z0-9_.\-/]+\.txt)',line):
            found.add(('file',m.group(1)))
    return found,unresolved


def yaml_environment(script):
    for command in script:
        m=re.search(r'cat <<\'([^\']+)\' > environment\.yml\n(.*?)\n\1(?:\n|$)',command,re.S)
        if m:
            return m.group(2)+'\n'
    return None


def split_conda_yaml(text):
    """Separate the conda input from pip's nested requirements, without executing it."""
    lines=text.splitlines(keepends=True)
    out=[];pip=[];in_pip=False
    for line in lines:
        if re.match(r'^  - pip:\s*$',line): in_pip=True;continue
        if in_pip and re.match(r'^\s{4,}-\s*',line):
            pip.append(line.split('-',1)[1].strip());continue
        if in_pip and (not line.strip() or line.lstrip().startswith('#')):
            continue
        in_pip=False
        out.append(line)
    return ''.join(out),pip


def python_version_from_script(script):
    versions=re.findall(r'\bpython\s*[= ]\s*(3\.(?:8|9|10|11|12))(?!\d)', '\n'.join(script))
    return versions[-1] if versions else None


def main(argv=None):
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root',required=True,type=Path)
    parser.add_argument('--stage',required=True,type=Path)
    parser.add_argument('--operation-id',required=True)
    args=parser.parse_args(argv)
    if os.geteuid()==0:
        raise RuntimeError('download-only fetch refuses root privileges')
    if not re.fullmatch(r'[0-9a-f]{64}', args.operation_id):
        raise RuntimeError('invalid pool operation ID')
    if args.stage.exists() or args.stage.is_symlink():
        raise RuntimeError('pool stage already exists (zombie); administrative cleanup required')
    repo_root=args.repo_root.resolve(strict=True)
    pins=json.loads((repo_root/'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/pins.json').read_text())
    contract_path=repo_root/'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/contract.json'
    if checksum(contract_path)!=pins['contract_sha256']:
        raise RuntimeError('unverified pinned SWE-Gym contract')
    data=json.loads(contract_path.read_bytes())
    tasks=data['tasks'];envs=data['environments']
    if len(tasks)!=230 or len(envs)!=25 or len({v['repo'] for v in tasks.values()})!=11:
        raise RuntimeError('unexpected SWE-Gym Lite inventory')
    subprocess.run([sys.executable,'-m','pip','--version'],check=True,stdout=subprocess.DEVNULL)
    # Create with O_EXCL semantics where possible. Never rewrite, replace or prune.
    args.stage.mkdir(mode=0o700)
    stage=args.stage
    for name in ('git','conda','wheels','npm','metadata'):
        (stage/name).mkdir(mode=0o700)
    write_new(stage/'STAGING',b'This directory is not an active pool until sealed by the broker.\n')
    # Pin the executable itself. It is only a resolver/downloader and is never
    # installed in Kali or added to the host PATH.
    resolver = stage/'micromamba-linux-64'
    fetch_url('https://github.com/mamba-org/micromamba-releases/releases/download/2.9.0-0/micromamba-linux-64',
              resolver, expected_sha256='366cd9cd8be14df1ab8ed50352a82111082a36686b2d389fdb79a92c3fafb3e3',limit=30*1024*1024)
    resolver.chmod(0o500)
    micromamba=str(resolver)
    start=time.monotonic()
    records=[]
    issues=[]
    mirrors={}
    # Git is data only; no hooks, checkouts, submodule commands or project scripts.
    grouped=defaultdict(set)
    for logical,item in tasks.items():
        if not REPO.fullmatch(item['repo']) or not COMMIT.fullmatch(item['base_commit']):
            raise RuntimeError('malformed pinned Git identity')
        grouped[item['repo']].add(item['base_commit'])
    for idx,(name,commits) in enumerate(sorted(grouped.items()),1):
        mirror=stage/'git'/(name.replace('/','_')+'.git')
        print(f'[pool] Git {idx}/{len(grouped)}: {name}, {len(commits)} exact commits',flush=True)
        run(['git','-c','protocol.file.allow=never','clone','--mirror','--','https://github.com/'+name+'.git',str(mirror)])
        mirrors[name]=mirror
        for commit in sorted(commits):
            run(['git','--git-dir',str(mirror),'cat-file','-e',commit+'^{commit}'])
    # A host-installed micromamba is a packaging tool, not a VM or Conda environment.
    pkgs=stage/'conda'/'pkgs';pkgs.mkdir()
    envroot=stage/'conda'/'plans';envroot.mkdir()
    # Mamba uses the shared local cache, so each package artifact downloads once.
    os.environ['MAMBA_ROOT_PREFIX']=str(stage/'conda'/'mamba-root')
    os.environ['CONDA_PKGS_DIRS']=str(pkgs)
    all_versions={}
    for ix,version in enumerate(PYTHONS,1):
        print(f'[pool] Python {ix}/5: {version}',flush=True)
        command=[micromamba,'create','--yes','--download-only','--strict-channel-priority',
                 '-c','conda-forge','--root-prefix',str(stage/'conda'/'mamba-root'),
                 '--prefix',str(envroot/('python-'+version)), 'python='+version,'pip']
        run(command)
    requirements_by_py=defaultdict(set)
    requirements_by_env=defaultdict(set)
    vcs_requirements=set()
    for idx,(env_id,entry) in enumerate(sorted(envs.items()),1):
        script=entry['original_script']
        version=python_version_from_script(script)
        if version is None:
            raise RuntimeError('Conda recipe has no determinable Python version: '+env_id)
        all_versions[env_id]=version
        yml=yaml_environment(script)
        if yml is not None:
            conda_yml,pipreqs=split_conda_yaml(yml)
            yml_path=envroot/('recipe-'+env_id+'.yaml')
            write_new(yml_path,conda_yml.encode())
            cmd=[micromamba,'create','--yes','--download-only','--strict-channel-priority',
                 '--root-prefix',str(stage/'conda'/'mamba-root'),
                 '--prefix',str(envroot/('recipe-'+env_id)),
                 '--file',str(yml_path)]
            # A few upstream jobs create their environment and subsequently change Python.
            # Resolve final Python separately as a constraint for the download closure.
            cmd+=['python='+version]
            print(f'[pool] Conda recipe {idx}/25, Python {version}',flush=True)
            run(cmd)
            for package in pipreqs:
                if package.startswith('git+https://'):
                    vcs_requirements.add(package)
                elif package and not package.startswith('#'):
                    requirements_by_env[env_id].add(package)
        else:
            print(f'[pool] Conda recipe {idx}/25: Python {version} already in base pool',flush=True)
    # Every repo is scanned at the exact task base_commit; task setup scripts are
    # treated as untrusted DATA and are never run by this fetcher.
    requirements_by_task={}
    for idx,(logical,item) in enumerate(sorted(tasks.items()),1):
        mirror=mirrors[item['repo']];commit=item['base_commit']
        version=all_versions[item['env_hash']]
        requested=set(requirements_by_env[item['env_hash']])
        directives,problem=repo_pip_directives(item)
        issues.extend(f'{logical}: {v}' for v in problem)
        def resolve(path,required=False):
            return source_file(mirror,commit,path,required=required)
        for kind,value in sorted(directives):
            if kind=='file':
                try:
                    content=resolve(value,True)
                    for dep in parse_requirement_text(content,value,resolve):
                        if dep.startswith('git+https://'):vcs_requirements.add(dep)
                        else:requested.add(dep)
                except (ValueError,RuntimeError) as exc:
                    issues.append(f'{logical}: {exc}')
            elif kind=='git':
                vcs_requirements.add(value)
            else:
                requested.add(value)
        # Static pyproject.toml dependency arrays; dynamic dependencies are reported.
        pyproject=resolve('pyproject.toml')
        if pyproject:
            try:
                project=tomllib.loads(pyproject).get('project',{})
                if 'dependencies' in project:
                    requested.update(project['dependencies'])
                if 'dependencies' in project.get('dynamic',[]):
                    issues.append(f'{logical}: dynamic pyproject dependencies')
            except (ValueError,TypeError) as exc:
                issues.append(f'{logical}: pyproject metadata unreadable: {exc}')
        requirements_by_task[logical]=(version,tuple(sorted(requested)))
        if idx % 20==0: print(f'[pool] Read pinned requirements {idx}/230',flush=True)
    # Do NOT combine requirements of unrelated tasks: they may pin conflicting
    # versions. Every compatible requirement set resolves independently against
    # the same physical download destination, providing filename-level reuse.
    groups={}
    for logical, (version,reqs) in sorted(requirements_by_task.items()):
        key=(version,reqs)
        groups.setdefault(key,[]).append(logical)
    for ix,((version,reqs),members) in enumerate(groups.items(),1):
        if not reqs: continue
        reqname='pip-'+str(ix).zfill(4)+'.txt'
        reqpath=stage/'metadata'/reqname
        write_new(reqpath, ('\n'.join(reqs)+'\n').encode())
        print(f'[pool] Wheel closure {ix}/{len(groups)}, Python {version}, {len(reqs)} specs, {len(members)} tasks',flush=True)
        command=[sys.executable,'-m','pip','download','--disable-pip-version-check',
                 '--only-binary=:all:','--implementation','cp','--python-version',version,
                 '--abi','cp'+version.replace('.',''),'--platform','manylinux2014_x86_64',
                 '--dest',str(stage/'wheels'),'-r',str(reqpath)]
        try: run(command)
        except subprocess.CalledProcessError as exc:
            issues.append(f'Python {version}, task {members[0]}: pip binary closure unavailable: {exc}')
    # Fetch pinned VCS requirements as source data, not through pip build hooks.
    # Mutable upstream refs are frozen to the commit actually downloaded.
    vcs_frozen={}
    (stage/'git-extra').mkdir()
    for dependency in sorted(vcs_requirements):
        value=dependency.removeprefix('git+')
        value=value.split('#',1)[0]
        parsed=urllib.parse.urlsplit(value)
        clean=urllib.parse.urlunsplit((parsed.scheme,parsed.netloc,parsed.path,'',''))
        if parsed.scheme!='https' or parsed.hostname!='github.com' or parsed.username or parsed.password:
            issues.append('untrusted VCS package: '+dependency);continue
        repo_part=parsed.path.lstrip('/')
        commit=None
        if '@' in repo_part:
            repo_part,commit=repo_part.rsplit('@',1)
        repo_part=repo_part.removesuffix('.git')
        if not REPO.fullmatch(repo_part) or (commit is not None and not COMMIT.fullmatch(commit)):
            issues.append('non-commit/invalid VCS package: '+dependency);continue
        target=stage/'git-extra'/(hashlib.sha256(repo_part.encode()).hexdigest()[:12]+'.git')
        if not target.exists():
            run(['git','-c','protocol.file.allow=never','clone','--mirror','--',
                 'https://github.com/'+repo_part+'.git',str(target)])
        resolved=commit or subprocess.check_output(['git','--git-dir',str(target),'rev-parse','HEAD'],text=True).strip()
        run(['git','--git-dir',str(target),'cat-file','-e',resolved+'^{commit}'])
        vcs_frozen[dependency]=resolved
        # Downloading Git bytes is supported; resolving its transitive build-time
        # Python dependencies requires a separate non-executing package analyzer.
        issues.append('transitive dependencies of pinned VCS source require resolution: '+dependency)
    write_new(stage/'metadata'/'vcs-frozen.json',(json.dumps(vcs_frozen,sort_keys=True,indent=2)+'\n').encode())
    # NPM lockfiles with integrity-pinned tarballs are downloadable as opaque data.
    npmseen={}
    for repo,commits in sorted(grouped.items()):
        mirror=mirrors[repo]
        for commit in sorted(commits):
            for path in ('package-lock.json','bokehjs/package-lock.json'):
                content=source_file(mirror,commit,path)
                if not content:continue
                try: lock=json.loads(content)
                except ValueError:
                    issues.append(repo+': invalid npm lockfile at '+commit);continue
                nodes=list((lock.get('packages') or {}).values())
                if not nodes: nodes=list((lock.get('dependencies') or {}).values())
                for value in nodes:
                    if not isinstance(value,dict) or not value.get('resolved'):continue
                    url=value['resolved'];integ=value.get('integrity')
                    parsed=urllib.parse.urlsplit(url)
                    if parsed.scheme!='https' or parsed.hostname!='registry.npmjs.org' or not integ:
                        issues.append(repo+': npm tarball lacks trusted origin/integrity: '+str(url)[:140]);continue
                    if url in npmseen:continue
                    npmseen[url]=integ
    for ix,(url,integrity) in enumerate(sorted(npmseen.items()),1):
        path=stage/'npm'/(hashlib.sha256(url.encode()).hexdigest()+'.tgz')
        actual=fetch_url(url,path)
        # Validate SRI sha512/sha384/sha256 when specified.
        algo,sep,encoded=integrity.partition('-')
        if algo not in ('sha512','sha384','sha256') or not sep:
            raise RuntimeError('unsupported npm package integrity record')
        h=hashlib.new(algo)
        with path.open('rb') as f:
            for chunk in iter(lambda:f.read(1048576),b''): h.update(chunk)
        if base64.b64encode(h.digest()).decode()!=encoded.split()[0]:
            raise RuntimeError('npm SRI integrity mismatch (file retained)')
        if ix%50==0: print(f'[pool] npm tarballs {ix}/{len(npmseen)}',flush=True)
    # APT and PDM/pipx/git+ packages can require runtime-side resolution. Never
    # pretend the closure is complete when those inputs were not resolved.
    for logical,item in tasks.items():
        for command in item['repo_script_list']:
            if re.search(r'\b(?:apt-get|apt|pdm|pipx|make init|git submodule)\b',command):
                issues.append(f'{logical}: additional non-Python dependency resolver required: '+command[:150])
    for path in sorted(stage.rglob('*')):
        if path.is_symlink():
            if os.path.isabs(os.readlink(path)):
                raise RuntimeError('absolute symlink in Conda cache: '+str(path))
            target=(path.parent/os.readlink(path)).resolve()
            if not target.is_relative_to(stage.resolve()):
                raise RuntimeError('escaping symlink in Conda cache: '+str(path))
            records.append({'path':path.relative_to(stage).as_posix(),
                            'type':'symlink','target':os.readlink(path)})
            continue
        if path.is_file() and path.name!='STAGING':
            records.append(inventory_file(path,stage))
    summary={'schema':1,'kind':'download-only-pool','complete':not issues,
             'tasks':len(tasks),'repos':len(grouped),'conda_recipes':len(envs),
             'python_versions':list(PYTHONS), 'files':records,
             'issues':sorted(set(issues)), 'elapsed_seconds':round(time.monotonic()-start,1)}
    write_new(stage/'inventory.json',(json.dumps(summary,sort_keys=True,indent=2)+'\n').encode())
    print(f'[pool] downloaded objects={len(records)}, unresolved requirements={len(set(issues))}',flush=True)
    if issues:
        raise RuntimeError('dependency pool INCOMPLETE; inspect inventory.json, explicit admin cleanup required. First issue: '+sorted(set(issues))[0])
    return summary


if __name__=='__main__':
    try: main()
    except BaseException as exc:
        print('[pool] FAILED; incomplete artifacts retained, no retry/automatic cleanup: '+str(exc),file=sys.stderr,flush=True)
        raise
