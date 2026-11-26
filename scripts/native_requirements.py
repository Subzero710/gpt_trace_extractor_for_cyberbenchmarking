"""Native requirements observed in locked CPython public headers.

This is a discovery probe, not a proof of arbitrary source builds. The probe
uses the execution host's GCC front end with the sealed guest system headers,
without the execution host's system include directories.
"""
from __future__ import annotations

import ast
import hashlib
import gzip
import lzma
import os
import posixpath
import re
import shlex
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


_PACKAGE = re.compile(r'[a-z0-9][a-z0-9+.-]*\Z')
_HEADER = re.compile(r'[A-Za-z0-9_.+/-]+\Z')


def upstream_base_packages(path, expected_sha, parse_apt):
    raw = Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha:
        raise RuntimeError('upstream base Dockerfile differs from the pinned harness')
    tree = ast.parse(raw)
    rows = [node.value for node in tree.body if isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == '_DOCKERFILE_BASE' for t in node.targets)]
    if len(rows) != 1:
        raise RuntimeError('missing unique pinned upstream base Dockerfile')
    dockerfile = ast.literal_eval(rows[0])
    if not isinstance(dockerfile, str):
        raise RuntimeError('upstream base Dockerfile is not a literal string')
    commands = [line.strip()[4:] for line in re.sub(r'\\\r?\n', ' ', dockerfile).splitlines()
                if line.strip().startswith('RUN ')]
    packages, upgrades = parse_apt(commands)
    if not packages or upgrades:
        raise RuntimeError('upstream base Dockerfile has no explicit install roots or requests upgrades')
    return packages


def _relative(name):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or '\x00' in name:
        raise RuntimeError('unsafe archive member: ' + name)
    return path


def _extract_headers(archive, destination, *, conda):
    """Copy the actual header tree once; never follow an archive link on the host."""
    destination = Path(destination)
    destination.mkdir(parents=True)
    links = []
    with archive:
        for item in archive:
            name = _relative(item.name)
            if conda:
                if not name.parts or name.parts[0] != 'include':
                    continue
                name = PurePosixPath(*name.parts[1:])
            if not name.parts:
                continue
            target = destination.joinpath(*name.parts)
            if item.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif item.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(item) as src, target.open('xb') as dst:
                    shutil.copyfileobj(src, dst)
            elif item.issym() or item.islnk():
                links.append((name, item.linkname, item.islnk()))
            else:
                raise RuntimeError('unsupported header archive member: ' + item.name)
    # Rebase guest-absolute links and refuse to follow links outside this tree.
    # External symlinks are represented as unavailable, not resolved via the host.
    for name, raw, hard in links:
        target = destination.joinpath(*name.parts)
        if hard:
            source = _relative(raw)
            if conda:
                if not source.parts or source.parts[0] != 'include':
                    continue
                source = PurePosixPath(*source.parts[1:])
            relative = source.as_posix()
        elif raw.startswith('/'):
            if conda or not raw.startswith('/usr/include/'):
                continue
            relative = raw.removeprefix('/usr/include/')
        else:
            relative = posixpath.normpath(posixpath.join(name.parent.as_posix(), raw))
        if relative == '..' or relative.startswith('../') or relative.startswith('/'):
            continue
        source = destination.joinpath(*_relative(relative).parts)
        if any(parent.is_symlink() for parent in target.parents if parent != destination.parent):
            raise RuntimeError('symlink ancestor of header link: ' + name.as_posix())
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() or target.is_symlink():
            raise RuntimeError('duplicate header archive member: ' + name.as_posix())
        if hard:
            if not source.is_file() or source.is_symlink():
                raise RuntimeError('missing header hardlink source: ' + raw)
            os.link(source, target)
        else:
            target.symlink_to(os.path.relpath(source, target.parent))


def extract_golden(archive, destination):
    with tarfile.open(archive, 'r:*') as source:
        _extract_headers(source, destination, conda=False)


def extract_conda(archive, destination, *, filename):
    if filename.endswith('.tar.bz2'):
        with tarfile.open(archive, 'r|bz2') as source:
            _extract_headers(source, destination, conda=True)
    elif filename.endswith('.conda'):
        # unzip and zstd stream the payload without writing a second archive.
        with zipfile.ZipFile(archive) as package:
            members = [name for name in package.namelist() if name.startswith('pkg-') and name.endswith('.tar.zst')]
            if len(members) != 1:
                raise RuntimeError('missing unique Conda payload stream')
        with subprocess.Popen(['unzip', '-p', str(archive), members[0]], stdout=subprocess.PIPE) as unzip:
            try:
                with subprocess.Popen(['zstd', '-dc'], stdin=unzip.stdout, stdout=subprocess.PIPE) as zstd:
                    unzip.stdout.close()
                    try:
                        with tarfile.open(fileobj=zstd.stdout, mode='r|') as source:
                            _extract_headers(source, destination, conda=True)
                        # Drain tar padding and any remaining payload before checking exit status.
                        while zstd.stdout.read(1024 * 1024):
                            pass
                    except BaseException:
                        zstd.kill()
                        raise
                if zstd.returncode:
                    raise RuntimeError('Conda zstd payload decompression failed')
            except BaseException:
                if unzip.poll() is None:
                    unzip.kill()
                raise
        if unzip.returncode:
            raise RuntimeError('Conda zip payload extraction failed')
    else:
        raise RuntimeError('unsupported locked Conda archive format: ' + filename)


def compiler_profile(compiler, architecture, *, timeout):
    env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
    def query(flag):
        return subprocess.check_output([str(compiler), flag], env=env, text=True, timeout=timeout).strip()
    machine = query('-dumpmachine')
    multiarch = query('-print-multiarch')
    builtin = Path(query('-print-file-name=include'))
    fixed = Path(query('-print-file-name=include-fixed'))
    if (machine.split('-', 1)[0] != architecture or not multiarch
            or not re.fullmatch(r'[a-zA-Z0-9_-]+', multiarch) or not builtin.is_absolute() or not builtin.is_dir()):
        raise RuntimeError('compiler discovery profile does not match target architecture')
    return {'compiler': str(compiler), 'machine': machine, 'multiarch': multiarch,
            'builtin': [str(builtin)] + ([str(fixed)] if fixed.is_absolute() and fixed.is_dir() else []),
            'version': query('-dumpfullversion')}


def missing_python_headers(python_include, golden_include, profile, *, timeout):
    python_include, golden_include = Path(python_include), Path(golden_include)
    headers = sorted(python_include.glob('*/Python.h'))
    if len(headers) != 1 or not headers[0].is_file():
        raise RuntimeError('missing unique public header in locked CPython artifact')
    env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
    command = [profile['compiler'], '-M', '-MG', '-MT', 'native_probe', '-nostdinc', '-x', 'c',
               '-I', str(headers[0].parent)]
    roots = [*map(Path, profile['builtin']), golden_include / profile['multiarch'], golden_include]
    for root in roots:
        command.extend(('-isystem', str(root)))
    command.append('-')
    result = subprocess.run(command, input='#include <Python.h>\n', capture_output=True,
                            text=True, env=env, timeout=timeout)
    if result.returncode:
        raise RuntimeError('CPython native discovery failed: ' + result.stderr)
    raw = result.stdout.replace('\\\n', ' ')
    if not raw.startswith('native_probe:'):
        raise RuntimeError('invalid compiler dependency output')
    missing = set()
    allowed = [python_include.resolve(), golden_include.resolve(), *[Path(p).resolve() for p in profile['builtin']]]
    for value in shlex.split(raw.split(':', 1)[1]):
        path = Path(value)
        if path.is_absolute():
            if not any(path.resolve().is_relative_to(root) for root in allowed) or not path.is_file():
                raise RuntimeError('dependency probe escaped its declared header roots: ' + value)
        else:
            if not _HEADER.fullmatch(value) or '..' in PurePosixPath(value).parts or value.startswith('./'):
                raise RuntimeError('unresolvable compiler header token: ' + value)
            missing.add(value)
    return {'public_header': headers[0].relative_to(python_include).as_posix(), 'missing': sorted(missing)}


def candidate_paths(headers, multiarch):
    if not re.fullmatch(r'[a-zA-Z0-9_-]+', multiarch):
        raise RuntimeError('invalid target multiarch identity')
    result = {}
    for header in headers:
        if not _HEADER.fullmatch(header) or header.startswith('/') or '..' in PurePosixPath(header).parts:
            raise RuntimeError('invalid native header requirement')
        result[header] = {f'usr/include/{header}', f'usr/include/{multiarch}/{header}'}
    return result


def contents_matches(lines, candidates):
    wanted = set().union(*candidates.values()) if candidates else set()
    result = {header: set() for header in candidates}
    by_path = {}
    for header, paths in candidates.items():
        for path in paths:
            by_path.setdefault(path, set()).add(header)
    for line in lines:
        fields = line.split()
        if len(fields) != 2 or fields[0] not in wanted:
            continue
        path, providers = fields
        for value in providers.split(','):
            package = value.rsplit('/', 1)[-1]
            if not _PACKAGE.fullmatch(package):
                raise RuntimeError('invalid signed Contents package: ' + value)
            for header in by_path[path]:
                result[header].add((package, path))
    return result


def unique_providers(matches, roots):
    result = {}
    for header, rows in sorted(matches.items()):
        packages = {package for package, _ in rows}
        selected = packages & set(roots)
        if len(selected) == 1:
            package = next(iter(selected))
        elif len(packages) == 1:
            package = next(iter(packages))
        else:
            raise RuntimeError('no unique compatible signed provider for ' + header + ': ' + repr(sorted(rows)))
        result[header] = {'package': package, 'paths': sorted(path for name, path in rows if name == package)}
    return result


def installed_packages(status):
    result = set()
    for paragraph in status.decode('utf-8').split('\n\n'):
        fields = dict(line.split(': ', 1) for line in paragraph.splitlines()
                      if line and not line[0].isspace() and ': ' in line)
        if fields.get('Status') == 'install ok installed':
            name, arch = fields['Package'], fields['Architecture']
            result.update((name, name + ':' + arch))
    return result


def signed_contents(release, suite, components, architecture):
    # gpgv has already authenticated the exact Release bytes. Select an actual
    # signed compressed index for every enabled component and architecture.
    fields = {}
    hashes = {}
    in_sha256 = False
    for line in release.splitlines():
        if line and not line[0].isspace():
            key, sep, value = line.partition(':')
            if not sep:
                raise RuntimeError('invalid signed Release field')
            fields[key] = value.strip()
            in_sha256 = key == 'SHA256'
        elif in_sha256 and line.strip():
            parts = line.split()
            if len(parts)!=3 or not re.fullmatch(r'[a-f0-9]{64}', parts[0]) or not parts[1].isdigit():
                raise RuntimeError('invalid signed SHA256 index entry')
            sha, size, path = parts
            if path in hashes:
                raise RuntimeError('duplicate signed Release path')
            hashes[path] = {'sha256': sha, 'size': int(size)}
    if suite not in (fields.get('Suite'), fields.get('Codename')) or architecture not in fields.get('Architectures','').split():
        raise RuntimeError('signed Kali Release target differs from Golden architecture/suite')
    if not set(components) <= set(fields.get('Components','').split()):
        raise RuntimeError('signed Kali Release components differ from requested sources')
    selected = {}
    for component in components:
        for arch in (architecture, 'all'):
            stem = component+'/Contents-'+arch
            available = {stem+ext: hashes[stem+ext] for ext in ('.gz','.xz') if stem+ext in hashes}
            if available:
                path = min(available, key=lambda name: (available[name]['size'], name))
                selected[path] = available[path]
            elif arch==architecture:
                raise RuntimeError('signed Contents index missing for '+stem)
    if not selected:
        raise RuntimeError('no signed Contents index selected')
    return selected


def query_index(path, candidates, relative):
    compression = {'.gz': gzip.open, '.xz': lzma.open}[Path(relative).suffix]
    with compression(path, 'rt', encoding='utf-8') as stream:
        result = contents_matches(stream, candidates)
    return {name: sorted(rows) for name, rows in result.items()}


# Archive inspection. No build hooks, imports, or ELF execution are performed.
def _read_at(stream, offset, size):
    if offset < 0 or size < 0:
        raise RuntimeError('invalid ELF range')
    stream.seek(offset)
    data = stream.read(size)
    if len(data) != size:
        raise RuntimeError('truncated ELF data')
    return data


def elf_dynamic(stream, size):
    import struct
    ident = _read_at(stream, 0, 16)
    if ident[:4] != b'\x7fELF' or ident[4] not in (1, 2) or ident[5] not in (1, 2):
        raise RuntimeError('unsupported ELF encoding')
    endian = '<' if ident[5] == 1 else '>'
    wide = ident[4] == 2
    header = struct.Struct(endian + ('HHIQQQIHHHHHH' if wide else 'HHIIIIIHHHHHH'))
    fields = header.unpack(_read_at(stream, 16, header.size))
    machine, phoff, entsize, count = fields[1], fields[4], fields[8], fields[9]
    ph = struct.Struct(endian + ('IIQQQQQQ' if wide else 'IIIIIIII'))
    if count == 65535 or (count and entsize != ph.size) or phoff + count * entsize > size:
        raise RuntimeError('unsupported ELF program header table')
    loads, dynamic = [], []
    for i in range(count):
        row = ph.unpack(_read_at(stream, phoff + i * entsize, ph.size))
        kind = row[0]
        offset, vaddr, length = (row[2], row[3], row[5]) if wide else (row[1], row[2], row[4])
        if offset + length > size:
            raise RuntimeError('ELF segment exceeds file')
        if kind == 1:
            loads.append((vaddr, offset, length))
        elif kind == 2:
            dynamic.append((offset, length))
    result = {'machine': machine, 'bits': 64 if wide else 32, 'needed': [], 'soname': [], 'rpath': [], 'runpath': [], 'flags_1': 0}
    if not dynamic:
        return result
    if len(dynamic) != 1:
        raise RuntimeError('multiple ELF dynamic segments')
    entry = struct.Struct(endian + ('qQ' if wide else 'iI'))
    offset, length = dynamic[0]
    if length % entry.size:
        raise RuntimeError('invalid ELF dynamic segment length')
    tags = {}
    # Read entries sequentially rather than repeatedly seeking inside a ZIP stream.
    stream.seek(offset)
    for _ in range(length // entry.size):
        raw = stream.read(entry.size)
        if len(raw) != entry.size:
            raise RuntimeError('truncated ELF dynamic entry')
        tag, value = entry.unpack(raw)
        if tag == 0:
            break
        tags.setdefault(tag, []).append(value)
    strings = {1: 'needed', 14: 'soname', 15: 'rpath', 29: 'runpath'}
    if any(tag in tags for tag in strings):
        if len(tags.get(5, [])) != 1 or len(tags.get(10, [])) != 1:
            raise RuntimeError('missing ELF dynamic string table')
        addr, length = tags[5][0], tags[10][0]
        regions = {offset + addr - vaddr for vaddr, offset, span in loads
                   if vaddr <= addr and addr + length <= vaddr + span}
        if len(regions) != 1 or length > size:
            raise RuntimeError('ELF dynamic string table is not file backed')
        data = _read_at(stream, regions.pop(), length)
        for tag, key in strings.items():
            for index in tags.get(tag, []):
                end = data.find(b'\0', index)
                if not 0 <= index < end:
                    raise RuntimeError('invalid ELF dynamic string')
                result[key].append(data[index:end].decode('utf-8'))
    for flags in tags.get(0x6ffffffb, []):
        result['flags_1'] |= flags
    return result


def inspect_wheel(path):
    result = {}
    with zipfile.ZipFile(path) as archive:
        seen = set()
        for member in archive.infolist():
            name = _relative(member.filename).as_posix()
            if name in seen:
                raise RuntimeError('duplicate wheel member: ' + name)
            seen.add(name)
            if member.is_dir():
                continue
            with archive.open(member) as stream:
                if stream.read(4) == b'\x7fELF':
                    result[name] = elf_dynamic(stream, member.file_size)
    return result


def _literal_extension_declarations(text):
    """Report literal Extension calls; never claim a dynamic setup.py is solved."""
    tree = ast.parse(text)
    declarations = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not ((isinstance(func, ast.Name) and func.id == 'Extension') or
                (isinstance(func, ast.Attribute) and func.attr == 'Extension')):
            continue
        record = {'line': node.lineno, 'literal': {}, 'dynamic': []}
        for arg in node.keywords:
            if arg.arg not in ('sources', 'include_dirs', 'library_dirs', 'libraries', 'define_macros',
                               'undef_macros', 'extra_compile_args', 'extra_link_args', 'extra_objects', 'language'):
                continue
            try:
                record['literal'][arg.arg] = ast.literal_eval(arg.value)
            except (ValueError, TypeError, SyntaxError):
                record['dynamic'].append(arg.arg)
        if len(node.args) >= 2 and 'sources' not in record['literal'] and 'sources' not in record['dynamic']:
            try:
                record['literal']['sources'] = ast.literal_eval(node.args[1])
            except (ValueError, TypeError, SyntaxError):
                record['dynamic'].append('sources')
        if any(arg.arg is None for arg in node.keywords) or any(isinstance(arg, ast.Starred) for arg in node.args):
            record['dynamic'].append('expanded_arguments')
        declarations.append(record)
    return declarations


def inspect_sdist(path, filename):
    """Read declared build inputs and source include candidates, without running setup.

    Include candidates are deliberately not APT roots: generated, inactive,
    vendored and Conda-provided includes must be distinguished by a real build.
    """
    import email.parser
    import tomllib
    import configparser
    result = {'metadata': {}, 'extensions': {}, 'build_files': [], 'includes': {}, 'native_files': [],
              'coverage': 'declarations-and-include-candidates-not-a-build-proof'}
    build_names = {'setup.py', 'setup.cfg', 'pyproject.toml', 'CMakeLists.txt', 'meson.build', 'configure.ac', 'configure.in', 'Cargo.toml', 'Makefile'}
    native_suffixes = {'.c', '.h', '.cc', '.cpp', '.cxx', '.hpp', '.hxx', '.f', '.f90', '.pyx', '.pxd', '.rs'}
    include_re = re.compile(r'^\s*#\s*include\s*([<"])([^>"\n]+)[>"]', re.M)
    seen = set()
    def consume(name, member, size):
        relative = _relative(name)
        if relative.as_posix() in seen:
            raise RuntimeError('duplicate source archive member: ' + name)
        seen.add(relative.as_posix())
        if relative.suffix in native_suffixes:
            result['native_files'].append(relative.as_posix())
        elif relative.name not in build_names and relative.name != 'PKG-INFO':
            return
        # Large generated source files are inspected in bounded chunks; only
        # metadata files are decoded as a whole. Never execute their contents.
        if relative.suffix in native_suffixes:
            candidates = set()
            for line in member:
                value = line.decode('utf-8', errors='replace')
                for match in include_re.finditer(value):
                    candidates.add((match[1], match[2]))
            if candidates:
                result['includes'][relative.as_posix()] = sorted(candidates)
            return
        raw = member.read()
        if len(raw) != size:
            raise RuntimeError('truncated source metadata: ' + name)
        if relative.name == 'PKG-INFO':
            parsed = email.parser.BytesParser().parsebytes(raw)
            external = parsed.get_all('Requires-External', [])
            if external:
                result['metadata'][relative.as_posix()] = {'requires_external': external}
            return
        result['build_files'].append(relative.as_posix())
        text = raw.decode('utf-8', errors='replace')
        if relative.name == 'setup.py':
            try:
                result['extensions'][relative.as_posix()] = _literal_extension_declarations(text)
            except SyntaxError:
                result['extensions'][relative.as_posix()] = {'unparsed': 'Python syntax not supported by host AST'}
        elif relative.name == 'pyproject.toml':
            data = tomllib.loads(text)
            if 'build-system' in data:
                result['metadata'][relative.as_posix()] = {'build-system': data['build-system']}
        elif relative.name == 'setup.cfg':
            cfg = configparser.ConfigParser(interpolation=None)
            cfg.read_string(text)
            if cfg.has_section('build_ext'):
                result['metadata'][relative.as_posix()] = {'build_ext': dict(cfg.items('build_ext', raw=True))}
        elif relative.name in ('CMakeLists.txt', 'meson.build', 'configure.ac', 'configure.in'):
            # Keep the original literal lines, not guessed package mappings.
            calls = re.findall(r'^\s*(?:find_package|find_library|find_path|find_program|dependency|AC_CHECK_HEADERS?|AC_CHECK_LIB|PKG_CHECK_MODULES)\s*\([^\n]*', text, re.M | re.I)
            if calls:
                result['metadata'][relative.as_posix()] = {'native_declaration_candidates': calls}
    if filename.endswith('.zip'):
        with zipfile.ZipFile(path) as archive:
            for row in archive.infolist():
                _relative(row.filename)
                if not row.is_dir():
                    with archive.open(row) as member:
                        consume(row.filename, member, row.file_size)
    else:
        with tarfile.open(path, 'r|*') as archive:
            for row in archive:
                _relative(row.name)
                if row.isfile():
                    with archive.extractfile(row) as member:
                        consume(row.name, member, row.size)
    result['build_files'].sort()
    result['native_files'].sort()
    return result




def conda_inventory(path, filename):
    """Read package-owned file paths without extracting the package payload."""
    import io
    def read(archive):
        with archive:
            for item in archive:
                if _relative(item.name).as_posix() == 'info/files' and item.isfile():
                    with archive.extractfile(item) as stream:
                        return sorted({_relative(line).as_posix() for line in stream.read().decode('utf-8').splitlines() if line})
        raise RuntimeError('locked Conda package has no info/files inventory')
    if filename.endswith('.tar.bz2'):
        return read(tarfile.open(path, 'r|bz2'))
    if not filename.endswith('.conda'):
        raise RuntimeError('unsupported Conda inventory format')
    with zipfile.ZipFile(path) as archive:
        members = [name for name in archive.namelist() if name.startswith('info-') and name.endswith('.tar.zst')]
        if len(members) != 1:
            raise RuntimeError('invalid Conda info archive')
        raw = subprocess.run(['zstd', '-dc'], input=archive.read(members[0]), stdout=subprocess.PIPE, check=True).stdout
    return read(tarfile.open(fileobj=io.BytesIO(raw), mode='r:'))


def native_candidates(inspections, multiarch):
    """Keep candidate evidence separate from proven mandatory requirements."""
    apt, conda, origins = {}, {}, {}
    def add(kind, name, sha, file):
        if not isinstance(name, str) or not _HEADER.fullmatch(name) or name.startswith('/') or '..' in PurePosixPath(name).parts:
            return
        key = kind + ':' + name
        if kind == 'header':
            apt[key] = candidate_paths([name], multiarch)[name]
            conda[key] = {'include/' + name, 'include/' + multiarch + '/' + name}
        else:
            if '/' in name:
                return
            names = {name} if kind == 'soname' else {'lib' + name + '.so', 'lib' + name + '.a'}
            apt[key] = {prefix + '/' + leaf for prefix in ('lib', 'usr/lib', 'lib/' + multiarch, 'usr/lib/' + multiarch) for leaf in names}
            conda[key] = {prefix + '/' + leaf for prefix in ('lib', 'lib/' + multiarch) for leaf in names}
        origins.setdefault(key, set()).add((sha, file))
    for sha, row in inspections.items():
        for file, elf in row.get('elf', {}).items():
            for name in elf['needed']:
                add('soname', name, sha, file)
        source = row.get('source', {})
        own_files = set(source.get('native_files', ()))
        own_suffixes = {suffix for file in own_files for suffix in (file, file.split('/', 1)[-1], PurePosixPath(file).name)}
        for file, includes in source.get('includes', {}).items():
            for style, name in includes:
                if style == '<' and name not in own_suffixes:
                    add('header', name, sha, file)
        for file, declarations in source.get('extensions', {}).items():
            if not isinstance(declarations, list):
                continue
            for declaration in declarations:
                libraries = declaration['literal'].get('libraries', [])
                if isinstance(libraries, (list, tuple)):
                    for library in libraries:
                        add('link', library, sha, file)
    return {'apt': {key: sorted(paths) for key, paths in apt.items()},
            'conda': {key: sorted(paths) for key, paths in conda.items()},
            'origins': {key: sorted(rows) for key, rows in origins.items()}}


if __name__ == '__main__':
    import json
    import sys
    command, *args = sys.argv[1:]
    if command == 'conda-headers' and len(args) == 3:
        extract_conda(args[0], args[1], filename=args[2])
    elif command == 'golden-headers' and len(args) == 2:
        extract_golden(*args)
    elif command == 'contents' and len(args) == 3:
        print(json.dumps(query_index(args[0], {name: set(paths) for name, paths in json.loads(args[1]).items()}, args[2])))
    elif command == 'conda-inventory' and len(args) == 2:
        print(json.dumps(conda_inventory(args[0], args[1])))
    elif command == 'contents-file' and len(args) == 3:
        print(json.dumps(query_index(args[0], {name: set(paths) for name, paths in json.loads(Path(args[1]).read_bytes()).items()}, args[2])))
    elif command == 'inspect-pip' and len(args) == 3:
        path, filename, kind = args
        if kind == 'wheel':
            result = {'elf': inspect_wheel(path)}
        elif kind == 'sdist':
            result = {'source': inspect_sdist(path, filename)}
        else:
            raise RuntimeError('invalid Pip artifact kind')
        print(json.dumps(result, sort_keys=True, default=str))
    else:
        raise SystemExit('invalid native discovery command')
