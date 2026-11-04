"""Mutation sensitivity of general integrity and admission properties.

Every equality/identity comparison in a selected boundary is mutated in an
independent in-memory code copy. Production modules and files are never edited.
Equivalent/surviving mutants are counted explicitly rather than called covered.
"""
import ast
import copy
import hashlib
import inspect
from pathlib import Path
import tempfile
import textwrap
from types import MethodType

import pytest

import superbench_pool as pool
from workstation_broker import preparation as jobs
from test_pipeline_properties import isolated_pool


def comparison_mutants(function):
    source = ast.parse(textwrap.dedent(inspect.getsource(function)))
    opposites = {ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.Is: ast.IsNot, ast.IsNot: ast.Is,
                 ast.In: ast.NotIn, ast.NotIn: ast.In}
    candidates = [(index, position, type(operator)) for index, node in enumerate(ast.walk(source))
                  if isinstance(node, ast.Compare) for position, operator in enumerate(node.ops)
                  if type(operator) in opposites]
    for index, position, original in candidates:
        tree = copy.deepcopy(source)
        node = list(ast.walk(tree))[index]
        node.ops[position] = opposites[original]()
        namespace = dict(function.__globals__)
        exec(compile(ast.fix_missing_locations(tree), '<isolated-contract-mutant>', 'exec'), namespace)
        yield namespace[function.__name__]


def accepts(operation, *args, **kwargs):
    try:
        operation(*args, **kwargs)
    except Exception:
        return False
    return True


def cas_probe(function):
    with isolated_pool() as candidate:
        data = b'generated integrity probe'
        sha = hashlib.sha256(data).hexdigest()
        source = candidate.stage / 'source'; source.write_bytes(data)
        candidate.put(source, 'contract', 'source')
        # A fresh verifier must exercise the expensive checksum branch.
        # Otherwise a cached signature masks violations of the cold path.
        candidate._verified_signatures.pop(sha, None)
        verify = MethodType(function, candidate)
        if not accepts(verify, sha):
            return False
        source.write_bytes(bytes(value ^ 1 for value in data))
        return not accepts(verify, sha)


def endpoint_probe(function):
    valid = 'https://pypi.org/simple/generated/'
    invalid = ['http://pypi.org/simple/generated/', 'https://other.test/simple/generated/',
               'https://user:secret@pypi.org/simple/generated/', 'https://pypi.org:444/simple/',
               'https://pypi.org/simple/#fragment', 'https://pypi.org/simple/\n']
    return accepts(function, valid, 'pypi.org') and not any(
        accepts(function, value, 'pypi.org') for value in invalid)


def publication_probe(function):
    import os
    if os.geteuid() != 0:
        pytest.skip('root-owned publication contract requires root')
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        operation = hashlib.sha256(b'generated operation').hexdigest()
        value = {'operation_id': operation, 'kind': 'download-only-pool', 'complete': True}
        raw = jobs.canonical(value)
        file = directory / 'inventory.json'; file.write_bytes(raw); file.chmod(0o444)
        directory.chmod(0o555)
        proof = {'manifest_sha256': hashlib.sha256(raw).hexdigest(), 'kind': value['kind']}
        try:
            return (accepts(function, directory, {'operation_id': operation}, proof)
                    and not accepts(function, directory, {'operation_id': operation + 'changed'}, proof)
                    and not accepts(function, directory, {'operation_id': operation},
                                    {**proof, 'manifest_sha256': hashlib.sha256(raw + b'changed').hexdigest()}))
        finally:
            directory.chmod(0o700)


@pytest.mark.parametrize('function,probe', [
    (pool.Pool.verify_object, cas_probe),
    (pool._validate_https_endpoint, endpoint_probe),
    (jobs.verify_published_inventory, publication_probe),
], ids=['CAS-integrity', 'endpoint-admission', 'publication-identity'])
def test_contracts_detect_generated_comparison_mutations(function, probe):
    assert probe(function), 'the original implementation must satisfy its contract'
    results = [probe(mutant) for mutant in comparison_mutants(function)]
    assert results, 'the mutation operator must generate candidates'
    killed = sum(not result for result in results)
    print(f'{function.__qualname__}: generated={len(results)} killed={killed} surviving={sum(results)}')
    assert killed == len(results), 'a generated contract violation survived undetected'
