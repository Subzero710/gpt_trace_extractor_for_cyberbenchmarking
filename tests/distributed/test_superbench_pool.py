"""Download-only SWE-Gym Lite fetcher regression tests; no network/KVM/VM."""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('superbench_pool_under_test', ROOT / 'scripts/superbench_pool.py')
pool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pool)


class TestStaticDependencyResolution(unittest.TestCase):
    def test_moto_named_install_requires(self):
        source = '''from setuptools import setup\ninstall_requires = ["requests>=2", "boto3>=1.9"]\nsetup(install_requires=install_requires)\n'''
        requirements, issues = pool.setup_static(source)
        self.assertEqual(requirements, {'requests>=2', 'boto3>=1.9'})
        self.assertEqual(issues, [])

    def test_dynamic_setup_metadata_is_not_silently_ignored(self):
        requirements, issues = pool.setup_static('setup(install_requires=dynamic())')
        self.assertFalse(requirements)
        self.assertTrue(issues)

    def test_requirements_and_constraints_remain_separate(self):
        sources = {'nested.txt': 'urllib3>=1\n', 'limits.txt': 'urllib3<2\n'}
        reqs, git, constraints = pool.parse_requirements(
            '-r nested.txt\n-c limits.txt\nrequests\n', 'base.txt',
            lambda name, required=False: sources[name])
        self.assertEqual(reqs, {'urllib3>=1', 'requests'})
        self.assertEqual(constraints, {'urllib3<2'})
        self.assertEqual(git, set())

    def test_hydra_git_protocol_rewrite_and_pep508(self):
        command = "sed -i 's|isort@git+git://github.com/timothycrosley/isort|isort@git+https://github.com/timothycrosley/isort|g' requirements/dev.txt"
        raw = 'isort@git+git://github.com/timothycrosley/isort.git@c54b3dd#egg=isort\n'
        changed = pool.transformed_source('facebookresearch/hydra', 'requirements/dev.txt', raw, [command])
        deps, vcs, constraints = pool.parse_requirements(changed, 'requirements/dev.txt', lambda *_: '')
        self.assertEqual(deps, set())
        self.assertEqual(constraints, set())
        self.assertEqual(vcs, {'git+https://github.com/timothycrosley/isort.git@c54b3dd#egg=isort'})

    def test_pydantic_make_install_invocations_keep_order(self):
        commands = ['python -m pip install -U pip', 'pip install -r requirements/all.txt', 'pip install -e .']
        _, filenames, _, issues, _, _, steps = pool.pip_commands(commands)
        self.assertEqual(issues, [])
        self.assertEqual(len(steps), 3)
        self.assertIn('requirements/all.txt', filenames)
        self.assertEqual(steps[0]['requirements'], {'pip'})

    def test_setup_cfg_install_requires(self):
        specs, issues = pool.setup_cfg_static('[options]\ninstall_requires =\n  numpy>=1\n  pytest\n')
        self.assertEqual(specs, {'numpy>=1', 'pytest'})
        self.assertEqual(issues, [])

    def test_conda_five_python_versions_and_contract_shape(self):
        contract = json.loads((ROOT / 'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/contract.json').read_bytes())
        self.assertEqual(len(contract['tasks']), 230)
        self.assertEqual(len(contract['environments']), 25)
        self.assertEqual(len({row['repo'] for row in contract['tasks'].values()}), 11)
        self.assertEqual(set(pool.PYTHONS), {'3.8','3.9','3.10','3.11','3.12'})


class TestAcquisitionFallbacks(unittest.TestCase):
    def test_pinned_sdist_then_static_binary_dependencies(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            candidate = pool.Pool(Path(tmp))
            (Path(tmp) / 'metadata').mkdir()
            (Path(tmp) / 'wheels').mkdir()
            calls = []
            def pipeline(argv, *, cwd=None, capture=False, env=None):
                calls.append(argv)
                if len(calls) == 1:
                    raise subprocess.CalledProcessError(1, argv)
                dest = Path(argv[argv.index('--dest') + 1])
                (dest / 'buildreq-1.0-py3-none-any.whl').write_bytes(b'fake wheel')
            source = {'filename': 'old-1.0.tar.gz', 'sha256': '1' * 64,
                      'requirements': ['buildreq==1.0']}
            with patch.object(pool, 'invoke', side_effect=pipeline), \
                 patch.object(pool, 'acquire_pinned_sdist', return_value=source):
                pool.pip_closure(candidate, '3.10', {'old==1.0'}, 'plan-key')
            plan = json.loads((Path(tmp) / 'metadata/pip-plan-plan-key.json').read_text())
            self.assertEqual(plan['source_archives'], [source])
            self.assertEqual(len(plan['files']), 1)
            self.assertEqual(len(calls), 2)

    def test_apt_key_uses_downloaded_content_address(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp)
            candidate = pool.Pool(stage)
            sha = hashlib.sha256(b'key-bytes').hexdigest()
            target = candidate.objects / sha[:2] / sha
            target.parent.mkdir(parents=True)
            target.write_bytes(b'key-bytes')
            def network(url, category, identity, **kwargs):
                self.assertEqual(category, 'apt')
                self.assertEqual(identity, 'signing-key')
                return sha
            def commands(args, *, cwd=None, capture=False, env=None):
                if args[0] == 'gpg': return 'fpr:::::::::' + pool.KALI_SIGNING_FPR + ':\n'
                if 'install' in args:
                    archives = stage / 'apt/archives'
                    (archives/'testpkg_1_all.deb').write_bytes(b'fixture .deb')
                return ''
            def dpkg(args, **kwargs): return 'testpkg\n1\nall\n'
            with patch.object(candidate, 'download', side_effect=network), \
                 patch.object(pool, 'invoke', side_effect=commands), \
                 patch.object(pool.subprocess, 'run', return_value=subprocess.CompletedProcess(['gpg'], 0)), \
                 patch.object(pool.subprocess, 'check_output', side_effect=dpkg):
                pool.apt_closure(candidate, {'testpkg'})
            self.assertEqual(json.loads((stage / 'metadata/apt-closure.json').read_text())['requested'], ['testpkg'])


class TestDeduplication(unittest.TestCase):
    def test_sha_and_url_share_one_download(self):
        with tempfile.TemporaryDirectory() as tmp:
            acquired = pool.Pool(Path(tmp))
            data = b'one identical upstream file\n'
            sha = hashlib.sha256(data).hexdigest()
            calls = []
            def network(url, path, *, sha=None, sri=None, limit=2**37, integrity_digests=None):
                calls.append(url)
                Path(path).write_bytes(data)
                if integrity_digests is not None:
                    import hashlib as h
                    integrity_digests.update({'sha384': h.sha384(data).digest(), 'sha512': h.sha512(data).digest()})
                return hashlib.sha256(data).hexdigest()
            with patch.object(pool, 'fetch', side_effect=network):
                acquired.download('https://example.test/one', 'python', 'task-a', sha=sha)
                acquired.download('https://example.test/one', 'python', 'task-b', sha=sha)
                acquired.download('https://example.test/two', 'python', 'task-c', sha=sha)
            self.assertEqual(calls, ['https://example.test/one'])
            self.assertEqual(len(acquired.links), 1)
            self.assertEqual(set(acquired.provenance['python']), {'task-a','task-b','task-c'})


class TestPublicationRecovery(unittest.TestCase):
    def test_published_verified_pool_is_reconciled_without_rehash_or_retry(self):
        import ast
        import types
        source = (ROOT / 'apps/workstation-broker/src/workstation_broker/preparation.py').read_text()
        tree = ast.parse(source)
        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'PreparationManager')
        method = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == '_reconcile')
        class Scope:
            @staticmethod
            def members(state): return []
            @staticmethod
            def close(state): return state
        namespace = {'JobScope': Scope, 'TERMINAL': {'ready','failed','canceled','interrupted'},
                     'RuntimeError': RuntimeError, 'Path': Path, 'json': json,
                     'safe': lambda path, **kwargs: Path(path)}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[])),
                     str(ROOT / 'apps/workstation-broker/src/workstation_broker/preparation.py'), 'exec'), namespace)
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp) / 'golden.qcow2'; base.write_bytes(b'unrelated')
            ready = base.parent / 'dependency-pool' / 'ready'; ready.mkdir(parents=True)
            operation = '7' * 64
            record = {'operation_id': operation, 'complete': True, 'tasks':230, 'repos':11, 'conda_recipes':25}
            (ready/'inventory.json').write_text(json.dumps(record))
            expected = {'kind':'download-only-pool','complete':True,
                        'pool_directory':str(ready),'tasks':230,'repos':11,'conda_recipes':25}
            state = {'phase':'interrupted','operation_id':operation,
                     'publication_verified':expected, 'error':'worker died after rename'}
            class FakeManager:
                def __init__(self): self.base=base; self.saved=[]
                def _reap(self): pass
                def _containers(self, *_): return []
                def _write(self, value): self.saved.append(value)
                def slot_busy(self): return False
            manager = FakeManager()
            recovered = namespace['_reconcile'](manager, state)
            self.assertEqual(recovered['phase'], 'ready')
            self.assertEqual(recovered['result'], expected)
            self.assertEqual(len(manager.saved), 1)

    def test_unverified_published_pool_is_not_automatically_accepted(self):
        source = (ROOT / 'apps/workstation-broker/src/workstation_broker/preparation.py').read_text()
        self.assertIn('publication_verified', source)
        self.assertIn("inventory.get('operation_id')", source)
        self.assertIn('actual_files != expected | {"inventory.json"}', source)


if __name__ == '__main__':
    unittest.main()
