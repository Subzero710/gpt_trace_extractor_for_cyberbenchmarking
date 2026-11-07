"""Regression of historical PyPI Requires-Python quoting; no network or VM."""
import hashlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

from packaging.version import Version

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'pool_quoted_requires_python_test', ROOT / 'scripts/superbench_pool.py')
POOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POOL)


class HistoricalRequiresPythonQuotes(unittest.TestCase):
    def test_exact_failure_reproduced_and_semantics_retained(self):
        check = POOL._requires_python_compatible
        self.assertTrue(check(">= '2.7'", Version('3.10.14')))
        self.assertFalse(check(">= '2.7'", Version('2.6.9')))
        self.assertTrue(check('>= "3.8"', Version('3.10.14')))
        self.assertFalse(check('>= "3.11"', Version('3.10.14')))
        self.assertTrue(check(" >= '3.8' , < '3.11' ", Version('3.10.14')))
        self.assertFalse(check(" >= '3.8' , < '3.10' ", Version('3.10.14')))
        self.assertTrue(check("== '3.10.*'", Version('3.10.14')))
        self.assertFalse(check("== '3.10.*'", Version('3.11.0')))
        self.assertTrue(check(">= '3.5.*'", Version('3.5.0')))
        self.assertFalse(check(">= '3.5.*'", Version('3.4.9')))
        self.assertTrue(check('>=3.8,<3.11', Version('3.10.14')))

    def test_invalid_inputs_are_not_silently_discarded(self):
        for invalid in (
            ">= 'banana'", ">= '2.7' unexpected", ">= '2.7' or >3",
            ">= '2.7' ; python_version > '3'", ">= '2.7",
            '>= "2.7\'', ">= ' 2.7'", "> '3.5.*'", ">= '2.7',<bad",
            ">=3.5.*,not-a-version", '', None,
        ):
            with self.subTest(raw=invalid), self.assertRaisesRegex(RuntimeError, 'invalid Requires-Python'):
                POOL._requires_python_compatible(invalid, Version('3.10.14'))

    def test_registry_wheel_and_source_admission_enforces_quoted_bounds(self):
        target = SimpleNamespace(python_full_version='3.10.14', tags=['py3-none-any'])
        payload = b'identity-only-fixture'
        sha = hashlib.sha256(payload).hexdigest()
        base = {'url': 'https://files.pythonhosted.org/packages/example-1.0-py3-none-any.whl',
                'filename': 'example-1.0-py3-none-any.whl',
                'packagetype': 'bdist_wheel', 'digests': {'sha256': sha}}
        compatible = {**base, 'requires_python': ">= '2.7'"}
        incompatible = {**base, 'requires_python': ">= '3.11'"}
        rows = POOL._release_artifacts('example', '1.0', [compatible], target)
        self.assertEqual([(row['kind'], row['filename']) for row in rows],
                         [('wheel', base['filename'])])
        self.assertEqual(POOL._release_artifacts('example', '1.0', [incompatible], target), [])
        source = {**base, 'packagetype': 'sdist', 'filename': 'example-1.0.tar.gz',
                  'url': 'https://files.pythonhosted.org/packages/example-1.0.tar.gz',
                  'requires_python': ">= '2.7'"}
        self.assertEqual([row['kind'] for row in POOL._release_artifacts('example', '1.0', [source], target)], ['sdist'])
