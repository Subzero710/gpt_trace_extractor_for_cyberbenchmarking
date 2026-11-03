"""Adversarial regressions: synthetic bytes, no task execution or network."""
import base64
import contextlib
import hashlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import test_superbench_pool as fixtures

pool = fixtures.pool
fixture_target = fixtures.fixture_target


def token(data, algorithm='sha512'):
    return algorithm + '-' + base64.b64encode(hashlib.new(algorithm, data).digest()).decode()


class AuditRegressions(unittest.TestCase):
    def make_pool(self, path):
        result = fixtures.TestGlobalPipArtifactPool().make_pool(path)
        self.addCleanup(result._pip_cache_context.cleanup)
        return result

    def candidate(self, data, **updates):
        result = {'kind': 'wheel', 'name': 'demo', 'version': '1.0',
                  'filename': 'demo-1.0-py3-none-any.whl',
                  'item': {'digests': {'sha256': hashlib.sha256(data).hexdigest()},
                           'url': 'https://files.pythonhosted.org/demo.whl'}}
        result.update(updates)
        return result

    def materialize(self, data, candidate=None):
        with tempfile.TemporaryDirectory() as raw:
            instance = self.make_pool(raw)
            def fetch(url, path, **kwargs):
                Path(path).write_bytes(data)
                return hashlib.sha256(data).hexdigest()
            with patch.object(pool, 'fetch', side_effect=fetch):
                return pool._materialize_candidate_metadata(
                    instance, candidate or self.candidate(data), 'test', fixture_target(), {})

    def test_legacy_wildcard_preserves_packaging_21_3_lower_bound_semantics(self):
        requirement=pool._parse_registry_requirement(
            'demo (>=1.2.*); python_version < "4"')
        self.assertEqual(str(requirement.specifier),'>=1.2.dev0')
        self.assertTrue(requirement.specifier.contains('1.2.dev0',prereleases=True))
        self.assertTrue(requirement.specifier.contains('1.2a1',prereleases=True))
        self.assertTrue(requirement.specifier.contains('2.0',prereleases=True))
        self.assertFalse(requirement.specifier.contains('1.1',prereleases=True))
        self.assertIsNotNone(requirement.marker)


    def test_unpinned_release_prefers_final_over_prerelease(self):
        Requirement, _, Version, _, _ = pool._packaging_symbols()
        rows = tuple((Version(version), self.candidate(version.encode(), version=version))
                     for version in ('1.0', '2.0rc1'))
        with tempfile.TemporaryDirectory() as raw:
            instance = self.make_pool(raw)
            with patch.object(pool, '_registry_release_candidates', return_value=rows):
                result = pool._candidate_versions(instance, 'demo', [Requirement('demo')], [], fixture_target())
            self.assertEqual([row['version'] for row in result], ['1.0'])

    def test_wheel_embedded_identity_matches_candidate(self):
        for name, version in [('other', '1.0'), ('demo', '2.0')]:
            with self.subTest(name=name, version=version), self.assertRaisesRegex(RuntimeError, 'identity'):
                self.materialize(fixtures.TestGlobalPipArtifactPool.wheel_bytes(name, version))

    def test_wheel_internal_requires_python_is_checked(self):
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, 'w') as archive:
            archive.writestr('demo-1.0.dist-info/METADATA',
                'Metadata-Version: 2.1\nName: demo\nVersion: 1.0\nRequires-Python: >=4\n\n')
        with self.assertRaisesRegex(RuntimeError, 'Requires-Python'):
            self.materialize(raw.getvalue())

    def test_core_metadata_duplicate_identity_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'duplicate|unique'):
            pool._core_metadata_fields(b'Metadata-Version: 2.1\nName: demo\nName: other\nVersion: 1.0\n\n')

    def test_core_metadata_invalid_utf8_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'UTF-8'):
            pool._core_metadata_fields(b'Metadata-Version: 2.1\nName: demo\xff\nVersion: 1.0\n\n')

    def test_foreign_wheel_is_excluded_from_release_candidates(self):
        row = {'packagetype': 'bdist_wheel', 'filename': 'other-1.0-py3-none-any.whl',
               'url': 'https://files.pythonhosted.org/other.whl',
               'digests': {'sha256': 'a' * 64}}
        self.assertEqual(pool._release_artifacts('demo', '1.0', [row], fixture_target()), [])
        valid = {**row, 'filename': 'demo-1.0-py3-none-any.whl'}
        selected = pool._release_artifacts('demo', '1.0', [row, valid], fixture_target())
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]['filename'], valid['filename'])

    def test_no_deps_preserves_metadata_without_expanding_it(self):
        data = fixtures.TestGlobalPipArtifactPool.wheel_bytes(requires=('missing-package==1',))
        candidate = self.candidate(data)
        candidate['_release_info'] = {'requires_dist': ['missing-package==1'], 'provides_extra': []}
        with tempfile.TemporaryDirectory() as raw:
            instance = self.make_pool(raw)
            def fetch(url, path, **kwargs):
                Path(path).write_bytes(data)
                return hashlib.sha256(data).hexdigest()
            with patch.object(pool, 'fetch', side_effect=fetch):
                record = pool._candidate_release_metadata(instance, candidate, 'test', fixture_target(), {}, {}, no_deps=True)
        self.assertEqual(record['requirements'], ['missing-package==1'])

    def test_metadata_cache_includes_artifact_digest(self):
        first = self.candidate(b'one')
        second = self.candidate(b'two')
        self.assertNotEqual(pool._candidate_probe_identity(first, fixture_target(), False),
                            pool._candidate_probe_identity(second, fixture_target(), False))

    def test_checkpoint_rejects_missing_transitive_dependency(self):
        data = fixtures.TestGlobalPipArtifactPool.wheel_bytes(requires=('absent==1',))
        record = self.materialize(data)
        with tempfile.TemporaryDirectory() as raw:
            instance = self.make_pool(raw)
            with self.assertRaisesRegex(RuntimeError, 'closure does not satisfy'):
                pool._write_pip_plan(instance, fixture_target(), ['demo==1.0'], 'test', [record])

    def test_existing_same_size_cas_corruption_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            instance = self.make_pool(raw)
            data = b'good'; sha = hashlib.sha256(data).hexdigest()
            path = Path(raw) / 'source'; path.write_bytes(data)
            target = instance.objects / sha[:2] / sha
            target.parent.mkdir(); target.write_bytes(b'evil')
            with self.assertRaisesRegex(RuntimeError, 'CAS|content-addressed|SHA-256'):
                instance.put(path, 'python', 'test')

    def test_verified_cas_mutation_is_detected_on_reuse(self):
        with tempfile.TemporaryDirectory() as raw:
            instance = self.make_pool(raw); path = Path(raw) / 'source'; path.write_bytes(b'good')
            sha = instance.put(path, 'python', 'first')
            path.write_bytes(b'evil')
            with self.assertRaisesRegex(RuntimeError, 'CAS|content-addressed|SHA-256'):
                instance.download('https://example.test/a', 'python', 'second', sha=sha)

    def test_sri_strongest_algorithm_is_required(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / 'data'; path.write_bytes(b'good')
            with self.assertRaisesRegex(RuntimeError, 'integrity'):
                pool.verify_sri(path, token(b'good', 'sha256') + ' ' + token(b'evil'))

    def test_sri_alternative_hash_does_not_poison_cache(self):
        with tempfile.TemporaryDirectory() as raw:
            instance = self.make_pool(raw); path = Path(raw) / 'source'; path.write_bytes(b'good')
            sha = instance.put(path, 'python', 'first')
            instance.download('https://example.test/a', 'npm', 'first', sha=sha,
                              sri=token(b'good') + ' ' + token(b'evil'))
            with self.assertRaisesRegex(RuntimeError, 'integrity'):
                instance.download('https://example.test/a', 'npm', 'second', sri=token(b'evil'))

    def test_npm_v1_nested_dependencies_are_included(self):
        child = {'resolved': 'https://registry.npmjs.org/child/-/child-1.tgz', 'integrity': token(b'child')}
        parent = {'resolved': 'https://registry.npmjs.org/parent/-/parent-1.tgz',
                  'integrity': token(b'parent'), 'dependencies': {'child': child}}
        urls = pool.npm_lock_urls({'lockfileVersion': 1, 'dependencies': {'parent': parent}}, 'fixture')
        self.assertEqual(set(urls), {parent['resolved'], child['resolved']})

    def test_sdist_duplicate_metadata_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / 'source.zip'
            with zipfile.ZipFile(path, 'w') as archive:
                for root in ['one', 'two']:
                    archive.writestr(root + '/PKG-INFO', 'Name: ' + root)
            with self.assertRaisesRegex(RuntimeError, 'ambiguous|duplicate|root'):
                pool._source_archive_files(path, path.name)

    def test_sdist_dynamic_dependencies_not_hidden_by_build_requires(self):
        req = pool._packaging_symbols()[0]('demo==1.0')
        item = {'packagetype': 'sdist', 'filename': 'demo-1.0.tar.gz',
                'url': 'https://files.pythonhosted.org/demo.tar.gz', 'digests': {'sha256': 'a' * 64}}
        metadata = {'urls': [item], 'info': {'name': 'demo'}}
        source = b'[build-system]\nrequires=["setuptools"]\n[project]\ndynamic=["dependencies"]\n'
        with tempfile.TemporaryDirectory() as raw:
            instance = self.make_pool(raw)
            with patch.object(pool, '_select_source_release', return_value=(req, '1.0', item)), \
                 patch.object(pool, '_pypi_json', return_value=metadata), \
                 patch.object(instance, 'download', return_value='a' * 64), \
                 patch.object(pool, '_source_archive_files', return_value={'pyproject.toml': source}), \
                 self.assertRaisesRegex(RuntimeError, 'isolated target evaluation'):
                pool.acquire_source_distribution(instance, 'demo==1.0', 'test', fixture_target())

    def test_sed_substitution_is_per_line_and_ampersand_means_match(self):
        self.assertEqual(pool._sed_substitution('s/foo/[&]/', 'foo foo\nfoo\n'), '[foo] foo\n[foo]\n')

    def test_recipe_edits_preserve_order_and_literal_echo_bytes(self):
        command="echo 'alpha' >> requirements.txt; sed -i 's/alpha/beta/g' requirements.txt"
        self.assertEqual(pool.transformed_source('fixture','requirements.txt','prefix',[command]),'prefixbeta\n')
        quoted='python -c "sed -i fake requirements.txt"; echo "real" >> requirements.txt'
        self.assertEqual(pool.transformed_source('fixture','requirements.txt','',[quoted]),'real\n')

    def test_unsupported_group_write_produces_diagnostic(self):
        with self.assertRaisesRegex(RuntimeError,'group redirection'):
            pool.transformed_source('fixture','requirements.txt','', ['{ echo "dep"; } >> requirements.txt'])

    def test_unknown_dependency_branches_are_not_unioned(self):
        source='if dynamic():\n    install_requires=["demo==1"]\nelse:\n    install_requires=["demo==2"]\nsetup(install_requires=install_requires)'
        deps,issues=pool.setup_static(source)
        self.assertFalse(deps);self.assertTrue(issues)
        same=source.replace('demo==2','demo==1')
        self.assertEqual(pool.setup_static(same),({'demo==1'},[]))

    def test_literal_file_does_not_clear_other_dynamic_metadata(self):
        source='deps=unknown_reader("requirements.txt")\nsetup(install_requires=deps,setup_requires=unknown_build_deps())'
        deps,remote,issues=pool.setup_requirements_from_sources(source,lambda *args,**kwargs:'known==1\n')
        self.assertIn('known==1',deps);self.assertFalse(remote)
        self.assertTrue(any('setup_requires' in issue for issue in issues))

    def test_setup_dependencies_are_read_at_the_actual_static_call(self):
        source='deps=["first==1"]\nsetup(install_requires=deps)\ndeps=["later==2"]'
        self.assertEqual(pool.setup_static(source),({'first==1'},[]))
        source='if False:\n    setup(install_requires=["unreachable==1"])\nsetup(install_requires=[])'
        self.assertEqual(pool.setup_static(source),(set(),[]))

    def test_pip_text_is_not_executed_and_quoted_operators_remain_arguments(self):
        result=pool.pip_commands(['echo pip install invented','python -c "pip install invented"'])
        self.assertFalse(result[0]);self.assertFalse(result[-1])
        segments=pool.shell_segments('echo ";"; pip install "demo>=1"')
        self.assertEqual(segments[0][0],['echo',';'])
        self.assertEqual(segments[1][0],['pip','install','demo>=1'])

    def test_apt_and_conda_only_parse_executable_positions(self):
        self.assertEqual(pool.apt_recipe_operations(['echo apt-get install invented']),(set(),[]))
        self.assertEqual(pool.conda_post_install_specs(['echo conda install invented']),[])
        self.assertEqual(pool.apt_recipe_operations(['sudo apt-get install real']),({'real'},[]))
        self.assertEqual(pool.conda_post_install_specs(['conda install -y real']),[['real']])

    def test_redirect_is_rejected_before_creating_redirect_request(self):
        request=pool.urllib.request.Request('https://pypi.org/simple/demo/')
        guard=pool._ValidatedHTTPSRedirect('pypi.org')
        for target in ['http://pypi.org/a','https://other.test/a','https://user:secret@pypi.org/a','https://pypi.org:444/a']:
            with self.subTest(target=target),self.assertRaisesRegex(RuntimeError,'untrusted'):
                guard.redirect_request(request,None,302,'redirect',{},target)
        redirected=guard.redirect_request(request,None,302,'redirect',{},'https://pypi.org/simple/demo-next/')
        self.assertEqual(redirected.full_url,'https://pypi.org/simple/demo-next/')

    def test_sdist_paths_are_distinct_and_oversize_metadata_is_not_ignored(self):
        with tempfile.TemporaryDirectory() as raw:
            path=Path(raw)/'demo.zip'
            with zipfile.ZipFile(path,'w') as archive:
                archive.writestr('demo/requirements.txt','root==1')
                archive.writestr('demo/nested/requirements.txt','nested==1')
            result=pool._source_archive_files(path,path.name)
            self.assertEqual(result,{'requirements.txt':b'root==1','nested/requirements.txt':b'nested==1'})
            with zipfile.ZipFile(path,'w') as archive:
                archive.writestr('demo/PKG-INFO',b'x'*(2*1024*1024+1))
            with self.assertRaisesRegex(RuntimeError,'exceeds security limit'):
                pool._source_archive_files(path,path.name)

    def test_future_metadata_major_version_is_not_silently_accepted(self):
        with self.assertRaisesRegex(RuntimeError,'metadata version'):
            pool._core_metadata_fields(b'Metadata-Version: 3.0\nName: demo\nVersion: 1\n\n')

    def test_sed_differential_for_supported_literal_surface(self):
        expressions = ['s/foo/[&]/', 's/foo/[&]/g', 's/a/b/', r's/\(foo\)/\1x/g', 's/^/prefix/', 's/$/suffix/']
        values = ['', 'foo foo\nfoo\n', 'aaa\n\na', 'foo\vfoo\n', 'foo\rbar\n', '\n']
        for expression in expressions:
            for value in values:
                with self.subTest(expression=expression, value=value):
                    result = subprocess.run(['sed', expression], input=value.encode(), capture_output=True, check=True)
                    self.assertEqual(pool._sed_substitution(expression, value).encode(), result.stdout)

    def test_global_http_budget_spans_concurrent_callers(self):
        import threading
        import concurrent.futures
        import time
        slots=threading.BoundedSemaphore(2); lock=threading.Lock(); active=0; maximum=0
        def operation():
            nonlocal active, maximum
            with lock:active+=1;maximum=max(maximum,active)
            time.sleep(0.01)
            with lock:active-=1
            return True
        with patch.object(pool,'_network_slots',return_value=slots), concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            results=list(executor.map(lambda _:pool._network_retry('fixture',operation),range(16)))
        self.assertTrue(all(results));self.assertEqual(maximum,2)

    def test_metadata_short_content_length_is_rejected(self):
        class Response(io.BytesIO):
            def getheader(self, name, default=''):
                return {'Content-Length': '20'}.get(name, default)
        with self.assertRaises((pool.MetadataDecodeError, pool.http.client.IncompleteRead)):
            pool._read_metadata_response(Response(b'{}'), 100)

    def test_unusable_metadata_never_becomes_unsat(self):
        candidates = [self.candidate(b'one', version='2.0'), self.candidate(b'two')]
        def versions(instance, name, requirements, constraints, target, **kwargs):
            return candidates if name == 'demo' else []
        def metadata(instance, candidate, *args, **kwargs):
            if candidate['version'] == '2.0': raise RuntimeError('unsupported dynamic metadata')
            return {**candidate, 'requirements': ['absent==1'], 'provides_extra': []}
        with tempfile.TemporaryDirectory() as raw:
            instance = self.make_pool(raw)
            with patch.object(pool, '_candidate_versions', side_effect=versions), \
                 patch.object(pool, '_candidate_release_metadata', side_effect=metadata):
                try: pool._resolve_registry_plan(instance, fixture_target(), ['demo'], [], 'test', materialize=False)
                except RuntimeError as exc:
                    self.assertNotIn('unsatisfiable', str(exc))
                    self.assertIn('metadata', str(exc))
                else: self.fail('unverified resolution accepted')

    def test_pool_contract_binds_every_staged_source(self):
        from gpt_trace_transport import local_templates
        from workstation_broker.preparation import FETCH_SOURCE_FILES
        root = Path(pool.__file__).resolve().parents[1]
        before = local_templates.pool_contract(root)
        sources = before.get('fetch_sources')
        self.assertIsInstance(sources, dict)
        self.assertEqual(set(sources), set(FETCH_SOURCE_FILES))
        for name in FETCH_SOURCE_FILES:
            self.assertEqual(sources[name], hashlib.sha256((root/name).read_bytes()).hexdigest())

    def test_every_versioned_recipe_and_conda_transaction(self):
        from gpt_trace_runner.superbench.adapters.swe_gym import source
        contract = source.contract(); official = source.harness(contract)
        lock, _ = pool.load_conda_lock(source.ROOT, source.PINS, contract)
        observed = set()
        for logical, task in contract['tasks'].items():
            with self.subTest(task=logical):
                spec = official.constants.MAP_REPO_VERSION_TO_SPECS[task['repo'].lower()][task['version']]
                repo_commands = official.test_spec.make_repo_script_list(
                    spec, task['repo'].lower(), '/testbed', task['base_commit'], 'testbed')
                self.assertEqual(repo_commands, task['repo_script_list'])
                original = official.test_spec.make_env_script_list(task, spec, 'testbed')
                env = hashlib.sha256(str(original).encode()).hexdigest()[:22]
                self.assertEqual(env, task['env_hash'])
                entry = contract['environments'][env]
                self.assertEqual(original, entry['original_script'])
                self.assertEqual(official.test_spec.make_env_script_list(task, spec, entry['stored_name']), entry['stored_script'])
                keys = pool.conda_expected_transaction_keys(env, original)
                self.assertEqual(keys, [row['key'] for row in lock['environments'][env]['transactions']])
                observed.add(env)
        self.assertEqual(observed, set(contract['environments']))

    def test_solver_against_finite_exhaustive_reference(self):
        import itertools
        import random
        Requirement, _, Version, _, _ = pool._packaging_symbols()
        target = fixture_target()
        for seed in range(256):
            rng = random.Random(seed); names = ['p0', 'p1', 'p2', 'p3']
            graph = {(name, str(version)): [rng.choice(names) + rng.choice(['==', '>=', '<=']) + str(rng.randrange(1, 4))
                                           for _ in range(rng.randrange(3))]
                     for name in names for version in (1, 2)}
            roots = ['p0', rng.choice(names)]
            def valid(assignment):
                pending = list(roots); visited = set()
                while pending:
                    requirement = Requirement(pending.pop()); name = requirement.name
                    if requirement.specifier and not requirement.specifier.contains(assignment[name]): return False
                    if name not in visited:
                        visited.add(name); pending.extend(graph[name, assignment[name]])
                return True
            expected = any(valid(dict(zip(names, values))) for values in itertools.product(('1', '2'), repeat=len(names)))
            def candidates(instance, name, requirements, constraints, target, **kwargs):
                return [self.candidate((name+version).encode(), name=name, version=version,
                            filename=name+'-'+version+'-py3-none-any.whl')
                        for version in ('2','1') if all(not req.specifier or req.specifier.contains(version)
                                                       for req in requirements)]
            def metadata(instance, candidate, *args, **kwargs):
                return {**candidate, 'requirements': graph[candidate['name'],candidate['version']], 'provides_extra': []}
            with self.subTest(seed=seed), tempfile.TemporaryDirectory() as raw:
                instance = self.make_pool(raw)
                with patch.object(pool, '_candidate_versions', side_effect=candidates), \
                     patch.object(pool, '_candidate_release_metadata', side_effect=metadata), contextlib.redirect_stdout(io.StringIO()):
                    try: result = pool._resolve_registry_plan(instance, target, roots, [], str(seed), materialize=False)
                    except RuntimeError as exc:
                        self.assertIn('unsatisfiable', str(exc)); actual = False
                    else:
                        actual = True
                        assignment = {name:'1' for name in names}
                        assignment.update({row['name']:row['version'] for row in result})
                        self.assertTrue(valid(assignment))
                self.assertEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()
