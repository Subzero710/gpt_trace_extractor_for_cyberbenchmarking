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

    def test_dynamic_setup_kwargs_is_not_silently_ignored(self):
        source = 'setup_args={"name": dynamic_name(), "install_requires": ["dep==1"]}\nsetup(**setup_args)\n'
        requirements, issues = pool.setup_static(source)
        self.assertFalse(requirements)
        self.assertTrue(any('**kwargs' in item for item in issues))

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


    def test_dvc_file_backed_tests_extra_and_target_python_append_are_static(self):
        setup = """from pathlib import Path
import sys
from setuptools import setup
install_requires=["base>=1"]
if sys.version_info[0] == 2:
    install_requires.append("networkx>=2.1,<2.3")
else:
    install_requires.append("networkx>=2.1")
tests_requirements=(Path("test_requirements.txt").read_text().strip().splitlines())
if sys.version_info >= (3, 6):
    tests_requirements.append("black==19.3b0")
setup(install_requires=install_requires, extras_require={"tests": tests_requirements})
"""
        files={'test_requirements.txt':'pytest>=6\ncollective.checkdocs\n'}
        deps, remote, issues = pool.setup_requirements_from_sources(
            setup, lambda name, required=False: files.get(name),
            extras={'tests'}, python_version='3.8')
        self.assertEqual(remote, set())
        self.assertEqual(issues, [])
        self.assertTrue({'base>=1','networkx>=2.1','pytest>=6',
                         'collective.checkdocs','black==19.3b0'} <= deps)
        self.assertNotIn('networkx>=2.1,<2.3', deps)

    def test_pep621_self_extras_expand_locally_instead_of_fetching_dvc(self):
        pyproject = """[build-system]
requires=["setuptools>=61"]
[project]
name="dvc"
dependencies=["base>=1"]
[project.optional-dependencies]
azure=["dvc-azure==2.21.1"]
testing=["pytest-test-utils"]
tests=["dvc[testing]", "pytest>=7"]
dev=["dvc[azure,tests]"]
"""
        deps, vcs, issues = pool.static_project(pyproject, extra_groups={'dev'})
        self.assertEqual(vcs, set())
        self.assertEqual(issues, [])
        self.assertTrue({'dvc-azure==2.21.1','pytest-test-utils','pytest>=7','base>=1'} <= deps)
        self.assertFalse(any(item.startswith('dvc[') for item in deps))

    def test_conda_solution_python_records_base_interpreter_phase(self):
        solution=[{'name':'openssl','version':'3.0.0'},
                  {'name':'python','version':'3.11.9','url':'https://example/python','sha256':'a'*64}]
        self.assertEqual(pool.conda_solution_python(solution),'3.11')



class TestAcquisitionFallbacks(unittest.TestCase):
    def test_non_exact_source_only_requirement_uses_static_resolver_stub(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            candidate = pool.Pool(Path(tmp))
            (Path(tmp) / 'metadata').mkdir()
            (Path(tmp) / 'wheels').mkdir()
            calls = []
            def pipeline(argv, **kwargs):
                calls.append(argv)
                if len(calls) == 1:
                    return subprocess.CompletedProcess(argv, 1,
                        stdout='ERROR: Could not find a version that satisfies the requirement collective.checkdocs (from versions: none)\n')
                return subprocess.CompletedProcess(argv, 0, stdout='')
            source = {'name':'collective.checkdocs','version':'0.2.1',
                      'requested':'collective.checkdocs','filename':'collective.checkdocs-0.2.1.tar.gz',
                      'sha256':'1'*64,'requirements':['setuptools'],'provides_extra':[]}
            with patch.object(pool.subprocess, 'run', side_effect=pipeline), \
                 patch.object(pool, 'acquire_source_distribution', return_value=source) as acquire:
                pool.pip_closure(candidate, '3.10', {'collective.checkdocs'}, 'plan-key')
            plan = json.loads((Path(tmp) / 'metadata/pip-plan-plan-key.json').read_text())
            self.assertEqual(plan['source_archives'], [source])
            self.assertEqual(plan['files'], [])
            self.assertEqual(len(calls), 2)
            acquire.assert_called_once_with(candidate, 'collective.checkdocs', 'plan-key', '3.10', constraints=())

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
            def dpkg(args, **kwargs): return 'Package: testpkg\nVersion: 1\nArchitecture: all\n'
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


class TestPinnedRealWorldRegressions(unittest.TestCase):
    def test_hydra_file_backed_install_requires_without_execution(self):
        # Matches actual hydra 94bbaaad setup.py metadata source syntax.
        setup = ("""from setuptools import setup
import pathlib
import pkg_resources
with pathlib.Path("requirements/requirements.txt").open() as requirements_txt:
    install_requires = [str(requirement) for requirement in pkg_resources.parse_requirements(requirements_txt)]
setup(install_requires=install_requires)
""")
        data = {'requirements/requirements.txt':'omegaconf>=2.0\nantlr4-python3-runtime==4.8\n'}
        deps, remote, issues = pool.setup_requirements_from_sources(setup,
            lambda name, required=False:data[name])
        self.assertEqual(issues, [])
        self.assertEqual(remote, set())
        self.assertEqual(deps, {'omegaconf>=2.0','antlr4-python3-runtime==4.8'})

    def test_conan_file_backed_install_requires_without_execution(self):
        # Matches actual conan 345be91 setup.py metadata source syntax.
        setup = ("""from setuptools import setup
project_requirements = get_requires("conans/requirements.txt")
project_requirements.extend(get_requires("conans/requirements_server.txt"))
setup(install_requires=project_requirements)
""")
        data = {'conans/requirements.txt':'requests>=2\n',
                'conans/requirements_server.txt':'bottle==0.12\n',
                'conans/requirements_dev.txt':'pytest>=6\n'}
        deps, remote, issues = pool.setup_requirements_from_sources(setup,
            lambda name, required=False:data[name], extras={'dev'})
        self.assertEqual(issues, [])
        self.assertEqual(remote, set())
        self.assertEqual(deps, {'requests>=2','bottle==0.12','pytest>=6'})

    def test_conan_legacy_single_runtime_file_without_execution(self):
        # Matches the older Conan layout used by eight pinned SWE-Gym commits.
        setup = ("""from setuptools import setup
project_requirements = get_requires('conans/requirements.txt')
dev_requirements = get_requires('conans/requirements_dev.txt')
setup(install_requires = project_requirements,
      extras_require={'dev': dev_requirements, 'test': dev_requirements})
""")
        data = {'conans/requirements.txt':'requests>=2\nurllib3<2\n',
                'conans/requirements_dev.txt':'pytest>=6\n'}
        deps, remote, issues = pool.setup_requirements_from_sources(setup,
            lambda name, required=False:data[name], extras={'test'})
        self.assertEqual(issues, [])
        self.assertEqual(remote, set())
        self.assertEqual(deps, {'requests>=2','urllib3<2','pytest>=6'})

    def test_modin_spreadsheet_setup_kwargs_reads_pinned_runtime_requirements(self):
        # Matches modin-spreadsheet@49ffd89: dynamic setup_args metadata plus a
        # fixed requirements.txt used for install_requires.
        setup = ("""from setuptools import setup

def read_requirements(basename):
    return dynamic_reader(basename)

def extras_require():
    return {'test': ['pytest']}

reqs = read_requirements("requirements.txt")
setup_args = {
    "name": dynamic_name(),
    "install_requires": reqs,
    "extras_require": extras_require(),
}
setup(version=dynamic_version(), **setup_args)
""")
        data = {'requirements.txt':'jupyter>=1.0.0\nnotebook>=6.0.3\nipywidgets>=7.0.0\n'}
        deps, remote, issues = pool.setup_requirements_from_sources(setup,
            lambda name, required=False:data[name])
        self.assertEqual(issues, [])
        self.assertEqual(remote, set())
        self.assertEqual(deps, {'jupyter>=1.0.0','notebook>=6.0.3','ipywidgets>=7.0.0'})

    def test_unrecognized_dynamic_setup_fails_closed(self):
        deps, remote, issues = pool.setup_requirements_from_sources(
            'setup(install_requires=run_untrusted_setup())',
            lambda name, required=False: 'bad')
        self.assertFalse(deps); self.assertFalse(remote); self.assertTrue(issues)

    def test_git_project_with_tool_only_pyproject_still_parses_setup(self):
        with patch.object(pool, 'git_file', side_effect=lambda mirror, commit, path, **kwargs:
                {'pyproject.toml':'[tool.black]\nline-length=88\n',
                 'setup.py':'setup(install_requires=["dep==1.0"])\n'}.get(path)):
            deps,remote,issues = pool.git_requirements('unused','a'*40)
        self.assertEqual(deps,{'dep==1.0'})
        self.assertEqual(remote,set()); self.assertEqual(issues,[])

    def test_git_project_with_pep508_nested_reference(self):
        with patch.object(pool, 'git_file', side_effect=lambda mirror, commit, path, **kwargs:
                {'pyproject.toml':('[project]\nname="thing"\n'
                    'dependencies=["other @ git+https://github.com/example/other.git@'
                    + 'a'*40 + '"]\n')}.get(path)):
            deps,remote,issues = pool.git_requirements('unused','a'*40)
        self.assertEqual(deps,set()); self.assertEqual(issues,[])
        self.assertEqual(len(remote),1)

    def test_no_deps_is_not_dropped_by_pip_parser(self):
        _,_,_,problems,_,_,steps = pool.pip_commands(['python -m pip install --no-deps -e .'])
        self.assertEqual(problems,[])
        self.assertEqual(len(steps),1)
        self.assertTrue(steps[0]['no_deps'])

    def test_bokeh_requires_pinned_tags_in_git_mirror(self):
        calls=[]
        def fake(args,**kwargs):
            calls.append([str(x) for x in args])
            if 'tag' in args: return 'v1\nv2\nv3\nv4\nv5\n'
            return ''
        with tempfile.TemporaryDirectory() as tmp,patch.object(pool,'invoke',side_effect=fake):
            pool.mirror_commits(Path(tmp),'bokeh/bokeh',{'a'*40})
        self.assertTrue(any('+refs/tags/*:refs/tags/*' in c for c in calls))

    def test_published_contract_cannot_be_empty_cas(self):
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp)
            (stage/'metadata').mkdir()
            candidate=pool.Pool(stage)
            with self.assertRaisesRegex(RuntimeError,'incomplete dependency closure'):
                pool.audit_inventory(candidate,{}, {}, {}, 'a'*64)
            inventory=json.loads((stage/'inventory.json').read_text())
            self.assertFalse(inventory['complete'])
            self.assertTrue(any('no acquired content-addressed objects' in x for x in inventory['issues']))

    def test_broker_does_not_export_credential_environment(self):
        broker=(ROOT/'apps/workstation-broker/src/workstation_broker/preparation.py').read_text()
        physical=broker.split('def _prepare(manager, state):',1)[1].split('def worker(operation_id, slot_fd):',1)[0]
        self.assertNotIn('os.environ.copy()',physical)
        self.assertNotIn('dict(os.environ',physical)
        self.assertIn('PIP_CONFIG_FILE',physical)
        self.assertIn('child.wait(timeout=24 * 3600)',physical)
        self.assertIn('os.killpg(child.pid, signal.SIGKILL)',physical)

    def test_conda_link_solution_not_just_fetch(self):
        records=[{'fn':'a.tar.bz2','url':'https://x/a.tar.bz2','sha256':'a'*64},
                 {'fn':'b.tar.bz2','url':'https://x/b.tar.bz2','sha256':'b'*64}]
        operations=[]
        class Candidate:
            stage=Path('/tmp')
            def download(self,*args,**kwargs):operations.append(kwargs['sha'])
        original_write=pool.write_new
        with patch.object(pool,'invoke',return_value=json.dumps({'success':True,
             'actions':{'LINK':records,'FETCH':records[:1]}})),patch.object(pool,'write_new'):
            pool.conda_resolve('fake',Candidate(),'test',['python=3.10'])
        self.assertEqual(operations,['a'*64,'b'*64])


class TestContractClosureRegressionV4(unittest.TestCase):
    def test_contract_direct_conda_create_covers_all_five_non_yaml_envs(self):
        contract = json.loads((ROOT / 'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/contract.json').read_bytes())
        direct = {}
        tasks = {}
        for env, entry in contract['environments'].items():
            if pool.conda_yaml(entry['original_script']) is None:
                direct[env] = pool.conda_direct_specs(entry['original_script'])
        for task in contract['tasks'].values():
            tasks[task['env_hash']] = tasks.get(task['env_hash'], 0) + 1
        self.assertEqual(len(direct), 5)
        self.assertEqual(sum(tasks[env] for env in direct), 205)
        self.assertEqual({tuple(value) for value in direct.values()},
                         {('python=3.8',),('python=3.9',),('python=3.10',),
                          ('python=3.11',),('python=3.12',)})

    def test_contract_post_create_conda_overrides_are_detected_as_separate_transactions(self):
        contract = json.loads((ROOT / 'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/contract.json').read_bytes())
        post = {env: pool.conda_post_install_specs(entry['original_script'])
                for env, entry in contract['environments'].items()}
        post = {env: value for env, value in post.items() if value}
        self.assertEqual(len(post), 5)
        self.assertTrue(all(len(value) == 1 for value in post.values()))
        self.assertEqual(sorted(value[0][0] for value in post.values()),
                         ['python=3.10','python=3.9','python=3.9','python=3.9','python=3.9'])

    def test_contract_environment_pip_phase_precedes_python_override(self):
        contract = json.loads((ROOT / 'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/contract.json').read_bytes())
        phased=[]
        for env,entry in contract['environments'].items():
            content=pool.conda_yaml(entry['original_script'])
            if not content: continue
            _,pips=pool.conda_pip_split(content)
            post=pool.conda_post_install_specs(entry['original_script'])
            if pips and post: phased.append((env,pips,post))
        self.assertEqual(len(phased),5)
        self.assertTrue(all(rows and post for _,rows,post in phased))
        source=(ROOT/'scripts/superbench_pool.py').read_text()
        self.assertIn('environment_pip_python',source)
        self.assertIn('base_python=conda_solution_python(base_solution)',source)
        self.assertIn("bucket='environment'",source)

    def test_poetry_isort_optional_dependencies_do_not_become_invalid_pip_specs(self):
        pyproject = """[tool.poetry]
name="isort"
version="4.3.21"
[tool.poetry.dependencies]
python="^3.6"
appdirs={version="^1.4.0", optional=true}
pipreqs={version="*", optional=true}
tomlkit={version="0.5.3", optional=true}
[tool.poetry.extras]
xdg_home=["appdirs"]
[build-system]
requires=["poetry>=0.12"]
build-backend="poetry.masonry.api"
"""
        deps, vcs, issues = pool.static_project(pyproject)
        self.assertEqual(issues, [])
        self.assertEqual(vcs, set())
        self.assertEqual(deps, {'poetry>=0.12'})
        deps, _, issues = pool.static_project(pyproject, extra_groups={'xdg_home'})
        self.assertEqual(issues, [])
        self.assertIn('appdirs>=1.4.0,<2.0.0', deps)

    def test_dvc_shell_chain_keeps_second_and_command_and_optional_true_steps(self):
        command = ('python -m pip install "cython<3.0.0" && '
                   'python -m pip install --no-build-isolation pyyaml==5.4.1; '
                   'python -m pip install -r test-requirements.txt || true')
        _, _, _, issues, _, _, steps = pool.pip_commands([command])
        self.assertEqual(issues, [])
        self.assertEqual(len(steps), 3)
        self.assertEqual(steps[0]['requirements'], {'cython<3.0.0'})
        self.assertEqual(steps[1]['requirements'], {'pyyaml==5.4.1'})
        self.assertFalse(steps[1]['optional'])
        self.assertEqual(steps[2]['files'], {'test-requirements.txt'})
        self.assertTrue(steps[2]['optional'])

    def test_dvc_setup_extras_resolve_all_remote_lists_without_execution(self):
        setup = """from setuptools import setup
install_requires=["ply>=3.9"]
gs=["google-cloud-storage==1.13.0"]
s3=["boto3==1.7.4"]
azure=["azure-storage-blob==1.3.0"]
ssh=["paramiko>=2.4.1"]
all_remotes=gs+s3+azure+ssh
setup(install_requires=install_requires,
      extras_require={"all":all_remotes,"gs":gs,"s3":s3,"azure":azure,"ssh":ssh})
"""
        deps, issues = pool.setup_static(
            setup, extras={'tests','dev','all_remotes','all','testing'})
        self.assertEqual(issues, [])
        self.assertTrue({'google-cloud-storage==1.13.0','boto3==1.7.4',
                         'azure-storage-blob==1.3.0','paramiko>=2.4.1'} <= deps)

    def test_modin_spreadsheet_setup_args_reads_pinned_requirements(self):
        setup = """def read_requirements(basename): pass
reqs = read_requirements("requirements.txt")
setup_args = {"install_requires": reqs}
setup(version=get_version(), **setup_args)
"""
        files = {'requirements.txt':'jupyter>=1.0.0\nnotebook>=6.0.3\nipywidgets>=7.0.0\n'}
        deps, remote, issues = pool.setup_requirements_from_sources(
            setup, lambda name, required=False: files.get(name))
        self.assertEqual(issues, [])
        self.assertEqual(remote, set())
        self.assertEqual(deps, {'jupyter>=1.0.0','notebook>=6.0.3','ipywidgets>=7.0.0'})

    def test_mock_ssh_server_file_backed_requirements_are_static(self):
        setup = """def read_requirements(): pass
setup(install_requires=read_requirements())
# requirements.txt
"""
        files = {'requirements.txt':'paramiko>=2.1\ncryptography>=1.5\n'}
        deps, remote, issues = pool.setup_requirements_from_sources(
            setup, lambda name, required=False: files.get(name))
        self.assertEqual(issues, [])
        self.assertEqual(remote, set())
        self.assertEqual(deps, {'paramiko>=2.1','cryptography>=1.5'})

    def test_normal_install_does_not_require_setup_tests_require(self):
        setup = """from setuptools import setup
def run_setup():
    tests_require = read_tests()
    setup(install_requires=["six>=1.4"], tests_require=tests_require)
"""
        deps, issues = pool.setup_static(setup)
        self.assertEqual(deps, {'six>=1.4'})
        self.assertEqual(issues, [])

    def test_contract_apt_upgrade_is_explicitly_identified_for_64_tasks(self):
        contract = json.loads((ROOT / 'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/contract.json').read_bytes())
        upgrade = []
        packages = set()
        for logical, task in contract['tasks'].items():
            found, verbs = pool.apt_recipe_operations(task['repo_script_list'])
            packages.update(found)
            if verbs: upgrade.append(logical)
        self.assertEqual(len(upgrade), 64)
        self.assertTrue({'cmake','build-essential','openjdk-17-jdk',
                         'openjdk-17-jre','libpq-dev'} <= packages)

    def test_vcs_npm_resolution_is_lock_only_and_ignores_scripts(self):
        package = json.dumps({'name':'fixture','version':'1.0.0',
                              'dependencies':{'dep':'^1.0.0'}})
        integrity = 'sha512-' + __import__('base64').b64encode(
            hashlib.sha512(b'archive').digest()).decode()
        with tempfile.TemporaryDirectory() as tmp:
            candidate = pool.Pool(Path(tmp))
            (Path(tmp)/'npm').mkdir()
            (Path(tmp)/'metadata').mkdir()
            commands = []
            def git_source(mirror, commit, path, **kwargs):
                return package if path == 'package.json' else None
            def run(candidate_pool, args, *, cwd, env, timeout=1800):
                commands.append([str(x) for x in args])
                lock={'packages':{'':{'name':'fixture','version':'1.0.0'},
                                  'node_modules/dep':{
                                      'version':'1.2.3',
                                      'resolved':'https://registry.npmjs.org/dep/-/dep-1.2.3.tgz',
                                      'integrity':integrity}}}
                (Path(cwd)/'package-lock.json').write_text(json.dumps(lock))
                return ''
            with patch.object(pool,'git_file',side_effect=git_source), \
                 patch.object(pool,'_run_pinned_npm',side_effect=run), \
                 patch.object(candidate,'download',return_value='a'*64):
                artifacts=pool.npm_package_json_closure(
                    candidate,'mirror','b'*40,'owner/repo','identity')
            self.assertEqual(len(artifacts),1)
            flat=' '.join(commands[0])
            self.assertIn('--package-lock-only',flat)
            self.assertIn('--ignore-scripts',flat)
            self.assertEqual(list((Path(tmp)/'npm').iterdir()), [])
            self.assertNotIn("invoke(['npm'", (ROOT/'scripts/superbench_pool.py').read_text())

    def test_execution_host_requirements_include_fetch_runtime(self):
        requirements=(ROOT/'requirements.txt').read_text().splitlines()
        self.assertIn('python3-pip', requirements)
        self.assertIn('openssl', requirements)
        self.assertIn('nodejs', requirements)
        self.assertIn('npm', requirements)


    def test_bokeh_npm_cli_is_pinned_to_node18_compatible_npm10(self):
        self.assertEqual(pool.NPM_NODE18_VERSION, '10.9.9')
        source=(ROOT/'scripts/superbench_pool.py').read_text()
        self.assertIn("'https://registry.npmjs.org/npm/'+NPM_NODE18_VERSION", source)
        self.assertNotIn("registry.npmjs.org/npm/latest", source)
        self.assertIn("_run_pinned_npm(pool", source)

    def test_pipx_application_uses_pinned_kali_system_python_not_testbed_python(self):
        self.assertEqual(pool.GOLDEN_SYSTEM_PYTHON, '3.13')
        source=(ROOT/'scripts/superbench_pool.py').read_text()
        self.assertIn("resolver_version=GOLDEN_SYSTEM_PYTHON", source)
        self.assertIn("pipx creates its application venv from Kali's system Python", source)



if __name__ == '__main__':
    unittest.main()
