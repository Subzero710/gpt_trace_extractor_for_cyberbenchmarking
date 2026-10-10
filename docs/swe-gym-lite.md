# SWE-Gym Lite

`swe-gym-lite` uses the ordinary Kali Workstation App with runner-owned setup,
candidate capture and native grading. Template construction is a separate host
prerequisite. Campaigns never build missing permanent environments.

## Pinned sources and validated contract

| Input | Immutable identifier |
| --- | --- |
| [SWE-Gym/SWE-Gym-Lite](https://huggingface.co/datasets/SWE-Gym/SWE-Gym-Lite) revision | `f70b1a29ab120eb0a0ee7a1deb029825e735b2b0` |
| `data/train-00000-of-00001.parquet` SHA256 | `f3a7cd934e8cc523b6053298d0abb2c82fd7db2b83f9f2ccba5944545aaa4eb1` |
| [SWE-Gym/SWE-Bench-Package](https://github.com/SWE-Gym/SWE-Bench-Package) commit | `16dd480cce9b27bf111a362d280881c6def5d2a7` |
| Safe setup contract SHA256 | `fbb8b762277d09b6732a9697735889f761cf5d1920df0cafb5320809f834f38f` |
| Recipe / registry schema / adapter | `2` / `2` / `2` |
| Miniconda installer | `Miniconda3-py311_24.7.1-0-Linux-x86_64.sh` |
| Installer SHA256 | `a098a5b1581d8fd078c430b82e27106602223e335efef708a124e723814d120c` |

The actual pinned parquet and official recipe functions validate **230 tasks,
11 repos and 25 globally distinct environment hashes**, with zero unmapped tasks.
Hashes use exactly `sha256(str(env_script_list).encode("utf-8")).hexdigest()[:22]`
with the upstream name `testbed`. Ordered upstream environment-file path searches,
including 404 responses, are recorded at each exact `base_commit`. The builder
independently verifies those contents against Git objects and requires zero
missing base commits before publication.

| Repository | Tasks | Distinct envs within repo | Template suffix |
| --- | ---: | ---: | --- |
| Project-MONAI/MONAI | 27 | 1 | Project-MONAI_MONAI |
| bokeh/bokeh | 1 | 1 | bokeh_bokeh |
| conan-io/conan | 12 | 1 | conan-io_conan |
| dask/dask | 14 | 10 | dask_dask |
| facebookresearch/hydra | 11 | 1 | facebookresearch_hydra |
| getmoto/moto | 59 | 1 | getmoto_moto |
| iterative/dvc | 36 | 2 | iterative_dvc |
| modin-project/modin | 5 | 4 | modin-project_modin |
| pandas-dev/pandas | 5 | 5 | pandas-dev_pandas |
| pydantic/pydantic | 20 | 1 | pydantic_pydantic |
| python/mypy | 40 | 4 | python_mypy |

Some hashes are shared across repos. Template IDs prepend `swe-gym-lite/` to
these suffixes. The first 11 tasks cycle through all 11 repositories.

## Images, sources and trust

Teacher and evaluator each use an independent fresh overlay over the same
`repo.qcow2 -> common.qcow2 -> kali-base.qcow2` chain. There are still exactly
11 repo template IDs/images and 25 shared immutable `swegym_<env_hash>` Conda
environments. No permanent instance images are built during campaigns.

Full Git mirrors live only in the root-only host `build-cache`. They never enter
common/repo images, task overlays, mounted shares or the teacher tools. The host
builds 230 deterministic gzip/tar source artifacts. Each preserves the ORIGINAL
exact base SHA as detached HEAD, marks that SHA as the shallow boundary, and
contains exactly one reachable commit, its trees/blobs, no remote, tags, other
refs, alternates, hooks, reflogs or unreachable object corpus. Exact Gitlink
submodules receive independent single-commit checkouts at their pinned SHAs.
The validator checks clean tracked and ignored-file contents, Git configuration,
all objects versus reachable objects, SHA/size, instance/repo/base/template
association, and an independent extraction. No ancestor exception is enabled.
Pandas' upstream tag fetch can access only its own sanitized checkout, never a
full mirror or public repository. If single-commit setup is incompatible, the
build fails for operator review; history is never expanded automatically.

Host mirror -> sanitized task source -> CURRENT task overlay only. The common
image has never held any task checkout or task-source archive. Its inputs are
only the 25 environment recipes, trusted helpers and frozen OS artifacts.
Repo images hold safe repo identity/configuration, without source history.
Publication inspects common and every repo image for forbidden mirror/source
paths and Git directories. Disposable task builder disks are deleted only after
successful fresh offline replay; failed disks remain diagnostic state.

Task-dependent downloads, VCS dependencies, wheelhouses, npm state and PDM/pipx
prerequisites are likewise frozen into separate HOST-ONLY setup-cache artifacts.
Every task is warmed in its own disposable VM and then validated in another new,
network-disabled VM. No earlier task filesystem or source-containing cache can
enter a later task's permanent image or overlay.

The schema-2 manifest maps opaque artifact IDs to immutable root-owned files,
SHA/size, logical task, source identity and allowed template. The broker resolves
only the attempt's recorded generation, rejects sibling/unknown IDs, traversal,
symlinks, changed bytes/size or permissions, and streams host -> guest in 1 MiB
frames. Source/cache archives never pass through runner RAM or model-visible MCP.
The separate trusted import session is sized from the selected artifact and can
exceed the ordinary 256 MiB runner import cap. It returns only a broker-controlled
guest path and verified integrity. Controller credentials cannot invoke it.

Runtime setup extracts only the selected source, validates the graph and SHA,
clones the exact environment with Conda prefix relocation, runs official setup,
checks frozen package/OS inventories, and exposes `/testbed` as the workspace.
Repo setup and upstream evaluation-time installation have separate frozen
inventories, so evaluation-only dependencies are verified at the correct phase.
Tracked setup-file mutations are reset to the exact base after installation;
installed packages and ignored build products remain. This keeps candidate diffs
base-relative without letting candidate setup.py/pyproject affect installation.
Candidate clean verification extracts the SAME source artifact again.

## Reproducible construction and publication

The golden records `kali-last-snapshot`, a mutable alias, not an immutable
snapshot identifier. The Lite builder therefore uses two-phase APT resolution.
A disposable trusted resolver downloads the exact `.deb` closure, records each
package/version/architecture/SHA/size and the golden/resolved installed package
inventories, and checks installation with no network. Common installation uses
ONLY these verified local artifacts with `unshare --net`, empty APT lists,
`--no-download` and `--no-remove`. There is no blanket APT upgrade. Official
pre-install OS upgrade clauses are removed; a guard checks already-frozen
prerequisites without resolving packages. Missing/corrupted artifacts or an OS
inventory change stop the build. Exact `.deb` files and manifests are retained.

Only after all 230 offline setups, source validations and QCOW2 chain/check
operations succeed does the builder calculate the final canonical input hash.
It covers source/harness/contract pins, golden SHA/provenance, host/guest recipes,
Miniconda, capacity, exact OS artifacts/inventories, all 25 environment inventories,
Conda/pip caches, VCS and task-download provenance, all 230 source/cache artifact
hashes, recipe/schema/security contract, and final common/repo QCOW2 hashes.
Relative backing paths avoid a generation-directory hash cycle. Different
resolved bytes cannot reuse a previous generation identity.

Publication moves `.build-<random>` to `generations/<content-id>`, seals all files
and directories, validates through the broker, and atomically replaces
`registry.json`. Failed validation restores/preserves the build stage and leaves
the old registry untouched. Recipe/schema-1 generations are rejected. Adapter
version 2 gives new run-row identities while source instance IDs stay unchanged.

The builder remains sequential and sparse, monitors the host free-space margin,
and reports common physical bytes, 11 repo-image physical bytes, 230 source
physical/logical bytes, setup-cache physical/logical bytes, and total unique-inode
immutable generation allocation. Published images, artifacts, manifests and audit
records are root-owned and read-only. Default virtual capacity is 512 GiB; the
host attempt reservation remains separately configured.

## Real-host commands

Use the dedicated Ubuntu/KVM host with the existing runtime requirements and
packages in `requirements-golden-build.txt`. The builder requires Docker, Git,
QEMU, `virt-customize`, `virt-cat`, `virt-copy-out` and `dpkg-deb`. Stop active/manual
attempts before replacing the installed Kali base. The internal guest streaming
capability changes the golden build-input hash: build/install the golden from this
checkout (or publish that matching image on the publishing host) before Lite builds.

```bash
# On the KVM image-building host, build the matching golden locally:
sudo python3 infra/workstation/image/build.py --local
# Deploy the matching golden and rebuild/start the runtime containers.
make build
make up
make superbench-fetch ADAPTER=swe-gym-lite
sudo make swe-gym-lite-templates
make template-doctor ADAPTER=swe-gym-lite
make doctor
make auth
make run ADAPTER=swe-gym-lite LIMIT=1
make status
```

Optional sparse capacity, margin and per-VM deadline:

```bash
sudo make swe-gym-lite-templates \
  TEMPLATE_BUILD_ARGS="--virtual-gib 512 --free-space-gib 64 --build-timeout-hours 96"
```

Read the builder's physical-size report. Failed `.build-<id>` directories retain
host logs and guest disks. Guest logs are in `/var/log/swe-gym-lite-builder.log`
and `/opt/swe-gym-lite/logs/`; inspect stopped images with `virt-cat`.

After a successful single-task smoke:

```bash
make run ADAPTER=swe-gym-lite LIMIT=11
make run ADAPTER=swe-gym-lite LIMIT=25
make run ADAPTER=swe-gym-lite
```

Completed rows are skipped under the existing contract checks. Each new campaign
preflights its selected immutable templates before committing active-run state
or connecting the teacher; unselected dataset sources are not discovered.

## Grading and recovery

Teacher overlay -> durable conversation and candidate.patch -> NEW isolated
evaluator overlay -> native hidden grading. The evaluator shares only immutable
repo/common/golden backings with the teacher. It has no NIC, shared filesystem,
desktop, browser, gateway attachment, App resource or model-facing route. Only
runner/broker credentials and authenticated host vsock can reach it. Loopback
continues to work in offline execution namespaces.

The order is exact base -> clone exact env -> official pre-install/install/setup
ON CLEAN BASE -> verify/reset tracked setup mutations -> import/apply the exact
persisted candidate -> official hidden test patch -> official test command ->
pinned log parser -> FAIL_TO_PASS/PASS_TO_PASS grading. Upstream eval-time install
also runs before the candidate. Candidate bytes are imported only after clean
setup has returned its proof. No post-candidate installation runs.

Capture keeps a temporary Git index, binary diffs, new/deleted files, the real
index, atomic host export and SHA verification. The durable journal phases are
`conversation_checkpointed` and `candidate_checkpointed`. Gold code patches never
enter either VM. Hidden test patches enter ONLY the evaluator, and oracle lists
remain in the trusted host parser/grader; neither ever enters the teacher VM.
Logs are evaluator artifacts, with compact hashes/counts/identities in storage.

| Event | Outcome |
| --- | --- |
| Native pass or native fail | Destroy evaluator, complete storage with verdict, normal teacher cleanup, continue |
| Template/setup/capture/parser/broker/QEMU/storage error | Preserve existing checkpoints/logs and remaining runtime state; `needs_intervention`; stop |
| Explicit resume after durable candidate | Abandon stale evaluator, allocate NEW retry over recorded backing, grade SAME patch; no recapture or model generation |
| Explicit reset-recovery | Abandon both runtimes, terminalize old attempt, retry same frozen task on next attempt |
| SIGINT / RateLimited | Existing cooperative pause / Retry-After behavior |

Evaluator identities include teacher run-task ID, attempt, environment,
fingerprint, purpose=evaluator and a new grading retry ID. Template ID,
generation, backing SHA and logical source scope are verified against the teacher
record. A durable host index is written BEFORE evaluator allocation, so partial
construction/stopped VMs remain recoverable. A stale evaluator is never silently
reused; only explicit checkpoint resume authorizes its abandonment. Status
includes checkpoint, candidate SHA and evaluator metadata. Broker inspect retains
partial evaluator paths even before guest boot succeeds.

```bash
make status
make resume
make reset-recovery TASK=<run_task_id_from_status>
make resume
```

Neither durable phase resumes ChatGPT generation. Conversation deletion connects
the teacher browser only after evaluation completes. Unexpected infrastructure
errors never skip tasks or automatically delete diagnostic guests. GAIA/manual
Kali, normal App tools, pause/rate-limit behavior and typed SFT export stay intact.

## Validation and operational limit

The original 314-test baseline is retained. With the actual pinned parquet
available, the implementation validation passed all 401 tests with zero skips
(42 unchanged upstream escape-sequence warnings). Regression coverage additionally
checks real multi-commit Git sanitization and exact submodules, ignored/unreachable
history attacks, task-scoped delivery, >256 MiB streaming, evaluator identity and
network isolation, hidden-data routing, clean setup before candidate application,
exact checkpoint recovery/abandonment, actual Debian artifact metadata/integrity,
resolved generation identity and atomic publication. These tests model libvirt;
real KVM construction and smoke execution are separate acceptance gates.

With runner test dependencies and broker installed:

```bash
GPT_TRACE_SUPERBENCH_SOURCE_ROOT=/absolute/path/to/fetched/sources \
PYTHONPATH=apps/runner/src:apps/workstation-broker/src:apps/kali-workstation/src:apps/mcp-gateway/src \
python -m pytest apps/runner/tests apps/workstation-broker/tests \
  apps/kali-workstation/tests apps/mcp-gateway/tests -q
```

That directory must contain
`swe-gym-lite/train-00000-of-00001.parquet` with the pinned checksum. Without the
source-root variable, the live parquet test is skipped. Original pinned harness
escape-sequence syntax warnings are retained without altering upstream bytes.

No real host template generation or ChatGPT smoke campaign was executed in the
implementation workspace. The host commands must build and validate all 12
permanent images before a campaign starts. Fresh offline setup replay and native
end-to-end host execution remain operational acceptance checks.
