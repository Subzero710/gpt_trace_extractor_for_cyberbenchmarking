# SWE-Gym Lite

`swe-gym-lite` uses the ordinary Kali Workstation App with runner-owned setup,
candidate capture and native grading. `make superbench-fetch ADAPTER=swe-gym-lite`
now performs download-only acquisition on `execution`, without KVM, QCOW2,
Conda environment creation or runtime installation. Artifacts are verified once
before immutable pool publication; an interrupted fetch remains a terminal zombie.
The runtime described below remains legacy and is not yet integrated with this pool.

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
missing base commits before local activation.

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
Local validation inspects common and every repo image for forbidden mirror/source
paths and Git directories. Disposable task builder disks are deleted only after
successful fresh offline replay; failed disks remain diagnostic state.

Task-dependent downloads, VCS dependencies, wheelhouses, npm state and PDM/pipx
prerequisites are likewise frozen into separate HOST-ONLY setup-cache artifacts.
The warm build cache persists only package-manager download/build cache across
tasks; captured setup artifacts remain task-scoped. Package capture prefers built
wheels and falls back to source archives only when a dependency cannot be wheeled,
so the fresh offline replay avoids repeating avoidable source builds. Every task
is warmed in its own disposable VM and then validated in another new,
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

## Reproducible local construction

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

The local builder `scripts/build_local_templates.py` runs only inside the root-owned administrative job on the execution host. It reuses the pinned recipes and constructs sequential sparse images. It monitors the existing 64 GiB free-space safety margin and reports the measured common/repository/archive/setup-cache allocation. The existing per-guest build timeout remains 96 hours. Default template virtual capacity remains 512 GiB; the attempt reservation stays separately configured.

The complete byte inventory in `local-validation.json` binds all files to the actual source recipe, native helpers, verified golden and generation. It contains only SHA-256 values calculated from actual built bytes. Installation seals files and directories, atomically renames the complete generation, rechecks native QCOW2 chains and all task scopes, then atomically activates `registry.json`. Validation failure retains diagnostics and leaves the previous registry/generations unchanged. Completed generations are never automatically removed, including generations referenced by recovery checkpoints.

The broker checks owner, permissions, manifest/recipe/provenance, 230 source mappings, 11 repository templates, 25 environments, frozen OS/package audits and offline replay proofs. It verifies all bytes on installation/reuse and first selection. Subsequent tool operations validate metadata and only the backing/artifacts actually used, with SHA caches keyed by inode, size and modification/change times. Every attempt/evaluator/checkpoint retains its original generation. Missing, corrupt or incompatible local files fail before teacher interaction with `make superbench-fetch ADAPTER=swe-gym-lite` in the diagnostic. They never authorize an implicit build.

## Preparation and deployment

After installing the role configuration, on the execution host:

```bash
sudo make requirements
sudo make build
sudo make up
sudo make doctor
```

Build prepares the broker and local pinned Kali golden. Up starts only the broker; neither prepares Lite. On the control host:

```bash
sudo make build
make up
make superbench-fetch ADAPTER=swe-gym-lite
make doctor
make auth
make run ADAPTER=swe-gym-lite LIMIT=1
make status
make export-parquet
```

Fetch first runs the unchanged benchmark source fetcher, which verifies the official pinned dataset and exact task contract. control host and execution host then compare their source/recipe fingerprints. A preparation ID is derived from these exact inputs and the actual verified golden. Only callers authenticated with the control host's independent administrative broker bearer token can start/query the job through the dedicated tunnel. No physical hostname or private LAN address is pinned in application code. Controller/MCP/model/guest credentials cannot access preparation, lifecycle or evaluator routes. There is no shell RPC, arbitrary command or task-controlled installation path.

The native broker starts one detached, finite worker and responds immediately. Short status requests report `starting`, `running`, `validating`, `ready`, or an explicit terminal error. A root-only state directory and an inherited flock identify the job across disconnects and broker restarts. PID, boot ID, start time and private process session prevent ambiguous duplicate mutations. A lost response never causes an automatic start retry. Rerunning the explicit fetch rediscovers the ID; only a proved-dead failed/interrupted job can be retried. Sealed results interrupted before activation can be validated and activated without rebuilding. Failed build stages, logs and original valid generations remain available for investigation.
Task checkpoints and interrupted scratch recovery are additionally bound to a
small semantic task-runtime schema and to a real Conda `testbed` clone. Compatible
implementation-only edits keep the same schema and can reuse completed work; a
semantic setup change bumps the schema, leaving older checkpoint files on disk for
diagnostics without authorizing their reuse.

Fetch returns success only after complete validation and activation, and records the actual generation. Permanent reuse checks the full immutable inventory, provenance and recorded integrity signatures. GAIA fetch remains unchanged and does not invoke the Lite builder. Source/dependency downloads needed for this local construction are verified by the existing pins, Git commits, package hashes and resolved provenance. No external image publication or image registry is used.

`make down` on the control host drains both runtime mutations and finite preparation workers, destroys only project-owned temporary resources, proves their absence and requests native broker exit. A finite, admin-only Unix-socket confirmation child reuses the Cloudflare Tunnel route after the actual broker PID/start-time has disappeared, audits absence again, confirms the fresh shutdown ID, and exits. A failed connection is never absence or broker-exit evidence. execution host `make down` performs local cleanup/exit and explicitly reports that control host campaign/services are outside this local scope. Golden, templates, permanent sources/environments, PostgreSQL, Docker volumes, traces and checkpoints are retained.

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
Kali, normal App tools, pause/rate-limit behavior and unfiltered typed Parquet export stay intact.

## Validation and operational limit

`python3 patch_local_preparation.py --self-test` applies the complete migration to a disposable copy and exercises source transactions, real file hashes/permissions, local activation, job tracking/restart/disconnect/cancellation, admin scope, shutdown proofs, existing capture/export functions and the actual TLS record engine offline. Synthetic QCOW2 metadata and package inventories in software tests are identified as fixtures; these checks do not execute KVM or ChatGPT or claim physical benchmark success.

With the declared runner/broker/guest test dependencies installed in compatible environments:

```bash
GPT_TRACE_SUPERBENCH_SOURCE_ROOT=/absolute/path/to/fetched/sources \
PYTHONPATH=shared:apps/runner/src:apps/workstation-broker/src:apps/kali-workstation/src:apps/mcp-gateway/src \
python -m pytest apps/runner/tests apps/workstation-broker/tests \
  apps/kali-workstation/tests apps/mcp-gateway/tests -q
```

The source root must contain `swe-gym-lite/train-00000-of-00001.parquet` with the pinned checksum. The live dataset test reports its prerequisite when absent. Native source sanitization, exact submodules, scoped delivery, isolated evaluator, hidden-data routing, clean setup before candidate application, grading and checkpoint recovery retain their existing regression tests. `python3 scripts/distributed.py acceptance --adapter swe-gym-lite` on the control host is the separate physical acceptance operation. It requires actual hosts and a successfully prepared generation; offline source checks never substitute for it.

The shutdown admission barrier is durable across broker restarts. Explicit execution host `make up` reopens it only after the managed broker and confirmation child are stopped and a fresh ownership audit proves temporary project resources absent. It never repairs templates or destroys resources while starting.


Finite preparations inherit a root-only cgroup v2 subtree of the existing `gpt-trace-distributed-broker.service` (`Delegate=yes`). Libguestfs uses its direct backend so detached helper processes remain inside this job's subtree. The durable job records this scope alongside PID/boot identity. Cleanup uses pidfds and, when required, the kernel subtree kill, then verifies the populated event and removes only the empty temporary scope. Source-fetch containers carry project, execution, preparation and attempt labels plus a fixed derived name; cleanup rechecks their identity, stops/removes only these temporary containers, and never prunes volumes or images. Unknown scopes, foreign container identities or unavailable inventory block a success claim. Fetch waits for the finite worker and its auxiliary resources to finish before reporting readiness.

The software tests use explicitly simulated cgroup control-file effects and Docker responses around real finite Python children, locks and immutable files. They do not exercise native cgroup, Docker, KVM, network listeners or physical benchmark integration. Native cgroup semantics follow the [Linux kernel interface](https://docs.kernel.org/admin-guide/cgroup-v2.html); delegation belongs to the [existing systemd unit](https://systemd.io/CGROUP_DELEGATION/).
