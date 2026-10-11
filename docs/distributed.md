# Distributed deployment

All historical Make operations route through `scripts/distributed.py`. The committed, generic `config/distributed.toml` defines deployment policy, while the local, ignored `.env` provides `DIST_ROLE=control` or `DIST_ROLE=execution` and the two private IPs/TLS server name. The physical machine names are never used as role identifiers. A missing `.env` is rejected rather than guessed. The pinned workstation/MCP/guest contracts and adapter recipes remain unchanged.

| Command | Execution host | Control host |
| --- | --- | --- |
| `make requirements` | Native KVM/local build packages, Docker source-fetch capability, Python venv | Control-host packages, Docker/Compose/Buildx; no KVM probes |
| `make build` | Native broker, local pinned golden, managed unit; no templates | Control Docker images, registry pins, only new empty storage |
| `make up`, `make kali_control` | Start native private broker | Start control services, or controller/gateway only |
| `make doctor` | Storage, golden provenance, broker inventory | Nouveau + actual teacher GPU gate + runner's real execution host runtime smoke |
| `make status` | Authenticated local project inventory | Durable active-run status |
| `make run`, `make resume`, `make pause` | Refused: control-host operations | ChatGPT/MCP orchestration and preserved recovery |
| `make register_apps`, manual Kali commands | Refused: control-host operations | Existing registration/manual lifecycle, VM allocated on the execution host |
| `make export-parquet` | Refused: control-host operation | One atomic, unfiltered capture corpus |
| `make down` | Local drain/cleanup/broker stop; explicitly not global | Drain/audit/destroy execution host temporary resources, confirm broker exit, stop services, retain data/images |
| `make throw_volumes` | Refused | Existing explicit THROW confirmation and destructive reset |

## Physical and storage boundaries

Both hosts require Ubuntu 26.04 and Python >=3.12. The execution host requires root for its native broker, /dev/kvm, libvirt, nftables and local SSD image storage. Docker on the execution host is used only for the isolated source-fetch build/container during local preparation; it never starts the control plane. The control host checks its own assigned private IPv4 address and Docker capabilities, never /dev/kvm or libvirt. The standard amd64 Ubuntu baseline is used; do not install an opt-in AVX2/v3 build on an older CPU without verifying its instruction support.

`config/runner.toml` is authoritative for the guest limits: 5120 MiB, 6 vCPUs and a 64 GiB reserved overlay are preserved. SWE-Gym Lite needs a teacher and separate evaluator concurrently. Two configured guests total 10240 MiB; an 8 GiB execution host therefore needs measured usable memory/swap and actual sustained acceptance. No source edit silently reduces memory/vCPU/disk dimensions. QEMU reservations must fit the local SSD; the complete template generation must fit before installation. There is no claimed hardware result in a source-only check.

The control host uses `compose.control.yaml` with PostgreSQL 17, storage, persistent teacher browser/tunnel, MCP gateway/controller/tunnel, runner and benchmark fetcher. Existing internal control/storage networks remain internal. Only runner and controller receive the private broker egress route and their own client key/certificate. No Docker/libvirt socket, KVM device or execution host Unix socket is mounted. The teacher-browser identity/profile, benchmark source cache, database and runner state remain dedicated persistent volumes.

The explicit four volume names in `[storage]` must resolve to distinct, nonoverlapping directories under `[paths].storage_root`. Build initializes new empty directories/volumes only. Existing data outside that root requires verified cold migration; it is never adopted, renamed or copied implicitly. Use the same volume names on the intended control host. Never start two writable PostgreSQL instances over the same volume.

## Private configuration and PKI

Use a trusted provisioning host with OpenSSL. Choose the actual RFC1918 IPv4 addresses and one TLS certificate DNS identity for the broker. The client connects to the numeric execution address and authenticates the TLS name. Keep the CA private key offline. Generate two role-specific credential bundles:

```bash
PYTHONPATH=shared python3 -m gpt_trace_transport.pki \
  --output /path/to/new-private-pki \
  --server-name "$BROKER_NAME" \
  --execution-address "$EXECUTION_IP" --control-address "$CONTROL_IP"
```

An existing deployment may pass `--tokens-from` to keep its token identities. Provisioning generates two bundles, `control/` and `execution/`. Each contains `manifest.json`, an automatically generated `manifest.sha256` pin, and `distributed.env` with four nonsecret local routing values. Copy the matching bundle's certificate/key/token files **and both manifest files** to `.secrets/distributed/` on that role's host. Merge the four `DIST_*` lines from its `distributed.env` into the existing `.env`; do not override application secrets or put certificates/private keys/tokens in `.env`. The tracked `config/distributed.toml` is identical on both hosts; do not replace it with a per-host file. Keep the CA private key only on the trusted provisioning host. Secure and authenticate the initial bundle transfer: the colocated checksum detects subsequent accidental changes but does not authenticate an untrusted initial transfer. A changed or missing pin, role mismatch, wrong address, changed certificate or expired certificate fails closed. Changing identities/IPs requires explicit re-provisioning, not manual hash editing.

The server requires mTLS, the exact control host source address, pinned role-specific client certificates and matching role-specific tokens. A controller credential cannot create/destroy attempts, change templates, allocate evaluators or shut down the broker. The runner pins the real server certificate fingerprint before sending its token. There is no proxy, unverified TLS, Unix/HTTPS downgrade or automatic mutation replay after a network loss.

Allow only the control host's configured address to reach the private broker port. Apply the corresponding host/VPN firewall policy. Guest nftables deny the control host's /32 before any explicit egress exception; guests cannot route to broker/control secrets or service ports. Each teacher VM still has its private libvirt NAT network and host DNS/DHCP-only input. Evaluators have no NIC, desktop, model route or shared filesystem.

The the control host's `.env` contains the existing PostgreSQL, independent teacher Kasm password/tunnel token/public HTTPS origin, OpenAI control-plane key, App tunnel ID and any gated benchmark source token. Provisioning never copies ChatGPT cookies, database files or these App credentials into a guest or an execution host bundle. The existing Kasm login form, internal Basic auth, pinned CloakBrowser, sandbox, Cloudflare routing and loopback CDP boundary are preserved.

## Permanent templates

On the control host, `make superbench-fetch ADAPTER=swe-gym-lite` verifies the pinned dataset, compares recipes with execution host and identifies a root-owned administrative preparation. The existing mTLS channel starts a finite execution host worker and polls short status requests until the full 230-task/11-repository/25-environment generation is validated and atomically active. GAIA fetch is unchanged. No other Make operation constructs Lite. `make build` on the execution host constructs only a missing pinned Kali golden locally; `make up` starts only the native broker.

`local-validation.json` contains the complete actual byte inventory and compatibility inputs for each locally built generation. Root ownership, read-only files/directories, actual SHA-256 values, golden provenance, task scopes, resolved package inventories, offline replay and native QCOW2 chains are verified automatically. First selection and explicit reuse validate all files; later tools verify metadata and used files through inode/time-sensitive hash caches. Checkpoints retain the originally selected generation. Corruption is an explicit error; valid permanent data is never replaced or deleted to repair it.

The preparation ID, private inherited build lock, durable phases, PID/boot/start-time/session and sealed-result marker allow rediscovery after a disconnect or broker restart. No timed-out mutation is blindly retried. A subsequent explicit fetch may retry only after proving the previous worker/session absent; completed sealed generations can finish activation without new VM builds. Failed stages/logs and old valid generations are preserved. Administrative preparation is not part of the controller/MCP surface and cannot receive an arbitrary command, shell or path. All image bytes stay on the execution host's SSD.

## Deployment and operation

After provisioning both role configurations and local execution host build prerequisites, on the execution host:

```bash
sudo make requirements
sudo make build
sudo make up
sudo make doctor
sudo make status
```

The managed systemd unit is installed during build/up with the exact checkout path; an unrelated existing unit is refused. Its entry point selects execution host from configuration, starts the native mTLS broker and exposes no guest/admin endpoint to the model. No control Docker service starts here.

On the control host, with an existing usable Docker installation and correct storage:

```bash
sudo make requirements
sudo make build
make up
make doctor
make tunnels
make register_apps
make auth
make superbench-fetch ADAPTER=gaia
make run ADAPTER=gaia LIMIT=3
make pause
make status
make resume
make export-parquet
```

Use the operator/root identity that owns the configured private bundles and storage. GAIA still uses the pinned 2023 validation Level-3 source and native answer grading. An available tool is not a mandatory invocation. `make start_kali`, `make status_kali` and `make stop_kali` preserve the existing durable manual identity and mutual exclusion with Superbench/registration. `make tunnels` itself creates no Kali.

For Lite, fetch the pinned source on the control host and select the adapter normally:

```bash
make superbench-fetch ADAPTER=swe-gym-lite
make run ADAPTER=swe-gym-lite LIMIT=1
make status
```

Selected source/template fingerprints are checked before teacher interaction. During a Lite attempt the teacher Kali stays active through capture and grading; a separate new isolated evaluator receives only the recorded candidate and evaluator-only hidden tests. Native grading order, parser pins, 230 task sources, 11 repository templates and 25 environments remain unchanged.

## Recovery and global shutdown

Keep runner journals, capture/candidate checkpoints and PostgreSQL rows. On transport loss, resource outcome is unknown until an authenticated inventory/discovery proves it. A response timeout never means that create/destroy did not happen, and mutations are never retried blindly. Teacher/evaluator identities, generation/source/backing hashes and task scopes remain frozen. Candidate resume allocates a new evaluator and grades the same persisted patch without new ChatGPT generation.

On the control host:

```bash
make status
make status_kali
make resume
# Explicit abandonment, only when the operator chooses it:
make reset-recovery TASK=the_exact_run_task_id
```

Administrative read-only reconciliation remains available through `python3 scripts/distributed.py reconcile`; the runtime itself reconciles before creation/recovery. It never becomes a new Make target. An infrastructure error preserves state and stops the campaign. Native fail is a normal evaluated completed trajectory.

Run `make down` on the control host for the whole project. It stops runner producers, sets a broker mutation barrier, verifies ownership, destroys all temporary teacher/evaluator domains, overlays/reservations, networks, firewalls and attempt artifact stores on the execution host, proves authenticated absence, requests broker shutdown, then verifies the actual native broker process has exited. The control host removes only project-labelled containers/networks and verifies that pre-existing volumes remain. It never clears recovery markers, terminalizes PostgreSQL rows, removes permanent golden/templates, prunes images or deletes data. Even expired remote credentials or unreachable execution host stop local control host services and return a nonzero cleanup-uncertainty error. A finite confirmation child uses the same mTLS identity after native broker exit, re-audits absence and confirms a fresh shutdown nonce. It offers only confirmation/status and exits after acknowledgement or its finite lease. Retained proof files are never current global absence evidence. The execution host permits local `make down` with `scope=execution-local; global=false` and an explicit message that control host campaign/services are not stopped globally. An inactive local broker is verified through its process record, systemd lifecycle and owned-resource audit before offline local cleanup. Before a later restart, start the execution host's broker with `make up`, then start control host.

`make throw_volumes` retains its explicit THROW confirmation for the intentionally destructive historical reset. Its remote cleanup must succeed before it removes the selected mutable generation data. This is a distinct operator choice and is never part of source patch application or ordinary shutdown.

## Cold migration and verification

Cold migration helpers remain administrative Python operations, with no additional Make target. On the old stopped control deployment, `python3 scripts/distributed.py backup --directory NEW_BACKUP_DIRECTORY` hashes every volume archive and retains original secrets/config in a mode-protected archive. On the control host, `python3 scripts/distributed.py restore --directory VERIFIED_BACKUP_DIRECTORY` validates every hash/size/member before extracting to new empty, nonoverlapping configured storage. It preserves archives and does not automatically replace deployment credentials, start services or overwrite a nonempty volume. Verify the backup manifest through your trusted transfer channel.

Source verification uses `python3 patch_local_preparation.py --check`, `--verify` and `--self-test`; patch application itself runs no deployment operation. Repository offline tests exercise real source transactions, real file SHA/permissions, local activation/provenance and durable preparation gates, role dispatch, failure-safe shutdown planning, normalized export rows and the actual TLS engine over in-memory records. Full application pytest suites require their declared package dependencies; controller/guest CloakBrowser 0.4.8 and runner CloakBrowser >=0.5 belong in separate environments. Do not combine incompatible package pins.

Physical acceptance is an explicit test: `python3 scripts/distributed.py acceptance` on the control host, optionally `--adapter swe-gym-lite`. It exercises the actual private transport, VM identity/discovery, MCP shell/browser/display, multi-MiB verified transfer, control host-port isolation, cleanup and the separate evaluator. It cannot be replaced by a mocked VM or an offline source test. Also exercise real private-link loss, process crashes, checkpoint resume, bad certificates and artifact mutation on the intended hosts before a benchmark campaign. No source-only script claims hardware/TLS-socket/ChatGPT success or constructs images by applying a patch.

The shutdown admission barrier is durable across broker restarts. Explicit execution host `make up` reopens it only after the managed broker and confirmation child are stopped and a fresh ownership audit proves temporary project resources absent. It never repairs templates or destroys resources while starting.


Finite preparations inherit a root-only cgroup v2 subtree of the existing `gpt-trace-distributed-broker.service` (`Delegate=yes`). Libguestfs uses its direct backend so detached helper processes remain inside this job's subtree. The durable job records this scope alongside PID/boot identity. Cleanup uses pidfds and, when required, the kernel subtree kill, then verifies the populated event and removes only the empty temporary scope. Source-fetch containers carry project, execution, preparation and attempt labels plus a fixed derived name; cleanup rechecks their identity, stops/removes only these temporary containers, and never prunes volumes or images. Unknown scopes, foreign container identities or unavailable inventory block a success claim. Fetch waits for the finite worker and its auxiliary resources to finish before reporting readiness.

The software tests use explicitly simulated cgroup control-file effects and Docker responses around real finite Python children, locks and immutable files. They do not exercise native cgroup, Docker, KVM, network listeners or physical benchmark integration. Native cgroup semantics follow the [Linux kernel interface](https://docs.kernel.org/admin-guide/cgroup-v2.html); delegation belongs to the [existing systemd unit](https://systemd.io/CGROUP_DELEGATION/).
