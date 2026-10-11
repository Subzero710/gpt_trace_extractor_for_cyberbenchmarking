# Distributed deployment

All historical Make operations route through `scripts/distributed.py`; the only role selector is the local `config/distributed.toml`. The checkout requires that file and does not guess a host role or fall back to a combined deployment. The pinned workstation/MCP/guest contracts and adapter recipes remain unchanged.

| Command | Acer execution host | Fossil control host |
| --- | --- | --- |
| `make requirements` | Native KVM packages, Docker image acquisition, Python venv | Control-host packages, Docker/Compose/Buildx; no KVM probes |
| `make build` | Native broker, verified permanent golden/templates, managed unit | Control Docker images, registry pins, only new empty storage |
| `make up`, `make kali_control` | Start native private broker | Start control services, or controller/gateway only |
| `make doctor` | Storage, golden/template integrity, broker inventory | Nouveau + actual teacher GPU gate + runner's real Acer runtime smoke |
| `make status` | Authenticated local project inventory | Durable active-run status |
| `make run`, `make resume`, `make pause` | Refused: control-host operations | ChatGPT/MCP orchestration and preserved recovery |
| `make register_apps`, manual Kali commands | Refused: control-host operations | Existing registration/manual lifecycle, VM allocated on Acer |
| `make export-parquet` | Refused: control-host operation | One atomic, unfiltered capture corpus |
| `make down` | Refused: global shutdown belongs to Fossil | Drain/audit/destroy Acer temporary resources, stop services, retain data/images |
| `make publish-kali-golden` | Explicit verified golden publication | Refused: no KVM on Fossil |
| `make throw_volumes` | Refused | Existing explicit THROW confirmation and destructive reset |

## Physical and storage boundaries

Both hosts require Ubuntu 26.04 and Python >=3.12. Acer requires root for its native broker, /dev/kvm, libvirt, nftables and local SSD image storage. Docker on Acer is used to acquire/package permanent images, never to launch the control plane. Fossil checks its own assigned private IPv4 address and Docker capabilities, never /dev/kvm or libvirt. The standard amd64 Ubuntu baseline is used; do not install an opt-in AVX2/v3 build on an older CPU without verifying its instruction support.

`config/runner.toml` is authoritative for the guest limits: 5120 MiB, 6 vCPUs and a 64 GiB reserved overlay are preserved. SWE-Gym Lite needs a teacher and separate evaluator concurrently. Two configured guests total 10240 MiB; an 8 GiB Acer therefore needs measured usable memory/swap and actual sustained acceptance. No source edit silently reduces memory/vCPU/disk dimensions. QEMU reservations must fit the local SSD; the complete template generation must fit before installation. There is no claimed hardware result in a source-only check.

Fossil uses `compose.control.yaml` with PostgreSQL 17, storage, persistent teacher browser/tunnel, MCP gateway/controller/tunnel, runner and benchmark fetcher. Existing internal control/storage networks remain internal. Only runner and controller receive the private broker egress route and their own client key/certificate. No Docker/libvirt socket, KVM device or Acer Unix socket is mounted. The teacher-browser identity/profile, benchmark source cache, database and runner state remain dedicated persistent volumes.

The explicit four volume names in `[storage]` must resolve to distinct, nonoverlapping directories under `[paths].storage_root`. Build initializes new empty directories/volumes only. Existing data outside that root requires verified cold migration; it is never adopted, renamed or copied implicitly. Use the same volume names on the intended control host. Never start two writable PostgreSQL instances over the same volume.

## Private configuration and PKI

Use an existing trusted provisioning host with OpenSSL. Select actual assigned RFC1918 IPv4 addresses and a broker DNS certificate identity; the transport connects to the numeric Acer address with that DNS SNI identity. Keep the CA private key offline. Provision complete distinct credential bundles:

```bash
PYTHONPATH=shared python3 -m gpt_trace_transport.pki \
  --output /path/to/new-private-pki \
  --server-name "$BROKER_NAME" \
  --acer-address "$ACER_IP" --fossil-address "$FOSSIL_IP"
```

An existing deployment can supply `--tokens-from` to preserve its two broker-token identities. The generated per-role `distributed.toml` contains the actual bundle-manifest SHA-256; verify it out of band when transferring the corresponding bundle. Install the generated local-role configuration at `config/distributed.toml` and its credential files in the configured `.secrets/distributed` directory. Preserve a mode-0700 credential directory, mode-0600 private keys/tokens and root/operator ownership. Fossil has only admin/controller client private keys; Acer has only the server private key. The CA private key belongs to neither deployment bundle. Configurations reject symlinks, unknown/missing fields, mismatched host identities, public/equal addresses, certificate/key/token/provenance changes and expired credentials.

The server requires mTLS, the exact Fossil source address, pinned role-specific client certificates and matching role-specific tokens. A controller credential cannot create/destroy attempts, change templates, allocate evaluators or shut down the broker. The runner pins the real server certificate fingerprint before sending its token. There is no proxy, unverified TLS, Unix/HTTPS downgrade or automatic mutation replay after a network loss.

Allow only Fossil's configured address to reach the private broker port. Apply the corresponding host/VPN firewall policy. Guest nftables deny Fossil's /32 before any explicit egress exception; guests cannot route to broker/control secrets or service ports. Each teacher VM still has its private libvirt NAT network and host DNS/DHCP-only input. Evaluators have no NIC, desktop, model route or shared filesystem.

Fossil's `.env` contains the existing PostgreSQL, independent teacher Kasm password/tunnel token/public HTTPS origin, OpenAI control-plane key, App tunnel ID and any gated benchmark source token. Provisioning never copies ChatGPT cookies, database files or these App credentials into a guest or an Acer bundle. The existing Kasm login form, internal Basic auth, pinned CloakBrowser, sandbox, Cloudflare routing and loopback CDP boundary are preserved.

## Permanent templates

The explicit one-time publisher is the workflow `.github/workflows/publish-template-release.yml`; see [the Lite guide](swe-gym-lite.md) for its build host and credential prerequisites. The tag is computed from the pinned source recipe, exact guest runtime sources/security contract and actual verified installed golden SHA. It is a lookup identity, not a claim that a Release already exists. Publication checks/enables GitHub immutability, builds at most once, retains diagnostics, calculates all real hashes, uploads a complete draft and verifies publication. No repository release or checksum is invented by deployment configuration.

On Acer, `make build` and `make up` retrieve the matching real permanent Release when not installed. Installation validates immutable API asset digests, the tag's source commit, every compressed part and expanded file, golden/harness compatibility, resolved-input generation identity, coverage/replay proofs, QCOW2 chains and task-scoped source/cache maps. It seals the entire generation and activates the registry atomically only after all checks. A root-owned read-only receipt and publication manifest bind installed bytes to the actual release. A missing Release explicitly reports Lite unavailable while allowing GAIA's verified golden and the broker to operate; selecting Lite then fails before any teacher allocation or attempt. Mutable, corrupted or incompatible publications and network/authentication failures abort installation/deployment. There is never a build fallback. A verified installed generation is reused entirely offline. Runtime selection, artifact delivery, evaluator allocation and checkpoint recovery recheck receipt metadata and every used backing/artifact; installation and reuse check all files. Permanent generations are never deleted by shutdown.

## Deployment and operation

After both role configurations and the permanent publication prerequisites exist, on Acer:

```bash
sudo make requirements
sudo make build
sudo make up
sudo make doctor
sudo make status
```

The managed systemd unit is installed during build/up with the exact checkout path; an unrelated existing unit is refused. Its entry point selects Acer from configuration, starts the native mTLS broker and exposes no guest/admin endpoint to the model. No control Docker service starts here.

On Fossil, with an existing usable Docker installation and correct storage:

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

Use the same operator/root identity that owns the configured private bundles and storage. GAIA still uses the pinned 2023 validation Level-3 source and native answer grading. An available tool is not a mandatory invocation. `make start_kali`, `make status_kali` and `make stop_kali` preserve the existing durable manual identity and mutual exclusion with Superbench/registration. `make tunnels` itself creates no Kali.

For Lite, fetch the pinned source on Fossil and select the adapter normally:

```bash
make superbench-fetch ADAPTER=swe-gym-lite
make run ADAPTER=swe-gym-lite LIMIT=1
make status
```

Selected source/template fingerprints are checked before teacher interaction. During a Lite attempt the teacher Kali stays active through capture and grading; a separate new isolated evaluator receives only the recorded candidate and evaluator-only hidden tests. Native grading order, parser pins, 230 task sources, 11 repository templates and 25 environments remain unchanged.

## Recovery and global shutdown

Keep runner journals, capture/candidate checkpoints and PostgreSQL rows. On transport loss, resource outcome is unknown until an authenticated inventory/discovery proves it. A response timeout never means that create/destroy did not happen, and mutations are never retried blindly. Teacher/evaluator identities, generation/source/backing hashes and task scopes remain frozen. Candidate resume allocates a new evaluator and grades the same persisted patch without new ChatGPT generation.

On Fossil:

```bash
make status
make status_kali
make resume
# Explicit abandonment, only when the operator chooses it:
make reset-recovery TASK=the_exact_run_task_id
```

Administrative read-only reconciliation remains available through `python3 scripts/distributed.py reconcile`; the runtime itself reconciles before creation/recovery. It never becomes a new Make target. An infrastructure error preserves state and stops the campaign. Native fail is a normal evaluated completed trajectory.

Run `make down` on Fossil for the whole project. It stops runner producers, sets a broker mutation barrier, verifies ownership, destroys all temporary teacher/evaluator domains, overlays/reservations, networks, firewalls and attempt artifact stores on Acer, proves authenticated absence, and acknowledges native broker shutdown. Fossil removes only project-labelled containers/networks and verifies that pre-existing volumes remain. It never clears recovery markers, terminalizes PostgreSQL rows, removes permanent golden/templates, prunes images or deletes data. Even expired remote credentials or unreachable Acer stop local Fossil services and return a nonzero cleanup-uncertainty error. No offline receipt is treated as a current absence proof. Acer refuses a local-only shutdown that could leave Fossil running. Before a later restart, start Acer's broker with `make up`, then start Fossil.

`make throw_volumes` retains its explicit THROW confirmation for the intentionally destructive historical reset. Its remote cleanup must succeed before it removes the selected mutable generation data. This is a distinct operator choice and is never part of source patch application or ordinary shutdown.

## Cold migration and verification

Cold migration helpers remain administrative Python operations, with no additional Make target. On the old stopped control deployment, `python3 scripts/distributed.py backup --directory NEW_BACKUP_DIRECTORY` hashes every volume archive and retains original secrets/config in a mode-protected archive. On Fossil, `python3 scripts/distributed.py restore --directory VERIFIED_BACKUP_DIRECTORY` validates every hash/size/member before extracting to new empty, nonoverlapping configured storage. It preserves archives and does not automatically replace deployment credentials, start services or overwrite a nonempty volume. Verify the backup manifest through your trusted transfer channel.

Source verification uses `python3 patch_distributed.py --check`, `--verify` and `--self-test`; patch application itself runs no deployment operation. Repository offline tests exercise real source transactions, real SHA/gzip file transfers, publication eligibility/provenance gates, role dispatch, failure-safe shutdown planning, normalized export rows and the actual TLS engine over in-memory records. Full application pytest suites require their declared package dependencies; controller/guest CloakBrowser 0.4.8 and runner CloakBrowser >=0.5 belong in separate environments. Do not combine incompatible package pins.

Physical acceptance is an explicit test: `python3 scripts/distributed.py acceptance` on Fossil, optionally `--adapter swe-gym-lite`. It exercises the actual private transport, VM identity/discovery, MCP shell/browser/display, multi-MiB verified transfer, Fossil-port isolation, cleanup and the separate evaluator. It cannot be replaced by a mocked VM or an offline source test. Also exercise real private-link loss, process crashes, checkpoint resume, bad certificates and artifact mutation on the intended hosts before a benchmark campaign. No source-only script claims hardware/TLS-socket/ChatGPT success or publishes artifacts by applying a patch.
