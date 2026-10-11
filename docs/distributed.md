# Fossil Control Plane / Acer Execution Plane

## Scope and validation status

This migration is pinned to the actually read repository commit
`6b22d4da8c3bf1e384917124a468d8714a85232e`. It preserves the Kali MCP 3.0.0
manifest, App registry, guest vsock protocol, immutable source scopes, evaluator
restrictions, storage schema, teacher identity and existing single-host targets.

Source checking, Python parsing and configuration checking are not deployment
tests. The development sandbox does not provide KVM, Docker, the existing Python
application dependencies or permission to create sockets. The real socket/TLS
suite and both physical-host acceptance commands must be run before collecting
a corpus. Twenty offline tests passed in that sandbox: source transactions,
rollback/idempotence, PKI validation, manifest/golden contracts and an actual
OpenSSL mTLS handshake/encrypted byte exchange through MemoryBIO. MemoryBIO
does not exercise sockets, HTTP, the broker or either physical host. No network
TLS, KVM, hardware, MCP or full benchmark success is asserted here.

## Architecture and interfaces

Fossil runs the nine existing Compose services, including the runner and source
fetch one-offs. `compose.control.yaml` is a standalone Compose document (JSON,
which is valid YAML), with the original project name and explicitly named external
volumes. `core_internal` and `app_control` stay internal. Only the runner and
Kali controller additionally join `broker_private_egress`; there is no incoming
LAN service on that bridge. Storage and CDP remain loopback-only. Teacher
KasmVNC and both tunnels retain their original Docker networks and routing.

Acer runs only the privileged native broker and libvirt/QEMU guests. Its broker
serves the existing Unix socket and a small bounded mTLS HTTP front end in the
same process. Only Fossil's configured LAN source address is admitted. The
listener binds the configured RFC1918 address, never `0.0.0.0` or a public
address. Libvirt, QMP, AF_VSOCK and golden/template files never cross the LAN.

Both Python clients share one transport package. Unix mode retains the existing
HTTPX AF_UNIX transport. Explicit mTLS mode uses a private numeric destination,
CA validation, a required DNS SAN, a pinned server certificate verified before
sending a token, and distinct pinned admin/controller client certificates and
tokens. The front end binds each client certificate to its original token scope;
the native broker independently checks the token and trusted operation scope.
There is no downgrade, public broker, proxy-environment routing or automatic
replay of a mutating request. A later operation makes a new authenticated
connection. Timeouts are 10 seconds for connection and at most 1900 seconds for
an operation, allowing the existing 1810/1850-second guest RPC contracts.

Frames and responses are capped at 32 MiB. Artifact and seed traffic retain
their existing 1 MiB chunks, bounded totals and end-to-end hashes. Only existing
broker operations handle guest artifacts; no remote host path is accepted.

The cohost assumptions removed are the provider/controller Unix-only HTTPX
constructors, runner/controller socket bind mounts, combined KVM/Docker build
and host doctor, `make up` starting a local broker, and shutdown coupling local
VM destruction to Docker and erasing recovery markers. Tunnels, gateway URLs,
teacher CDP, database, exports and benchmark state all remain local to Fossil.
The old `scripts/down.py` retains its historical single-host semantics; use the
explicit distributed targets for the new architecture.

The original golden fingerprint included the unused host controller source.
`host-controller-input.json` reverses only the reviewed host-only edits before
hashing that input; its original SHA256 is checked. Guest code/locks/provisioning
are unchanged, so the original golden input fingerprint remains exactly
`4130895e6f37115739a3b832d8b5e6ce3c371a403968cda95c57a249e4a0f29e`.
Unknown controller revisions stop golden reuse rather than inventing a tag.

## Source migration

At the repository root, with Python >=3.12:

```bash
python3 patch_distributed.py --check
python3 patch_distributed.py --dry-run
python3 patch_distributed.py --apply
python3 patch_distributed.py --verify
```

The patch validates the complete pinned file catalog before any source write,
precomputes transformations, parses produced modules/configurations, records
backups and journal hashes, and replaces files atomically. A second apply does
not rewrite compliant files. It never invokes runtime operations, reads secrets,
modifies `/etc`, adjusts partitions/firewalls, or touches live VM/Docker data.
`--rollback` refuses to overwrite any later edit, including new generated files.

## Prerequisites and placement

Use Ubuntu 26.04.1 on both hosts. Set the actual private IPv4 addresses and a
chosen broker DNS certificate identity during provisioning below. The DNS
identity need not resolve: the client connects to the explicitly configured
numeric address and verifies the hostname separately. Verify SSH host keys by
an independent channel before copying secrets or backups between hosts.

On Acer, install the existing host requirements, Python venv support, libvirt,
KVM, nftables and Docker Engine for the unchanged verified golden **artifact
installer**. No control-plane container is built or started there. Create
`/var/lib/libvirt/images/gpt-trace` on the local SSD and keep golden, templates,
reservation files, artifact stages and overlays there. `acer doctor/build`
verify a nonrotational local block device and KVM/libvirt access.

On Fossil, install Python >=3.12, OpenSSL, iproute2, git and Docker
Engine/Compose/Buildx. KVM and libvirt are not required or inspected. Ensure the
configured `/srv/stockage/cyber-dataset` is on Fossil's intended MergerFS storage.
The volume initialization command creates explicit bind-backed external volumes
there; it never adopts nonempty unrecognized data or alters an existing volume.

Use the standard `amd64` Ubuntu image/packages on Fossil. Canonical documents
the standard baseline separately from the optional `amd64v3` variant, which
requires AVX2 and other later instructions. Do not opt this i5-2500 into that
variant. This OS distinction still does not validate the pinned Chromium binary
or its GPU path; the running-browser probe below remains mandatory. See
[Canonical architecture baselines](https://documentation.ubuntu.com/project/how-ubuntu-is-made/concepts/supported-architectures/)
and [Ubuntu 26.04 LTS changes](https://documentation.ubuntu.com/release-notes/26.04/summary-for-lts-users/).

The versioned resource values remain `memory_mb=5120`, `vcpus=6`, and
`overlay_quota_gb=64`, and remain configurable in `config/runner.toml`. Copy the
same workstation table to both hosts. The authenticated deployment probe checks
that the table hashes match. One teacher and one isolated evaluator together
configure 10240 MiB of guest RAM, exceeding Acer's stated 8 GiB physical RAM.
Real simultaneous RSS/swap capacity and two complete overlay reservations must
be measured on Acer. This patch does not silently resize a guest or claim that
the stated physical memory guarantees evaluator execution.

## Verified cold backup before switching

On the existing single-host installation, pause the campaign and wait for the
runner to finish the current task. Stop manual Kali cleanly. Record active-run,
teacher identity, source cache and storage status. Stop all project containers
without deleting volumes, including one-off runners. Confirm with `docker ps`.

```bash
make pause
make status
make stop_kali
docker compose --profile runner --profile app-tunnels stop
sudo python3 scripts/distributed.py backup --directory /path/to/new-cold-backup
```

Use a real destination on an appropriate disk. Backup refuses running project
containers and writes all four cold volume archives plus deployment secrets and
the original workstation config. It prints the backup manifest SHA256. Keep
that digest through an independent channel and verify it on Fossil before
restoration; restore then validates every archive hash and all member paths
before extracting anything. Cold PostgreSQL restoration uses the unchanged
PostgreSQL 17 image. Preserve the original volumes and source-host backup until
the physical acceptance and corpus/export comparison pass.

Active QCOW2 overlays are not copied or modified by this procedure. If a
campaign has an unfinished attempt, keep its Acer VM/storage and exact runner
journal; do not migrate its backing generation mid-attempt. If the old execution
host is not Acer, finish or explicitly abandon that attempt before moving the
golden/templates offline. Copy only immutable verified golden/template artifacts
and their provenance to Acer, keeping root ownership and read-only modes.

## Certificates, tokens and configuration

Run the dedicated CA provisioning on a trusted offline administration machine
with the patched repository and OpenSSL. Supply the real values for the shell
variables below; never put private keys or tokens in Git. Reuse the existing
broker tokens with `--tokens-from` during migration, preserving all App-control
tokens and teacher credentials separately. For a fresh install, omit that option.

```bash
PYTHONPATH=shared python3 -m gpt_trace_transport.pki \
  --output .secrets/new-distributed-authority \
  --server-name "$BROKER_DNS_NAME" \
  --acer-address "$ACER_IP" --fossil-address "$FOSSIL_IP" \
  --control-id fossil --execution-id acer --port 9443 \
  --tokens-from .secrets
```

The output contains `authority`, `acer`, and `fossil` directories. Keep the CA
private key offline. Acer receives only its server key, the two public client
certificates and broker tokens. Fossil receives its distinct admin/controller
keys and tokens, and the public server certificate. The creation result gives
each bundle manifest digest and the server certificate fingerprint.

Copy the appropriate bundle to `.secrets/distributed` on each host with an
SSH-host-key-verified channel. Copy its `distributed.toml` to
`config/distributed.toml`. Keep `.secrets` and the bundle directory at 0700,
private keys at 0600, and initially tokens at 0600. The existing Compose token
materializer may set tokens to 0444 behind the private directory; keys never use
that exception. Confirm the printed manifest SHA256 on both destinations
through the independent channel. Configuration loading verifies every bundle
hash, role, host identity, address, certificate purpose, expiration and key mode.
Never copy the authority or the other host's private key to a runtime machine.

Configure the storage volume names from the original rendered Compose metadata.
Existing names are preserved when their data already reside in the required
Fossil storage root. For cross-host restoration use fresh empty Fossil bind-backed
volumes, retaining the original data and restoring the exact teacher identity,
runner state and source bytes. All operational addresses, host identities,
paths and volume names are in the generated non-secret TOML.

Only the Acer broker port may cross this LAN boundary. Configure the host/LAN
firewall to accept it from Fossil's configured source address and reject every
other source, independently of mTLS. Inspect `ip route get "$ACER_IP"` on Fossil
to confirm the selected source matches the configured address. There is no
automatic host firewall installation. Existing per-attempt nftables rules still
block private/IPv6 destinations and limit Acer input to DHCP/DNS. An explicit
Fossil /32 drop precedes every configured private target exception. Keep all
Fossil control addresses out of `egress_allow_cidrs`; additional control aliases
must not be introduced as benchmark target networks.

For rotation, provision a new dedicated generation offline, keep the existing
tokens via `--tokens-from`, verify and replace both bundles/config pins during a
paused campaign, and restart the broker/control containers. A broker restart
does not destroy VMs. Reconcile interrupted requests after restart; do not replay
an input, shell command or upload chunk whose outcome is unconfirmed.

## Acer installation and start

With the Acer bundle/config installed and immutable data on its SSD:

```bash
sudo make acer-build
sudo make acer-unit
sudo install -m 0644 state/distributed/gpt-trace-distributed-broker.service \
  /etc/systemd/system/gpt-trace-distributed-broker.service
sudo systemctl daemon-reload
sudo systemctl enable gpt-trace-distributed-broker.service
sudo make acer-up
sudo make acer-doctor
sudo make acer-status
```

Unit installation is an explicit runtime deployment action, not an action of
`patch_distributed.py`. The unit launches only the broker on Acer. The build
refuses known project domains before golden installation and never discards an
existing golden after a failed verification. Template construction is the
existing native host builder:

```bash
sudo make acer-templates
```

Its pinned upstream task/template source acquisition runs on Acer for immutable
execution artifacts. It is not a Superbench service and no runner container is
started. Golden/template installation and benchmarking are separate operations.

## Fossil installation and start

Preserve or restore the original `.env`, App-control token and teacher password
securely from `local-secrets.tar`; do not overwrite the new distributed bundle.
They are validated by the unchanged project state/tunnel workflows. Never log
or publish their content.

```bash
sudo make fossil-init-storage
# For an existing installation migrated to empty Fossil volumes:
sudo make fossil-restore BACKUP=/path/to/verified-cold-backup
make fossil-build
make fossil-up
make fossil-doctor
make fossil-tunnels
make fossil-auth
make fossil-start-kali
make fossil-status-kali
# Use the existing Kali Workstation MCP App; its browser runs inside Acer's VM.
make fossil-stop-kali
```

The real teacher probe connects to the running, pinned headed Chromium and
checks CDP GPU feature status, the actual GPU renderer and WebGL rendering/readback.
It also checks Nouveau on the host and the existing non-root/sandbox/X11/Kasm
health contracts. It closes only its temporary page and Playwright connection.
The i5-2500's lack of AVX2 and the presence of `/dev/dri/renderD128` do not prove
this Chromium build works. Startup plus the actual probe are the acceptance
gate. A software renderer or failed GPU/CPU/browser probe exits nonzero; there
is no renderer, browser or sandbox downgrade.

## Benchmark, traces and exports

```bash
make fossil-fetch ADAPTER=gaia
make fossil-run ADAPTER=gaia LIMIT=3
make fossil-status
make fossil-pause
make fossil-resume
make fossil-export-parquet
make fossil-export-sft
```

These invoke the original scheduler, PostgreSQL API, provenance, trace capture
and typed exporters on Fossil. Completed rows and existing sources are retained.
Run the native Lite path after fetching pinned Lite sources on Fossil and
building/publishing matching immutable templates on Acer:

```bash
make fossil-fetch ADAPTER=swe-gym-lite
make fossil-template-doctor ADAPTER=swe-gym-lite
make fossil-acceptance ADAPTER=swe-gym-lite
make fossil-run ADAPTER=swe-gym-lite LIMIT=1
```

The actual full benchmark still requires the existing registered App and teacher
authentication. No substitute trace, evaluation result or success is generated.

## Network loss, crash recovery and shutdown

Communication failure never means absence. Remote creation first asks the
authenticated broker to prove absence or rediscover the exact surviving
identity. A partial/stopped runtime that cannot be verified is preserved and
blocks progress. A lost creation response is never handled by replaying creation.
Unknown shell/input/upload outcomes require inspection. Template evaluator
ownership/checkpoints and explicit stale-evaluator recovery retain their original
contracts. Distributed infrastructure errors retain the runner journal/VM/binding.

```bash
make fossil-reconcile
make fossil-status
make fossil-status-kali
make fossil-resume
# Explicit abandonment only for a matching pending benchmark journal:
make fossil-reset-recovery TASK=the_exact_run_task_id
```

After a controller/gateway restart, the normal resume path rebinds the exact
broker-verified attempt. After an Acer broker crash/restart, all libvirt/state/
backing/fingerprint checks still apply. Inspect `sudo make acer-status` for
partial allocation, evaluator retries and stopped resources. Unknown ownership
blocks destruction instead of deleting a similarly named domain/network.

```bash
make fossil-pause
make fossil-down
sudo make acer-down
```

Fossil down stops one-off runners, audits/destroys owned Acer resources, checks
authenticated absence and stops the control containers without deleting volumes
or recovery markers. If Acer is unreachable, control containers still stop and
the command exits nonzero; VM cleanup remains unconfirmed. Restore connectivity
and reconcile before claiming a clean shutdown. Acer down audits locally and
stops its broker only after all project resources are proven absent.

## Tests and two-machine acceptance

```bash
python3 -B -m unittest discover -s tests/distributed -p test_offline.py -v
make distributed-test
make fossil-doctor
make fossil-acceptance
make fossil-acceptance ADAPTER=swe-gym-lite
```

Run the existing application tests in separate environments. The existing
runner requires CloakBrowser >=0.5 while the Kali package pins 0.4.8; installing
both projects in one environment has a pre-existing dependency conflict. Their
Docker images and these test environments keep those pins separate:

```bash
for app in runner kali-workstation mcp-gateway storage; do
  python3 -m venv "state/distributed/tests/$app"
  "state/distributed/tests/$app/bin/python" -m pip install -e shared -e "apps/$app[test]"
  "state/distributed/tests/$app/bin/python" -m pytest "apps/$app/tests" || exit "$?"
done
python3 -m venv state/distributed/tests/broker
state/distributed/tests/broker/bin/python -m pip install -e shared \
  -e apps/workstation-broker 'pytest>=8.3,<9' 'pytest-asyncio>=0.25,<1' 'httpx>=0.28,<1'
state/distributed/tests/broker/bin/python -m pytest apps/workstation-broker/tests infra/browser/tests
```

The stdlib suite performs actual UDS/TLS/file-transfer operations, SAN/pin and
certificate/token scope rejection, expiration, permissions, invalid framing,
timeouts and a disconnect **after a real file mutation** with no replay. Offline
tests validate generated certificates/bundles and patch transaction, idempotence,
rollback conflicts, symlinks and source-only behavior. They do not simulate KVM
success. Physical acceptance creates/discovers a real Acer VM via Fossil, runs
the unchanged MCP GUI/PTY/browser smoke, checks exact artifact bytes/hashes,
tests Fossil network isolation, rebinds that same runtime, and verifies cleanup.
The Lite acceptance additionally materializes real scoped template artifacts and
boots a separate evaluator with only `lo`, no browser RPC and matching immutable
backing/source hashes. Native grading/SFT validity are checked by the actual
benchmark plus the original export tests.

For the required outage test, record manual VM identity and broker inventory,
interrupt only the broker LAN connection at a controlled network point, and run
`fossil-status-kali`/`fossil-resume`. They must report unavailability/error without
false destruction or journal clearing. Restore the link and verify the same
identity/overlay/fingerprint before issuing new commands. Repeat after killing
only the Acer broker process, restarting the controller/gateway, and crashing
the runner during a persisted candidate checkpoint. Check source/evaluator
provenance, preserved candidate hash, recovered native evaluation, and final
authenticated absence. Never kill the QEMU guest to simulate a transport failure.

Compare PostgreSQL row counts, teacher fingerprint, runner journals/candidates,
source hashes and completed Parquet/SFT outputs against the cold backup. Treat
any known failure as a failed acceptance gate, not a successful migration.

## Return to single-host operation

Pause and stop distributed work, prove remote absence and preserve another cold
backup. Keep the original volumes and immutable image generations. Move only
offline data to the chosen single host, verifying backup hashes and restoring
the exact teacher identity/state. Restore the original broker/App tokens from
the protected backup and use the original volume names. Disable the distributed
systemd unit explicitly. Remove `COMPOSE_FILE` and distributed transport variables
from the shell environment. The historical Make targets are still present:

```bash
python3 patch_distributed.py --rollback
sudo make build
make up
make doctor
```

Source rollback does not move or delete persistent data, certificates, units,
volumes or VM images. It refuses later source edits. If the source rollback has
already occurred, both the cold backups and the explicitly installed unit must
still be managed by the operator; no source patch silently undoes a deployment.
