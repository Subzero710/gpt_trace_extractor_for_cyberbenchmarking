# Golden construction and recovery

The historical `make build` dispatches from the existing distributed role
configuration and private `.env`. Only execution constructs the golden.
Control never calls the image builder. No additional Make target is required.
The image directory must already be its configured dedicated local mount.

## Persistent checkpoints

Journal schema 2 records an input fingerprint, original repository commit,
stage, semantic phase, exact file sizes/hashes and the last failure. The phases
are `new`, `source_acquired`, `base_converted`, `offline_started`,
`offline_complete`, `guest_started`, `guest_complete`, `manifests_collected`,
`provenance_generated`, `prepared`, and `installed`.

Each fingerprint has a deterministic `.golden-build-<fingerprint>` directory.
The stage journal is fsynced before the global `golden-install.json`. Recovery
checks both identities and accepts an advanced stage checkpoint only after
validating its complete inventory. It never chooses an arbitrary newest stage.
Unknown schemas, symlinks, conflicting identities and corrupted committed
checkpoints fail with their bytes retained. A missing journal can rediscover
only the exact deterministic stage, with its own valid proof. An empty stage
left by an interrupted mkdir has no reusable artifacts and can be initialized.

Conversion has its own hashed receipt before rename. Only the explicitly
uncommitted conversion `.part` can be overwritten after interruption; completed
QCOW2s and permanent artifacts are never deleted. Offline injection has an
explicit in-progress phase and can repeat its exact bundle/unit writes. All
injected bytes are read back before boot. The golden constructor's systemd
unit receives a private snapshot whose semantic fingerprint was checked before
injection; concurrent checkout edits cannot change those injected bytes. The
constructor's systemd
unit survives unsuccessful boots, so a guest failure can replay its steps on
the same image. APT checkpoints verify actual installed inventories, existing
venvs are checked and retained, and filesystem growth first inspects capacity
and growpart's dry-run result.

`guest_started` deliberately permits the guest to mutate the image. Recovery
first verifies its injected identity and QCOW2 integrity, then inspects its
completion proof. A proven success is checkpointed without another QEMU call,
including when the host died immediately after QEMU. After `guest_complete`,
the image hash is mandatory and no later collection/provenance failure invokes
conversion, offline injection or guest provisioning. Required manifests are
hash-bound in a guest proof; `complete=ok` is written only after all exist.

Prepared artifacts are sealed and verified before activation. Atomic
no-clobber hardlinks publish metadata first and the base last. An interrupted
activation compares every existing destination to its prepared inventory and
finishes only matching links. Conflicting permanent bytes remain untouched.
Long-running mutators inherit the exclusive build lock: an orphaned QEMU or
guestfs process prevents a concurrent constructor after its parent exits.

Failures retain the semantic checkpoint and report the phase, stage,
fingerprint, invariant, journal/log paths and required revalidation. Old and
incompatible stages are retained; there is no automatic garbage collection.

## Legacy decisions

A schema-1 stage is inspected explicitly. Its original journal and assessment
are retained in that stage. A missing input identity or current guest manifest
proof makes it non-recoverable, even if its guest marker says `ok`. This
includes the historical successful guest with the missing npm manifest.
The builder preserves that image, records why reuse was rejected and creates
the current deterministic stage. It never retroactively invents provenance.

A schema-1 journal pointing to a guest that already carries the exact current
input identity and complete, matching schema-2 proof can migrate to the proven
post-provisioning checkpoint. Incompatible permanent provenance is explicitly
rejected and never rewritten or removed.

## Frozen Python graph

The project's direct runtime dependencies remain in its pyproject. Packaging
is explicit because the actual guest's marker/tag capture imports it.
`python-lock.json` freezes the reviewed package versions and upstream hashes;
`golden_lock.py` deterministically renders `requirements.lock` without any
index or interpreter-dependent resolution. The original version set is
retained, with packaging added. This is a frozen graph, not a claim that a
development interpreter has resolved another Python version. The former
Python-3.12 pip-compile comment is removed because it was not a target proof.

Lock changes require deliberate version/hash review and direct-dependency
validation. Rendering the same frozen graph is byte-identical on every
development interpreter. No resolver is allowed to update versions silently.
The graph's supported Python range comes from the pyproject. The guest checks
its actual interpreter against that range, selects only wheels with its own
measured tags, enforces hash membership, and installs with `--no-index`,
`--only-binary=:all:` and `--require-hashes`. Pip's offline dependency resolver,
`pip check`, and an installed METADATA audit verify active marker constraints,
Requires-Python and closure against the exact pins. An unsupported guest or
missing target wheel fails; the host interpreter is never substituted.

`python-metadata.json` records dependency declarations read from one explicit,
hash-verified reference wheel per pin, including `pyjwt[crypto]`. These
reference wheels supply static metadata only and are never injected or treated
as target-compatible artifacts. `golden_lock.py --metadata-from DIRECTORY`
recreates this snapshot without an index or resolution, rejecting missing,
duplicate or unhashed reference wheels. Before KVM the metadata audit checks
unconditional edges and propagates requested extras. Python/platform marker
conditions remain the actual target interpreter's responsibility; no host
marker value participates in that decision.

## Download cache and trust

The root-private `cache` directory is outside every stage. Only the trusted
golden constructor receives its private 9p export, mounted nosuid/nodev/noexec.
Normal task and evaluator guests never receive it. Root-owned schema-1 Kali
cache permissions are explicitly tightened while retaining valid bytes and
resumable `.part` downloads. No alternative download origin is tried by the
constructor.

Python wheels are acquired by the actual guest interpreter and stored under
their SHA-256 with their original wheel filename. Complete downloads are
hash-checked before atomic promotion. A later guest can reuse a wheel only if
its hash is in the current graph and its tags fit the actual interpreter.
Completed wheels left in acquisition scratch after a crash are validated
before promotion. Partial and corrupted bytes cannot enter the CAS. Corrupt
committed cache entries are preserved and rejected, never silently replaced.

Chromium's platform-specific version and Ed25519 trust roots come from the
hash-locked CloakBrowser wheel. No Chromium version string is maintained in
the builder or systemd unit. The single explicit package-defined download
URL supplies the archive and signed checksums. Upstream's signature verifier,
signed version binding and archive checksum are mandatory on every reuse.
Authenticated archives and signed manifests remain persistent between stages.
No custom mirror, checksum bypass, license or local binary override can alter
acquisition. Host validation reads the constants as literals from the locked
wheel without executing it and rejects invalid retained objects before KVM.
The guest repeats upstream verification independently.

Extraction validates the entire archive before writing: no traversal,
duplicates, special files or unsafe links. Accepted internal links become
ordinary files. The final `/opt/cloakbrowser/chromium/chrome` must be executable
and pass ldd with no missing dependency. Its actual executable version, binary
hash and complete file inventory are recorded. A replay checks the existing
installed inventory. The generated `/etc/gpt-trace-browser.env` supplies the
derived version and fixed binary path to the existing agent unit.

## Required manifests and provenance

Node and npm are required guest packages: dependency-pool resolution consumes
the golden's actual npm version. Their executables and versions must exist
before guest success. npm is never optional on one side of the boundary.

Provenance schema 2 includes the source/hash, image hash, semantic inputs,
original repository commit, guest agent version, authenticated browser identity,
actual Node/npm, APT suite and manifest hash, Python manifest and lock hashes,
actual target markers/tags/architecture, actual system Python binary identity,
UTC build time and provisioning method. Both image verification and template
consumers validate this schema. No missing field is replaced with a placeholder.
The firstboot has no embedded Python heredocs: the versioned helper programs
are syntax-checked directly before any boot.

## Verification

`python infra/workstation/image/build.py --validate` performs host/static checks
without a VM. `python infra/workstation/image/golden_lock.py --check` checks the
frozen graph, direct dependencies and rendered lock. Existing distributed,
broker and workstation test roots remain the maintained suites. The golden
tests use real files and Ed25519 signatures with explicit VM/network fixtures;
they cover post-provisioning reuse, guest replay, checkpoint integrity,
activation crashes, cache reuse/corruption and explicit legacy decisions.
Transport integration tests require an environment permitting local sockets.
No patch applicator or unit test starts a real VM.
