# Verified Rust dependency resolver (production)

This binary is **mandatory** for `make superbench-fetch ADAPTER=swe-gym-lite`.
There is no Python graph-search path and no fallback when the binary or its
attested metadata is absent. All candidate selection, constraint propagation,
backtracking, learned nogoods and conflict-state caching run natively in Rust.

The Python bridge is **not a resolver**. It remains the verified PEP 440/508
version/marker oracle, PyPI wheel-compatibility filter, immutable artifact
metadata verifier, and target-locked PEP 517 metadata executor. The Rust engine
never chooses dependency versions using host-Python assumptions. The completed
solution is independently checked against Python packaging semantics before
its artifacts are published.

No third-party Rust crates are used. Cargo must compile and run native tests
with `--locked --offline`. Fossil's historical `make requirements` provisions
`cargo` and `rustc`; `make build` compiles the binary *before* installing the
broker. The broker's immutable source snapshot includes the Rust binary, its
source, Cargo lock, and the bridge. Its SHA-256 is also part of the resolver
checkpoint identity. The binary is copied as root-owned mode 0555, executable
by the unprivileged fetch worker without network or write access.

CPU workers are derived from process affinity, cgroup-v2 ancestor CPU quotas,
and available memory with versioned resource budgets. Metadata/network I/O
concurrency remains separate. A per-closure deadline and finite search/cache
budgets are defined in `config/preparation.toml`.

A build failure, solver protocol violation, incomplete dependency closure or
incompatible release is fatal; verified CAS bytes are retained for later
reconciliation. There is no implicit cleanup or semantic downgrade.
