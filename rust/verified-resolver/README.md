# Rust verified resolver kernel — NOT CONNECTED TO PRODUCTION

This is a work-in-progress, standalone CPU-side kernel. The Python host must
provide authoritative PEP 440/508, wheel, target interpreter and PEP 517
metadata over the newline-delimited JSON callback protocol. The core is not
compiled, tested, deployed, wired into `superbench_pool.py`, or included in its
immutable fetch snapshot by this patch.

It is deliberately NOT an alternative or a fallback dependency resolver.
Production continues to use the existing solver until a parity-checked,
versioned, binary-identity-bound migration can be completed.

Do not use this crate on real benchmark acquisition until an audited callback
host, end-to-end parity tests and executable snapshot provenance are added.
