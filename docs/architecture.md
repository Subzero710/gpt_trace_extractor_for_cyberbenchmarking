# Architecture

Fossil hosts ChatGPT/storage/MCP services; Acer hosts the native broker and all Kali/evaluator VMs. The historical Make interface dispatches from `config/distributed.toml`. See [distributed operations](distributed.md) and [Kali Workstation runtime](workstation.md) for the trusted control plane, libvirt broker, per-attempt KVM boundary, AF_VSOCK guest agent, desktop/browser/shell coherence, identity recovery, network policy and operational lifecycle.
