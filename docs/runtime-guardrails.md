# Runtime boundaries

The runner can access the storage API, the stable workstation gateway, and the narrow broker Unix socket. Only the host broker uses libvirt, qemu-img and nftables. The Kali guest has neither control-plane secrets nor a Docker or libvirt socket. Its dedicated libvirt NAT network permits public IPv4 egress while nftables blocks private/control networks and host input except DNS/DHCP. All model-facing shell, browser and desktop actions happen within the per-attempt KVM guest. See [workstation.md](workstation.md).
