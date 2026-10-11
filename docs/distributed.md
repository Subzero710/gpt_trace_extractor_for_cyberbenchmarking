# Two-host deployment through Cloudflare Tunnel and Cloudflare Access

This checkout is hardware/hostname-agnostic. `control` runs the Docker control plane,
PostgreSQL, runner, and teacher browser. `execution` runs the native root-owned
broker, KVM guests, and immutable images. The shared `config/distributed.toml` is
committed. Each host chooses its role using its private `.env`.

## Why Cloudflare

The **execution** host runs a separate Cloudflare Tunnel. Configure the published
application route (on your Cloudflare account) as:

- Public hostname: `broker.YOUR-CLOUDFLARE-DOMAIN` (an HTTPS hostname you own).
- Origin type: **UNIX**; URL: `unix:/run/workstation-broker/broker.sock`.
- Under origin HTTP parameters, enable **Disable Chunked Encoding** so the
  finite post-exit confirmation server receives fixed-length POST requests.
- Configure **Cloudflare Access** on precisely that hostname: a self-hosted
  application with an explicit **Service Auth** policy allowing only the
  intended Service Token. **No Bypass or public Allow policies.**
- Generate the Access Service Token in the dashboard and copy its **Client ID**
  and **Client Secret** into the **control** `.env`. Separately obtain the
  Tunnel token for the **execution** tunnel and put it in that host's `.env`.
- Create a **dedicated broker tunnel**, not the teacher-browser tunnel. Do not
  expose a direct TCP broker port, add local port forwarding or publish the Unix socket.

The `cloudflared` container is started by `make up` on the execution host and
reaches only the native Unix socket via a read-only bind mount. It has its own
Compose project, no published host port and no host-dependent role name.
The container runs as UID 0 because the broker runtime directory is root-only;
Docker administrators can inspect its `TUNNEL_TOKEN` environment variable.
Protect Docker access and `.env`. For stronger secret storage, integrate a
separate secret manager rather than putting tokens on a command line.

**No custom TLS server certificate, private CA, SNI name, manifest SHA-256,
or LAN address is required for broker connectivity.** External TLS is verified
against the system trust store. Access checks the Service Token before forwarding
and the native broker independently checks its role-scoped bearer tokens.
When the Access edge is absent/bypassed, the anonymous `/healthz` preflight
must fail: it expects a Cloudflare 302, 401 or 403, never 200.

## Local `.env` fields

On **control** (besides the existing `.env` secrets):

```dotenv
DIST_ROLE=control
DIST_BROKER_URL=https://broker.YOUR-CLOUDFLARE-DOMAIN
DIST_ACCESS_CLIENT_ID=THE_SERVICE_TOKEN_CLIENT_ID
DIST_ACCESS_CLIENT_SECRET=THE_SERVICE_TOKEN_CLIENT_SECRET
DIST_CONTROL_ADDRESS=192.168.1.57
```

On **execution**:

```dotenv
DIST_ROLE=execution
DIST_BROKER_TUNNEL_TOKEN=THE_TUNNEL_RUN_TOKEN
DIST_CONTROL_ADDRESS=192.168.1.57
```

`DIST_CONTROL_ADDRESS` is **optional** for normal operation. If provided on
execution it adds an explicit `/32` deny rule for the control host in each
Kali guest (private RFC1918 addresses are already denied). On control it is
required by the *strict physical acceptance* isolation check. The addresses
above are examples, not code defaults. Both `.env` files must be mode 0600:

```bash
chmod 600 .env
```

Do not fill in old `DIST_SERVER_NAME`, `DIST_EXECUTION_ADDRESS`, TLS paths,
or any SHA-256; remove those keys from previous deployments.

## One-time broker tokens

Cloudflare Access authenticates **Fossil's service**, but inside the native
broker two distinct scopes are retained. Generate one shared pair ONCE on
control using the checked-out generator (no OpenSSL):

```bash
python3 scripts/create_broker_tokens.py --output "$HOME/new-broker-credentials"
install -d -m 700 .secrets/distributed
install -m 600 "$HOME/new-broker-credentials/"workstation_broker_{admin,controller}_token .secrets/distributed/
```

Copy **the same two files** to the execution host over authenticated SSH.
For example (adjust SSH username):

```bash
scp "$HOME/new-broker-credentials/"workstation_broker_{admin,controller}_token user@EXECUTION_HOST:~/
```

On execution, from the repository root:

```bash
install -d -m 700 .secrets/distributed
install -m 600 ~/workstation_broker_admin_token ~/workstation_broker_controller_token .secrets/distributed/
rm -f ~/workstation_broker_admin_token ~/workstation_broker_controller_token
```

Do not regenerate them independently on each host: the existing code still
requires both ends to agree. The generator refuses to overwrite any existing
bundle. Rotate deliberately when there are no active benchmark attempts.

## Build and launch

On **execution** (Ubuntu with native KVM):

```bash
sudo make requirements
sudo make build
sudo make up
sudo make doctor
```

On **control**:

```bash
sudo make requirements
sudo make build
make up
make doctor
python3 scripts/distributed.py acceptance
make start_kali
make status_kali
```

`make up` on execution starts the native broker systemd unit and the dedicated
cloudflared Compose service. The Cloudflare tunnel must have a published route
and the Access Service Auth policy before control can probe it.
The teacher-browser Cloudflare Tunnel and its credentials remain independent.

`make down` on control still drains workloads and requires real authenticated
post-exit confirmation. A short-lived Unix-socket HTTP confirmation endpoint
receives only `/v1/shutdown_status` and `/v1/shutdown_complete`, with admin
bearer authentication, after the broker process is proven dead. The tunnel
continues to route this same socket during the shutdown handoff.
On execution, `make down` performs local cleanup and stops that host's
cloudflared Compose service; persistent volumes/images are retained.

## Security and limitations

- The Access hostname must be dedicated and **require Service Auth**.
- A Cloudflare Tunnel **alone** does not secure the broker. Retain Access and
  independent admin/controller tokens. If Access config is wrong, fail closed.
- Both hosts need outbound connectivity to Cloudflare; no private LAN peer
  connection is required for broker transport. This changes trust from a
  private CA/peer-IP ACL to Cloudflare Access and the scoped broker tokens.
- Access account configuration and token issuance happen in Cloudflare's
  dashboard (not via the repository). No Git patch can configure that account.
- Cloudflare adds an external dependency and may impose request size/duration
  limits; verify long-running preparation, artifact transfer and shutdown on
  the physical machines before relying on it for benchmark collection.
