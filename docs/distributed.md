# Two-host deployment through Cloudflare Tunnel

This checkout is hardware/hostname-agnostic. `control` runs the Docker control plane,
PostgreSQL, runner, and teacher browser. `execution` runs the native root-owned
broker, KVM guests, and immutable images. The shared `config/distributed.toml` is
committed. Each host chooses its role using its private `.env`. For this installation,
Fossil is `execution` (Intel VT-x, 4 vCPU, 12 GiB Kali RAM, 512 GiB sparse
QCOW2 on its second HDD); Acer is `control` (PostgreSQL, runner, KasmVNC).
The roles are NOT hard-coded to hostnames in the tracked repository.

## Cloudflare Tunnel (without Cloudflare Access)

The **execution** host runs a dedicated remotely-managed Cloudflare Tunnel.
Configure its published HTTP application route in the Cloudflare dashboard:

- Public hostname: `broker.YOUR-CLOUDFLARE-DOMAIN` (HTTPS).
- Service/origin URL: `unix:/run/workstation-broker/broker.sock`.
- Origin HTTP option **Disable Chunked Encoding**, needed for the one-time
  post-exit confirmation server's fixed-length HTTP requests.
- Do **not** publish any other public paths, host TCP ports, or the Unix socket.

`make up` on execution starts `cloudflared` in a dedicated Compose project.
`cloudflared` connects outbound to Cloudflare and forwards incoming requests
from this hostname directly to the native root-only Unix broker socket.

**Cloudflare Access is not required.** The tunnel provides routing and TLS, **not
client authorization**. The broker URL is internet-reachable. The application
must independently enforce two randomly generated strong bearer tokens:
`admin` for lifecycle and `controller` for the reduced data plane. Every
`/v1/*` operation and `/healthz` requires such a token. Do not share the
hostname or tokens, and rotate the tokens immediately if compromised.

Cloudflare's certificate is verified by the control host's normal system trust
store. There is no custom CA, mTLS client certificate, certificate fingerprint,
private network IP, or TLS server name to configure.

## Local `.env` fields

On **control** (Acer, besides existing environment settings):

```dotenv
DIST_ROLE=control
DIST_BROKER_URL=https://broker.YOUR-CLOUDFLARE-DOMAIN
```

On **execution** (Fossil):

```dotenv
DIST_ROLE=execution
DIST_BROKER_TUNNEL_TOKEN=THE_TUNNEL_RUN_TOKEN
```

**No IP address** is needed on either host, even for the acceptance check.
`DIST_BROKER_URL` is the public hostname assigned in Cloudflare; the Tunnel
Token comes from the Cloudflare dashboard. The application requires `.env`
to have owner-only permissions:

```bash
chmod 600 .env
```

Do not set the obsolete `DIST_CONTROL_ADDRESS`, `DIST_EXECUTION_ADDRESS`,
`DIST_SERVER_NAME`, `DIST_ACCESS_CLIENT_ID`, `DIST_ACCESS_CLIENT_SECRET`,
private TLS parameters, or SHA-256 values. They are no longer used.

Guest isolation continues to block all private RFC1918 ranges through
nftables. In this two-host configuration, private CIDR egress exceptions
are forbidden, so control-host access cannot accidentally be re-enabled via
a whitelist. The physical acceptance probes representative private IPv4
addresses without requiring the actual control host's address.

## Operator-managed tokens (read-only `.env`)

**The application never generates, chooses, changes, transfers or writes broker
credentials or `.env`.** Only the operator supplies their values.

Choose two **different**, high-entropy strings (32 to 512 characters, using
letters, numbers, `_` and `-`; prefer 48 or more random bytes). Enter the **same**
two values manually in `.env` on both hosts:

```dotenv
DIST_BROKER_ADMIN_TOKEN=YOUR_OWN_ADMIN_SECRET
DIST_BROKER_CONTROLLER_TOKEN=YOUR_OWN_CONTROLLER_SECRET
```

On **control**, also define the app-control secret, independently chosen:

```dotenv
APP_CONTROL_TOKEN=YOUR_OWN_APP_CONTROL_SECRET
```

Store the values in a password manager and enter them yourself. The project
never calls SSH to exchange credentials, nor generates a pair, nor changes
`.env`. The two hosts authenticate only if the corresponding broker values
match **exactly**; changing one requires manually changing the other before
resuming the broker. Do not paste actual credentials into chats or commits.

Run `chmod 600 .env` **yourself** on each host. At runtime `.env` is only read,
and missing/invalid credentials fail closed. Compose obtains the control host
secrets from `.env` as environment-backed Docker Compose secrets, exposing the
existing `/run/secrets/*` interfaces inside containers without any user-managed
secret files. The native execution broker reads broker credentials from `.env`.

The existing teacher-browser password also originates in `.env`; a runtime
file is still materialized for its legacy service interface, but `.env` is
never edited by that operation.

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
cloudflared Compose service. Configure the Cloudflare Tunnel published route before control can probe the broker.
The teacher-browser Cloudflare Tunnel and its credentials remain independent.

`make down` on control still drains workloads and requires real authenticated
post-exit confirmation. A short-lived Unix-socket HTTP confirmation endpoint
receives only `/v1/shutdown_status` and `/v1/shutdown_complete`, with admin
bearer authentication, after the broker process is proven dead. The tunnel
continues to route this same socket during the shutdown handoff.
On execution, `make down` performs local cleanup and stops that host's
cloudflared Compose service; persistent volumes/images are retained.

## Security and limitations

- A Cloudflare Tunnel **alone does not authenticate clients**. This setup
  uses the broker's independent admin/controller bearer credentials instead
  of Cloudflare Access. Anyone on the internet can reach the public URL,
  but unauthenticated calls must be denied. Use the dedicated broker hostname.
- Both hosts need outbound access to Cloudflare; no LAN peer IP is required.
- `make down` relies on a short authenticated confirmation handoff via the same
  Unix socket; do not remove the Cloudflare route mid-shutdown.
- Cloudflare may impose request-size/duration limits. Test actual long-running
  jobs, artifact transfers and cleanup on the physical machines before relying
  on this route for benchmark collection.
