# ChatGPT Plus MCP capability probe

This probe determines whether this ChatGPT Plus account can discover and invoke
a private MCP server through Secure MCP Tunnel, including a tool explicitly
annotated as write/modify.

Everything runtime-related is containerized. Nothing needs to be installed on
the host other than Docker / Docker Compose.

The probe exposes exactly three tools:

- `probe_ping`: read-only connectivity.
- `probe_read_state`: read-only state inspection.
- `probe_write_state`: changes private probe state and declares
  `readOnlyHint=false`.

## Configuration

Put only the tunnel identity/runtime key in the repository `.env`:

```dotenv
CONTROL_PLANE_TUNNEL_ID=tunnel_...
CONTROL_PLANE_API_KEY=sk-...
```

Do not commit `.env` and do not paste the runtime key into chat.

`MCP_SERVER_URL` is intentionally not taken from `.env`. Inside Compose the
official OpenAI tunnel-client container talks to:

```text
http://mcp-probe:8000/mcp/
```

over the dedicated `mcp_probe_host` Docker bridge.

## Local probe

```bash
sudo make mcp-probe-up
sudo make mcp-probe-check
sudo make mcp-probe-state
```

Expected tool set:

```text
probe_ping
probe_read_state
probe_write_state
```

## Tunnel doctor

The official image is pinned in Compose:

```text
ghcr.io/openai/tunnel-client:v0.0.14
```

No host `tunnel-client` binary is used.

Run:

```bash
sudo make mcp-probe-tunnel-doctor
```

This executes `tunnel-client doctor --explain` in an ephemeral container.

## Start tunnel

```bash
sudo make mcp-probe-tunnel
```

Inspect live logs with:

```bash
sudo make mcp-probe-tunnel-logs
```

Stop only the tunnel container with:

```bash
sudo make mcp-probe-tunnel-down
```

## ChatGPT plugin

Create/finish the personal plugin:

- Name: `MCP Plus Probe`
- Connection: `Tunnel`
- Tunnel: the configured tunnel ID
- MCP authentication: none

Confirm ChatGPT discovers exactly the three probe tools.

First test a normal Chat conversation because the benchmark runner currently
automates Chat. If the personal plugin is unavailable there, repeat in Work and
record which surface exposes it.

Read test:

```text
Use MCP Plus Probe to call probe_read_state. Report the exact JSON result.
```

Write test:

```text
Use MCP Plus Probe to call probe_write_state and set value exactly to:
plus-write-probe-2026-09-18
Then call probe_read_state and report the exact JSON result.
```

If ChatGPT displays an approval prompt for the write, approve it.

Verify independently:

```bash
sudo make mcp-probe-state
```

Full write support is proven when the local state contains:

```text
"value":"plus-write-probe-2026-09-18"
```

The revision number is not fixed because repeated experiments can increment it.
