# ChatGPT Plus MCP capability probe

This probe answers one narrow question with the actual account/UI:

> Can this ChatGPT Plus account discover and invoke a private MCP server through
> Secure MCP Tunnel, including a tool explicitly annotated as a write/modify tool?

It deliberately has only three tools:

- `probe_ping`: read-only connectivity.
- `probe_read_state`: read-only state inspection.
- `probe_write_state`: changes private probe state and declares
  `readOnlyHint=false`.

No OpenAI model API is used. `tunnel-client` does require a Platform runtime API
key for the tunnel control plane. The MCP server itself stays private and is
published only on `127.0.0.1`.

## 1. Start and self-test locally

```bash
sudo make mcp-probe-up
sudo make mcp-probe-check
sudo make mcp-probe-state
```

The local self-test intentionally sets the probe value to `local-smoke`.

## 2. Create a Secure MCP Tunnel

In the ChatGPT "New Plugin" dialog choose `Tunnel` and click **Create tunnel**,
or create the tunnel in Platform tunnel settings.

Create a **runtime** API key with only the tunnel permissions required by the
OpenAI tunnel documentation. Do not put that key in this repository or `.env`.

Install the current `tunnel-client` from the tunnel setup UI / official
`openai/tunnel-client` release, then verify:

```bash
tunnel-client --version
tunnel-client help quickstart
```

Export the values in your shell:

```bash
export CONTROL_PLANE_TUNNEL_ID='tunnel_...'
read -rsp 'CONTROL_PLANE_API_KEY: ' CONTROL_PLANE_API_KEY; echo
export CONTROL_PLANE_API_KEY
```

Do not run the tunnel client through `sudo`; keep the runtime key in your normal
user shell.

Validate the route:

```bash
make mcp-probe-tunnel-doctor
```

Then keep this running in its own terminal:

```bash
make mcp-probe-tunnel
```

The Make target sets:

```text
MCP_SERVER_URL=http://127.0.0.1:8099/mcp/
```

The trailing slash intentionally avoids the Starlette `/mcp -> /mcp/` redirect.

## 3. Create the personal ChatGPT plugin

In ChatGPT:

1. Open the New Plugin dialog.
2. Name: `MCP Plus Probe`.
3. Connection: `Tunnel`.
4. Select the tunnel you created.
5. Authentication: no MCP-server authentication (`None` / `No authentication`,
   wording may vary). Tunnel control-plane authentication is separate.
6. Accept the custom MCP risk acknowledgement.
7. Create/scan the plugin.

Confirm that ChatGPT discovers exactly:

- `probe_ping`
- `probe_read_state`
- `probe_write_state`

and that the write tool is shown as a modifying/non-read-only action if the UI
surfaces annotations.

## 4. Test where the plugin is usable, then test read/write

First try a fresh normal **Chat** conversation, because the benchmark runner
currently automates Chat. If the personal plugin is not available there, repeat
the same test in **Work**. Record which surface actually exposes the plugin;
this determines whether the benchmark runner can stay on Chat or must switch to
Work.

With the plugin enabled on the surface being tested, first ask:

```text
Use MCP Plus Probe to call probe_read_state. Report the exact JSON result.
```

Then ask:

```text
Use MCP Plus Probe to call probe_write_state and set value exactly to:
plus-write-probe-2026-09-18
Then call probe_read_state and report the exact JSON result.
```

If ChatGPT shows an approval prompt for the write, approve it. The purpose is to
test whether Plus permits the call, not whether approval can be bypassed.

Verify independently on the VM:

```bash
sudo make mcp-probe-state
```

Success for full write MCP means the local result contains
`"value":"plus-write-probe-2026-09-18"`. The revision is intentionally not
fixed because the local smoke test and repeated experiments can increment it.
The decisive fact is that the value changed through the ChatGPT plugin.

Interpretation:

- Discovery fails: tunnel/plugin connectivity problem; we have not tested Plus
  capability yet.
- Read works, write tool is hidden or refused by ChatGPT: Plus is effectively
  read-only for this custom MCP path.
- Write invocation reaches the server and `mcp-probe-state` changes: the native
  private-MCP architecture is viable for `Code Workspace` and `Browser`.
