# Real ChatGPT Apps through Secure MCP Tunnel

The benchmark uses two local Apps:

- `Code Workspace`
- `Cloak Browser`

Their stable local MCP gateways are `workspace-gateway:8000/mcp` and `browser-gateway:8000/mcp`. ChatGPT reaches them through the official Dockerized Secure MCP Tunnel client.

## Secrets vs state

`.env` contains only the control-plane API secret:

```dotenv
CONTROL_PLANE_API_KEY=...
```

The two non-secret provisioned tunnel IDs are stored locally in ignored state:

```json
{
  "schema_version": 1,
  "tunnels": {
    "code-workspace": "tunnel_...",
    "browser": "tunnel_..."
  }
}
```

at `state/tunnels.json`.

## Registration / repair flow

Start the core first:

```bash
sudo make up
sudo make doctor
```

Then run:

```bash
sudo make tools
```

`make tools`:

1. holds real ephemeral Code Workspace and Browser backends open;
2. injects the tunnel IDs from `state/tunnels.json` into the two tunnel-client containers;
3. waits for `mcp session initialized` for both servers;
4. asks you to verify `@Code Workspace` and `@Cloak Browser` in ChatGPT;
5. cleans the temporary registration backends while leaving the tunnel clients available.

After that:

```bash
sudo make auth
sudo make run
```

The runner uses `@` mention resolution, not the `+` App picker, as the App availability/selection path.
