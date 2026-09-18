# Real ChatGPT Apps over Secure MCP Tunnel

The benchmark requires two ChatGPT Apps with exact visible names:

- `Code Workspace`
- `Browser`

Each App uses its own Secure MCP Tunnel. Both tunnel-client processes run only
inside Docker Compose.

## Required `.env`

Use one runtime API key with Tunnels Read + Use and two tunnel IDs:

```dotenv
CONTROL_PLANE_API_KEY=sk-...
APP_CODE_WORKSPACE_TUNNEL_ID=tunnel_...
APP_BROWSER_TUNNEL_ID=tunnel_...
```

The existing probe tunnel may be reused for Code Workspace. A second tunnel is
required for Browser.

## Registration bootstrap

The stable gateways return no MCP backend while no benchmark attempt is active.
For one-time Plugin registration, hold real ephemeral backends open:

```bash
sudo make apps-register
```

Keep that terminal running.

In a second terminal:

```bash
sudo make app-tunnels-doctor
sudo make app-tunnels-up
sudo make app-tunnels-logs
```

The tunnel logs should show an initialized MCP session for both real apps.

Then create two personal ChatGPT Plugins:

### Code Workspace

- Name: `Code Workspace`
- Connection: `Tunnel`
- Tunnel: the value of `APP_CODE_WORKSPACE_TUNNEL_ID`
- Authentication: None / No authentication

### Browser

- Name: `Browser`
- Connection: `Tunnel`
- Tunnel: the value of `APP_BROWSER_TUNNEL_ID`
- Authentication: None / No authentication

After both Plugins show their tools, return to the `apps-register` terminal and
press Enter. The temporary registration backends are destroyed.

## Benchmark

```bash
sudo make doctor
sudo make auth
sudo make run
```

`make run` activates fresh per-attempt local backends before ChatGPT selects and
uses the Apps. `make down` removes the real tunnel containers as execution
resources but does not delete persistent volumes or tunnel records.
