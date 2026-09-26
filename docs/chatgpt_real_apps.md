# ChatGPT App registration

`make tools` prepares one temporary Kali workstation App, starts `mcp-tunnel-workstation`, and leaves the tunnel active after registration. Configure `APP_KALI_WORKSTATION_TUNNEL_ID` in `.env`; the gateway endpoint is `http://workstation-gateway:8000/mcp`. The trusted teacher browser continues as a separate service.
