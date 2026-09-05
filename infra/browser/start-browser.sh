#!/usr/bin/env bash
set -euo pipefail
mkdir -p /profile
x11vnc -display "${DISPLAY:-:99}" -forever -shared -nopw -rfbport 5900 -quiet &
websockify --web=/usr/share/novnc 7900 localhost:5900 &
exec cloakserve --headless=false --data-dir=/profile
