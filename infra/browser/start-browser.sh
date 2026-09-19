#!/usr/bin/env bash
set -euo pipefail

display="${DISPLAY:-:99}"
profile_dir="${BROWSER_PROFILE_DIR:-/profile}"
mkdir -p "$profile_dir"

if [[ "$(id -u)" -eq 0 ]]; then
  chown -R browser:browser "$profile_dir"
  install -d -m 0700 -o browser -g browser \
    /home/browser/.cache /home/browser/.config
  chown -R browser:browser /home/browser
  x11_ready=false
  for _ in $(seq 1 100); do
    if xdpyinfo -display "$display" >/dev/null 2>&1; then
      x11_ready=true
      break
    fi
    sleep 0.1
  done
  [[ "$x11_ready" == "true" ]] || {
    echo "X11 display $display did not become ready before privilege drop" >&2
    exit 67
  }
  DISPLAY="$display" xhost +SI:localuser:browser >/dev/null
  exec gosu browser "$0" "$@"
fi

[[ "$(id -u)" -eq 10001 ]] || {
  echo "start-browser must run as root for setup or uid 10001 after privilege drop" >&2
  exit 68
}

if ! unshare --user --map-root-user true >/dev/null 2>&1; then
  echo "Chromium user-namespace sandbox unavailable inside browser container" >&2
  echo "Check browser seccomp profile and host user-namespace policy" >&2
  exit 69
fi

python - <<'PY'
from cloakbrowser.config import get_default_stealth_args
args = get_default_stealth_args()
if "--no-sandbox" in args:
    raise SystemExit("CloakBrowser still injects --no-sandbox; refusing to launch")
PY

# The persistent profile owns the teacher-browser identity. Existing legacy
# markers are canonicalized in-place (not replaced with config from .env).
python /usr/local/bin/browser-identity ensure "$profile_dir"

x11_ready=false
for _ in $(seq 1 100); do
  if xdpyinfo -display "$display" >/dev/null 2>&1; then
    x11_ready=true
    break
  fi
  sleep 0.1
done
[[ "$x11_ready" == "true" ]] || {
  echo "X11 display $display did not become ready" >&2
  exit 67
}

python /usr/local/bin/clipboard-server --port "${BROWSER_CLIPBOARD_PORT:-8765}" &
x11vnc -display "$display" -forever -shared -nopw -noshm -rfbport 5900 -quiet &
websockify --web=/usr/share/novnc 7900 localhost:5900 &

exec cloakserve --headless=false --data-dir="$profile_dir"
