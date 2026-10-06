#!/usr/bin/env bash
set -euo pipefail

display="${DISPLAY:-:99}"
profile_dir="${BROWSER_PROFILE_DIR:-/profile}"
kasm_user="${BROWSER_KASM_USERNAME:-kasm_user}"
kasm_password_file="${BROWSER_KASM_PASSWORD_FILE:-/run/secrets/teacher_browser_password}"
dri_node="${BROWSER_DRI_NODE:-/dev/dri/renderD128}"
gpu_required="${BROWSER_GPU_REQUIRED:-0}"

mkdir -p "$profile_dir"

if [[ "$(id -u)" -eq 0 ]]; then
  chown -R browser:browser "$profile_dir"
  install -d -m 0700 -o browser -g browser \
    /home/browser/.cache /home/browser/.config /home/browser/.vnc
  # Xorg requires the shared X11 socket directory to be root-owned even though
  # Xvnc itself runs as the unprivileged browser uid. Clean only our display.
  install -d -m 1777 -o root -g root /tmp/.X11-unix
  rm -f /tmp/.X99-lock /tmp/.X11-unix/X99

  # GPT_TRACE_TEACHER_BROWSER_GPU_FIX: preserve render-node access after dropping root.
  if [[ "$gpu_required" == "1" ]]; then
    [[ -c "$dri_node" ]] || {
      echo "GPU render node missing in container: $dri_node" >&2
      exit 72
    }

    dri_gid="$(stat -c '%g' "$dri_node")"

    render_group="$(
      awk -F: -v gid="$dri_gid"         '$3 == gid { print $1; exit }' /etc/group
    )"

    if [[ -z "$render_group" ]]; then
      render_group="gpurender${dri_gid}"
      groupadd --gid "$dri_gid" "$render_group"
    fi

    usermod -aG "$render_group" browser
  fi

  chown -R browser:browser /home/browser
  exec gosu browser "$0" "$@"
fi

[[ "$(id -u)" -eq 10001 ]] || {
  echo "start-browser must run as root for setup or uid 10001 after privilege drop" >&2
  exit 68
}

if [[ "$gpu_required" == "1" ]]; then
  [[ -c "$dri_node" ]] || {
    echo "GPU render node missing after privilege drop: $dri_node" >&2
    exit 72
  }

  [[ -r "$dri_node" && -w "$dri_node" ]] || {
    echo "browser cannot access GPU render node: $dri_node" >&2
    id >&2
    ls -ln "$dri_node" >&2 || true
    exit 72
  }
fi

[[ -r "$kasm_password_file" ]] || {
  echo "teacher browser Kasm password secret is unreadable: $kasm_password_file" >&2
  exit 66
}

kasm_password="$(tr -d '\r\n' < "$kasm_password_file")"
(( ${#kasm_password} >= 12 && ${#kasm_password} <= 128 )) || {
  echo "teacher browser Kasm password must be 12..128 characters" >&2
  exit 66
}
[[ -n "$kasm_user" ]] || {
  echo "BROWSER_KASM_USERNAME must not be empty" >&2
  exit 66
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

python /usr/local/bin/browser-identity ensure "$profile_dir"

install -d -m 0700 /home/browser/.vnc
rm -f /home/browser/.kasmpasswd
printf '%s\n%s\n' "$kasm_password" "$kasm_password" \
  | kasmvncpasswd -u "$kasm_user" -wo >/dev/null
chmod 0600 /home/browser/.kasmpasswd
unset kasm_password

if [[ ! -s /home/browser/.vnc/self.pem ]]; then
  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /home/browser/.vnc/self.pem \
    -out /home/browser/.vnc/self.pem \
    -subj "/C=XX/ST=None/L=None/O=GPTTrace/OU=TeacherBrowser/CN=teacher-browser" \
    >/dev/null 2>&1
  chmod 0600 /home/browser/.vnc/self.pem
fi

# The pinned CloakBrowser base normally starts Xvfb in its inherited entrypoint.
# This image overrides that entrypoint: KasmVNC/Xvnc is the only X server.

children=()
cleanup() {
  local pid
  for pid in "${children[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  for pid in "${children[@]:-}"; do
    wait "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM HUP

cat > /home/browser/.vnc/xstartup <<'EOF'
#!/usr/bin/env sh
set -eu
exec openbox
EOF
chmod 0755 /home/browser/.vnc/xstartup

# With -fg, vncserver stays attached to xstartup. Keeping Openbox as the
# foreground xstartup process gives the container one supervised Kasm session:
# when Openbox exits, vncserver tears down Xvnc and exits as well.
vncserver "$display" -fg -xstartup /home/browser/.vnc/xstartup > /home/browser/.vnc/kasmvnc.log 2>&1 &
kasm_pid=$!
children+=("$kasm_pid")

x11_ready=false
for _ in $(seq 1 200); do
  if ! kill -0 "$kasm_pid" 2>/dev/null; then
    tail -n 200 /home/browser/.vnc/kasmvnc.log >&2 || true
    echo "KasmVNC exited before X11 became ready" >&2
    exit 67
  fi
  if xdpyinfo -display "$display" >/dev/null 2>&1; then
    x11_ready=true
    break
  fi
  sleep 0.1
done
[[ "$x11_ready" == "true" ]] || {
  tail -n 200 /home/browser/.vnc/kasmvnc.log >&2 || true
  echo "KasmVNC X11 display $display did not become ready" >&2
  exit 67
}

kasm_ready=false
for _ in $(seq 1 100); do
  if python /usr/local/bin/kasm-healthcheck --require-authwall >/dev/null 2>&1; then
    kasm_ready=true
    break
  fi
  if ! kill -0 "$kasm_pid" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
[[ "$kasm_ready" == "true" ]] || {
  tail -n 200 /home/browser/.vnc/kasmvnc.log >&2 || true
  echo "KasmVNC HTTPS/authwall did not become ready" >&2
  exit 70
}

/usr/local/bin/kasm-auth-proxy \
  --upstream https://127.0.0.1:6902 \
  --password-file "$kasm_password_file" \
  --username "$kasm_user" \
  --cert /home/browser/.vnc/self.pem &
auth_proxy_pid=$!
children+=("$auth_proxy_pid")

auth_proxy_ready=false
for _ in $(seq 1 100); do
  if /usr/local/bin/auth-proxy-healthcheck >/dev/null 2>&1; then
    auth_proxy_ready=true
    break
  fi
  if ! kill -0 "$auth_proxy_pid" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
[[ "$auth_proxy_ready" == "true" ]] || {
  echo "teacher browser HTML auth proxy did not become ready" >&2
  exit 71
}

python /usr/local/bin/clipboard-server --port "${BROWSER_CLIPBOARD_PORT:-8765}" &
clipboard_pid=$!
children+=("$clipboard_pid")

cloakserve --headless=false --data-dir="$profile_dir" &
cloak_pid=$!
children+=("$cloak_pid")

set +e
wait -n "$kasm_pid" "$auth_proxy_pid" "$clipboard_pid" "$cloak_pid"
status=$?
set -e

echo "teacher-browser critical process exited; restarting container" >&2
exit "$status"
