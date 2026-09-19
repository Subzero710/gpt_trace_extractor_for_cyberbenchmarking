#!/usr/bin/env bash
set -euo pipefail

display="${DISPLAY:-:99}"
profile_dir="${BROWSER_PROFILE_DIR:-/profile}"

mapfile -t identity < <(python /usr/local/bin/browser-identity values "$profile_dir")
[[ "${#identity[@]}" -eq 4 ]] || {
  echo "browser identity helper returned an invalid record" >&2
  exit 1
}
seed="${identity[0]}"
timezone="${identity[1]}"
locale="${identity[2]}"
geoip="${identity[3]}"

xdpyinfo -display "$display" >/dev/null
pgrep -x x11vnc >/dev/null
pgrep -f 'websockify.*7900.*localhost:5900' >/dev/null
curl -fsS "http://localhost:7900/vnc.html" >/dev/null
curl -fsS "http://localhost:${BROWSER_CLIPBOARD_PORT:-8765}/healthz" >/dev/null

args=(--data-urlencode "fingerprint=$seed")
[[ -z "$timezone" ]] || args+=(--data-urlencode "timezone=$timezone")
[[ -z "$locale" ]] || args+=(--data-urlencode "locale=$locale")
[[ "$geoip" != "true" ]] || args+=(--data-urlencode "geoip=true")

version_json="$(curl -fsSG "http://localhost:9222/json/version" "${args[@]}")"
VERSION_JSON="$version_json" python3 - "$seed" <<'PY'
import json
import os
import sys

seed = sys.argv[1]
data = json.loads(os.environ["VERSION_JSON"])
ws = data.get("webSocketDebuggerUrl")
needle = f"/fingerprint/{seed}/devtools/browser/"
if not isinstance(ws, str) or needle not in ws:
    raise SystemExit(f"CDP endpoint is not bound to persistent seed {seed}: {ws!r}")
PY

python3 - "$seed" <<'PY'
import json
import sys
import urllib.request

seed = sys.argv[1]
with urllib.request.urlopen("http://localhost:9222/", timeout=2) as response:
    data = json.load(response)
processes = data.get("processes")
if not isinstance(processes, dict):
    raise SystemExit("cloakserve status has no process map")
keys = set(processes)
if keys != {seed}:
    raise SystemExit(
        f"unexpected CloakBrowser identities: expected {{{seed!r}}}, got {sorted(keys)!r}"
    )
item = processes[seed]
if str(item.get("seed")) != seed:
    raise SystemExit(
        f"cloakserve process seed mismatch: expected {seed!r}, got {item.get('seed')!r}"
    )
PY

python3 - "$seed" "$profile_dir" <<'PY'
from pathlib import Path
import sys

seed = sys.argv[1]
profile_dir = sys.argv[2].rstrip("/")
roots = []
bad = []
unsafe = []

for entry in Path("/proc").iterdir():
    if not entry.name.isdigit():
        continue
    try:
        raw = (entry / "cmdline").read_bytes()
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        continue
    if not raw:
        continue
    args = [x.decode("utf-8", "replace") for x in raw.split(b"\0") if x]
    if not args or not args[0].endswith("/chrome"):
        continue
    if "--no-sandbox" in args[1:]:
        unsafe.append((entry.name, "--no-sandbox"))
    try:
        status = (entry / "status").read_text(encoding="utf-8", errors="replace")
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        status = ""
    for line in status.splitlines():
        if line.startswith("Uid:"):
            fields = line.split()
            if len(fields) >= 2 and fields[1] == "0":
                unsafe.append((entry.name, "uid=0"))
            break
    for arg in args[1:]:
        if arg == "--headless" or arg.startswith("--headless="):
            bad.append((entry.name, arg))
        if arg == "--ozone-platform=headless":
            bad.append((entry.name, arg))
    if not any(arg.startswith("--type=") for arg in args[1:]):
        roots.append((entry.name, args))

if bad:
    raise SystemExit(f"Chromium is headless: {bad!r}")
if unsafe:
    raise SystemExit(f"Chromium sandbox invariant violated: {unsafe!r}")
if len(roots) != 1:
    raise SystemExit(f"expected exactly one root Chromium process, got {len(roots)}")
pid, args = roots[0]
if f"--fingerprint={seed}" not in args:
    raise SystemExit(f"root Chromium pid {pid} is not using persistent fingerprint {seed}")
expected_profile = f"--user-data-dir={profile_dir}/{seed}"
if expected_profile not in args:
    raise SystemExit(
        f"root Chromium pid {pid} is not using expected persistent profile {expected_profile}"
    )
PY

visible_chrome=false
while IFS= read -r wid; do
  [[ -n "$wid" ]] || continue
  wm_class="$(xprop -id "$wid" WM_CLASS 2>/dev/null || true)"
  case "$wm_class" in
    *Chromium*|*chromium*|*Chrome*|*chrome*) ;;
    *) continue ;;
  esac
  geometry="$(xdotool getwindowgeometry --shell "$wid" 2>/dev/null || true)"
  width="$(printf '%s\n' "$geometry" | sed -n 's/^WIDTH=//p')"
  height="$(printf '%s\n' "$geometry" | sed -n 's/^HEIGHT=//p')"
  [[ "$width" =~ ^[0-9]+$ && "$height" =~ ^[0-9]+$ ]] || continue
  if (( width >= 200 && height >= 150 )); then
    visible_chrome=true
    break
  fi
done < <(xdotool search --onlyvisible --name '.*' 2>/dev/null || true)

[[ "$visible_chrome" == "true" ]] || {
  echo "Chromium has no real visible X11 window on $display" >&2
  exit 1
}
