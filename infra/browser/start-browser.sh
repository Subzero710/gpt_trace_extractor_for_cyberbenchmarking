#!/usr/bin/env bash
set -euo pipefail

seed="${BROWSER_FINGERPRINT_SEED:?BROWSER_FINGERPRINT_SEED is required}"
[[ "$seed" =~ ^[1-9][0-9]*$ ]] || { echo "invalid BROWSER_FINGERPRINT_SEED" >&2; exit 64; }
geoip="${BROWSER_GEOIP:-false}"
[[ "$geoip" == "true" || "$geoip" == "false" ]] || { echo "BROWSER_GEOIP must be true or false" >&2; exit 64; }
timezone="${BROWSER_TIMEZONE:-}"
locale="${BROWSER_LOCALE:-}"
[[ -z "$timezone" || "$timezone" =~ ^[A-Za-z0-9._+/-]{1,128}$ ]] || { echo "invalid BROWSER_TIMEZONE" >&2; exit 64; }
[[ -z "$locale" || "$locale" =~ ^[A-Za-z0-9-]{1,64}$ ]] || { echo "invalid BROWSER_LOCALE" >&2; exit 64; }

profile_dir="${BROWSER_PROFILE_DIR:-/profile}"
mkdir -p "$profile_dir"
printf -v identity 'fingerprint=%s\ntimezone=%s\nlocale=%s\ngeoip=%s' "$seed" "$timezone" "$locale" "$geoip"
marker="$profile_dir/.gpt-trace-identity"
if [[ -f "$marker" ]]; then
  [[ "$(cat "$marker")" == "$identity" ]] || {
    echo "browser profile identity does not match configured fingerprint/timezone/locale" >&2
    exit 65
  }
else
  # Existing pre-marker profiles require an explicit one-time adoption so a
  # persistent oai-did/cookie profile is never silently paired with a new seed.
  if find "$profile_dir" -mindepth 1 -maxdepth 1 ! -name '.gpt-trace-identity' -print -quit | grep -q .; then
    [[ "${BROWSER_ADOPT_EXISTING_PROFILE:-false}" == "true" ]] || {
      echo "existing browser profile has no identity marker; set BROWSER_ADOPT_EXISTING_PROFILE=true once after verifying the seed" >&2
      exit 66
    }
  fi
  printf '%s' "$identity" > "$marker"
fi

python /usr/local/bin/clipboard-server --port "${BROWSER_CLIPBOARD_PORT:-8765}" &
x11vnc -display "${DISPLAY:-:99}" -forever -shared -nopw -rfbport 5900 -quiet &
websockify --web=/usr/share/novnc 7900 localhost:5900 &
exec cloakserve --headless=false --data-dir="$profile_dir"
