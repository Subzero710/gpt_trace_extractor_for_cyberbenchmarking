#!/usr/bin/env bash
set -euo pipefail
args=(--data-urlencode "fingerprint=${BROWSER_FINGERPRINT_SEED:?}")
[[ -z "${BROWSER_TIMEZONE:-}" ]] || args+=(--data-urlencode "timezone=${BROWSER_TIMEZONE}")
[[ -z "${BROWSER_LOCALE:-}" ]] || args+=(--data-urlencode "locale=${BROWSER_LOCALE}")
[[ "${BROWSER_GEOIP:-false}" != "true" ]] || args+=(--data-urlencode "geoip=true")
curl -fsSG "http://localhost:9222/json/version" "${args[@]}" >/dev/null
curl -fsS "http://localhost:${BROWSER_CLIPBOARD_PORT:-8765}/healthz" >/dev/null
