# syntax=docker/dockerfile:1
FROM cloakhq/cloakbrowser@sha256:2ed5b2d047cbdde22cde7ef1a796526c716aadaa5bccbe1db5ade49282b64a76

USER root

ARG TARGETARCH
ARG KASMVNC_VERSION=1.5.0
ENV CLOAKBROWSER_AUTO_UPDATE=false \
    CLOAKBROWSER_VERSION=146.0.7680.177.5 \
    KASMVNC_VERSION=${KASMVNC_VERSION}

RUN <<PY
#!/usr/bin/env python3
from pathlib import Path

target = Path("/usr/local/bin/cloakserve")
source = target.read_text(encoding="utf-8")

old = '''        elif arg == "--headless=false" or arg == "--headless=False":
            config["headless"] = False
            passthrough.append(arg)
'''

new = '''        elif arg == "--headless=false" or arg == "--headless=False":
            config["headless"] = False
'''

if source.count(old) != 1:
    raise SystemExit(
        "unexpected cloakserve source in pinned base image; refusing to modify it"
    )

patched = source.replace(old, new, 1)

if old in patched or patched.count(new) != 1:
    raise SystemExit("cloakserve headed-mode transformation failed")

compile(patched, str(target), "exec")
target.write_text(patched, encoding="utf-8")
target.chmod(0o755)
PY

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      ca-certificates curl openssl xclip x11-utils x11-xserver-utils xdotool openbox gosu util-linux python3-aiohttp; \
    case "$TARGETARCH" in \
      amd64) kasm_arch=amd64; kasm_sha=80b241de7dfe53bba2b7e1cc5ac8c5246d72271efa16be2d4f76607f30fab1c4 ;; \
      arm64) kasm_arch=arm64; kasm_sha=fbb11589958a2acccd2d67f67944be79ac1e8e3a1d6172c0e6db6dc59e55a919 ;; \
      *) echo "unsupported KasmVNC architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    kasm_deb="/tmp/kasmvncserver_trixie_${KASMVNC_VERSION}_${kasm_arch}.deb"; \
    curl -fL --retry 4 --retry-delay 2 \
      "https://github.com/kasmtech/KasmVNC/releases/download/v${KASMVNC_VERSION}/kasmvncserver_trixie_${KASMVNC_VERSION}_${kasm_arch}.deb" \
      -o "$kasm_deb"; \
    printf '%s  %s\n' "$kasm_sha" "$kasm_deb" | sha256sum -c -; \
    apt-get install -y --no-install-recommends "$kasm_deb"; \
    rm -f "$kasm_deb"; \
    rm -rf /var/lib/apt/lists/*; \
    command -v Xvnc >/dev/null; \
    command -v kasmvncpasswd >/dev/null; \
    /usr/bin/python3 -c 'import aiohttp; assert aiohttp.__version__'

RUN command -v unshare >/dev/null

COPY browser_identity.py /usr/local/bin/browser-identity
COPY start-browser.sh /usr/local/bin/start-browser
COPY browser-healthcheck.sh /usr/local/bin/browser-healthcheck
COPY clipboard_server.py /usr/local/bin/clipboard-server
COPY kasm_healthcheck.py /usr/local/bin/kasm-healthcheck
COPY kasm_auth_proxy.py /usr/local/bin/kasm-auth-proxy
COPY auth_proxy_healthcheck.py /usr/local/bin/auth-proxy-healthcheck
COPY kasmvnc.yaml /etc/kasmvnc/kasmvnc.yaml

RUN chmod +x \
    /usr/local/bin/browser-identity \
    /usr/local/bin/start-browser \
    /usr/local/bin/browser-healthcheck \
    /usr/local/bin/clipboard-server \
    /usr/local/bin/kasm-healthcheck \
    /usr/local/bin/kasm-auth-proxy \
    /usr/local/bin/auth-proxy-healthcheck

RUN python - <<'PY'
from pathlib import Path
import cloakbrowser.config as cloak_config

target = Path(cloak_config.__file__)
source = target.read_text(encoding="utf-8")
old = "    base = [\n        \"--no-sandbox\",\n        f\"--fingerprint={seed}\",\n    ]\n"
new = "    base = [\n        f\"--fingerprint={seed}\",\n    ]\n"
if source.count(old) != 1:
    raise SystemExit(
        f"unexpected CloakBrowser config at {target}; refusing an unsafe/ambiguous patch"
    )
patched = source.replace(old, new, 1)
compile(patched, str(target), "exec")
target.write_text(patched, encoding="utf-8")
PY

RUN python - <<'PY_INNER'
from pathlib import Path

target = Path("/usr/local/bin/cloakserve")
source = target.read_text(encoding="utf-8")

needle = "            process = subprocess.Popen(\n                full_args,\n"
replacement = """            # GPT_TRACE_STRIP_NO_SANDBOX_FINAL_ARGV
            full_args = [
                arg
                for arg in full_args
                if arg.split("=", 1)[0] != "--no-sandbox"
            ]
            if any(
                arg.split("=", 1)[0] == "--no-sandbox"
                for arg in full_args
            ):
                raise RuntimeError("--no-sandbox survived final argv sanitization")

            process = subprocess.Popen(
                full_args,
"""

if source.count(needle) != 1:
    raise SystemExit(
        "unexpected cloakserve source in pinned image: "
        f"expected exactly one Popen(full_args) site, found {source.count(needle)}"
    )

patched = source.replace(needle, replacement, 1)
compile(patched, str(target), "exec")
if "GPT_TRACE_STRIP_NO_SANDBOX_FINAL_ARGV" not in patched:
    raise SystemExit("cloakserve final argv guard was not installed")

target.write_text(patched, encoding="utf-8")
target.chmod(0o755)
PY_INNER

RUN set -eux; \
    groupadd --gid 10001 browser; \
    useradd --uid 10001 --gid 10001 --create-home --home-dir /home/browser --shell /bin/bash browser; \
    mkdir -p /opt/cloakbrowser-cache /home/browser/.vnc; \
    cp -a /root/.cloakbrowser/. /opt/cloakbrowser-cache/; \
    chown -R browser:browser /opt/cloakbrowser-cache /home/browser; \
    chrome_bin="$(find /opt/cloakbrowser-cache -type f -name chrome -perm -0100 -print -quit)"; \
    test -n "$chrome_bin"; \
    python -c 'from cloakbrowser.config import get_default_stealth_args; assert "--no-sandbox" not in get_default_stealth_args()'; \
    test ! -e /usr/bin/x11vnc; \
    test ! -e /usr/bin/websockify

ENV CLOAKBROWSER_CACHE_DIR=/opt/cloakbrowser-cache \
    HOME=/home/browser \
    XDG_CACHE_HOME=/home/browser/.cache \
    XDG_CONFIG_HOME=/home/browser/.config \
    GPT_TRACE_SANDBOXED_CLOAKBROWSER=1 \
    BROWSER_KASM_USERNAME=kasm_user \
    BROWSER_KASM_PASSWORD_FILE=/run/secrets/teacher_browser_password

EXPOSE 9222 6901 8765
ENTRYPOINT ["/usr/local/bin/start-browser"]
CMD []
