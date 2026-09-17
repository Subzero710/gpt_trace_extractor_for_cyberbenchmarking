# syntax=docker/dockerfile:1
FROM cloakhq/cloakbrowser@sha256:2ed5b2d047cbdde22cde7ef1a796526c716aadaa5bccbe1db5ade49282b64a76

USER root

ENV CLOAKBROWSER_AUTO_UPDATE=false \
    CLOAKBROWSER_VERSION=146.0.7680.177.5

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

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       x11vnc novnc websockify xclip x11-utils xdotool \
    && rm -rf /var/lib/apt/lists/*

COPY start-browser.sh /usr/local/bin/start-browser
COPY browser-healthcheck.sh /usr/local/bin/browser-healthcheck
COPY clipboard_server.py /usr/local/bin/clipboard-server

RUN chmod +x \
    /usr/local/bin/start-browser \
    /usr/local/bin/browser-healthcheck \
    /usr/local/bin/clipboard-server

EXPOSE 9222 5900 7900 8765
CMD ["/usr/local/bin/start-browser"]
