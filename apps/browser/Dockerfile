FROM cloakhq/cloakbrowser:latest

USER root
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    APP_BROWSER_STATE_ROOT=/browser-state \
    APP_CONTROL_TOKEN_FILE=/run/secrets/app_control_token \
    MCP_TOOL_MANIFEST=/app/tool-manifest.json

RUN if ! getent group 10001 >/dev/null 2>&1; then groupadd --gid 10001 browserapp; fi \
    && if ! id -u browserapp >/dev/null 2>&1; then useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin browserapp; fi \
    && test "$(id -u browserapp)" = "10001" \
    && test "$(id -g browserapp)" = "10001" \
    && mkdir -p /browser-state /app \
    && chmod 0700 /browser-state

WORKDIR /app
COPY pyproject.toml /app/pyproject.toml
COPY src /app/src
COPY tests /app/tests
COPY tool-manifest.json /app/tool-manifest.json
RUN pip install --no-cache-dir -e ".[test]"

EXPOSE 8000
ENTRYPOINT ["python", "-m", "browser_mcp.server"]
