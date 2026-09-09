FROM rust:slim-bookworm AS rust-toolchain

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    CODE_WORKSPACE_ROOT=/workspace \
    CODE_WORKSPACE_STATE_ROOT=/state \
    APP_CONTROL_TOKEN_FILE=/run/secrets/app_control_token \
    MCP_TOOL_MANIFEST=/app/tool-manifest.json \
    CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    PATH=/usr/local/cargo/bin:${PATH}

COPY --from=rust-toolchain /usr/local/cargo /usr/local/cargo
COPY --from=rust-toolchain /usr/local/rustup /usr/local/rustup

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       bash binutils build-essential ca-certificates git jq procps ripgrep unzip zip \
    && rm -rf /var/lib/apt/lists/* \
    && rustc --version \
    && cargo --version \
    && gcc --version \
    && as --version \
    && if ! getent group 10002 >/dev/null 2>&1; then groupadd --gid 10002 workspace; fi \
    && if ! id -u workspace >/dev/null 2>&1; then useradd --uid 10002 --gid 10002 --no-create-home --shell /usr/sbin/nologin workspace; fi \
    && test "$(id -u workspace)" = "10002" \
    && test "$(id -g workspace)" = "10002" \
    && mkdir -p /workspace /state \
    && chmod 0770 /workspace \
    && chmod 0700 /state

WORKDIR /app
COPY pyproject.toml /app/pyproject.toml
COPY src /app/src
COPY tests /app/tests
COPY tool-manifest.json /app/tool-manifest.json
RUN pip install --no-cache-dir -e ".[test]"

EXPOSE 8000
ENTRYPOINT ["python", "-m", "code_workspace.server"]
