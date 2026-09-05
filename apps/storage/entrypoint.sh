#!/usr/bin/env sh
set -eu
alembic upgrade head
exec uvicorn gpt_trace_storage.main:app --host "${STORAGE_HOST:-0.0.0.0}" --port "${STORAGE_PORT:-8080}" --loop asyncio
