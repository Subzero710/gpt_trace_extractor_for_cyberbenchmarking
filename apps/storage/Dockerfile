FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY pyproject.toml /app/pyproject.toml
COPY alembic.ini /app/alembic.ini
COPY migrations /app/migrations
COPY src /app/src
COPY tests /app/tests
COPY entrypoint.sh /usr/local/bin/storage-entrypoint
RUN chmod +x /usr/local/bin/storage-entrypoint && pip install --no-cache-dir -e ".[test]"
ENTRYPOINT ["storage-entrypoint"]
