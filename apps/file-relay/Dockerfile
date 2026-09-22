FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml /app/
COPY src /app/src

FROM base AS test
COPY tests /app/tests
RUN pip install --no-cache-dir ".[test]"
CMD ["python", "-m", "pytest", "-q"]

FROM base AS runtime
RUN pip install --no-cache-dir . && \
    addgroup --system --gid 65532 relay && \
    adduser --system --uid 65532 --gid 65532 --home /nonexistent --no-create-home relay
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=1s --timeout=1s --start-period=2s --retries=20 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=.8).read()"
CMD ["uvicorn", "file_relay.server:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
