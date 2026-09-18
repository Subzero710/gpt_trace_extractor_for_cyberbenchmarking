FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml /app/pyproject.toml
COPY src /app/src

RUN pip install --no-cache-dir .

RUN useradd --system --uid 10001 --create-home --home-dir /home/probe probe
USER probe

ENTRYPOINT ["mcp-probe"]
