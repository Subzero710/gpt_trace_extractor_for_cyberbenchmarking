FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml /app/pyproject.toml
COPY src /app/src
COPY tool-manifest.json /app/tool-manifest.json
RUN pip install --no-cache-dir -e .
ENTRYPOINT ["python", "-m", "kali_workstation.server"]
