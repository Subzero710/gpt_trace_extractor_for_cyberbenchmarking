FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY apps/kali-workstation/pyproject.toml /app/pyproject.toml
COPY apps/kali-workstation/src /app/src
COPY shared /app/shared
RUN pip install --no-cache-dir /app/shared
COPY apps/kali-workstation/tool-manifest.json /app/tool-manifest.json
COPY apps/kali-workstation/tests /app/tests
RUN pip install --no-cache-dir -e ".[test]"
ENTRYPOINT ["python", "-m", "kali_workstation.server"]
