FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY apps/runner/pyproject.toml /app/pyproject.toml
COPY apps/runner/src /app/src
COPY shared /app/shared
RUN pip install --no-cache-dir /app/shared
COPY apps/runner/tests /app/tests
COPY scripts/distributed_acceptance.py /app/tools/distributed_acceptance.py
COPY scripts/teacher_gpu_doctor.py /app/tools/teacher_gpu_doctor.py
COPY scripts/build_local_templates.py /repo/scripts/build_local_templates.py
COPY scripts/distributed.py /repo/scripts/distributed.py
COPY config/distributed.toml /repo/config/distributed.toml
RUN pip install --no-cache-dir -e ".[test]"
ENTRYPOINT ["gpt-trace"]
CMD ["--help"]
