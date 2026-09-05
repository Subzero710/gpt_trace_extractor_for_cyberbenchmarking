FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY pyproject.toml /app/pyproject.toml
COPY src /app/src
COPY tests /app/tests
RUN pip install --no-cache-dir -e ".[test]"
ENTRYPOINT ["gpt-trace"]
CMD ["--help"]
