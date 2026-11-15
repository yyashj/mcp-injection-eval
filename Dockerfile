FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt pytest

COPY src ./src
COPY scenarios ./scenarios
COPY tests ./tests
COPY pyproject.toml README.md ./

# Run as an unprivileged user. The MCP tools are fully mocked, but defence in depth.
RUN useradd --create-home --uid 10001 evaluser && mkdir -p /app/results && chown -R evaluser /app
USER evaluser

ENV PYTHONPATH=/app/src
CMD ["python", "-m", "mcpinj.runner", "--agents", "naive,guarded,llm", "--out", "/app/results"]
