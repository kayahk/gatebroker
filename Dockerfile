# syntax=docker/dockerfile:1
FROM python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv@sha256:df4cae8f3a96d175e2e5f992e597550000edbe78fdc2594d5cd8de1a217f504c /uv /uvx /bin/

COPY pyproject.toml uv.lock README.md LICENSE NOTICE ./
COPY src ./src
RUN uv sync --locked --no-dev --no-editable \
    && addgroup --system broker \
    && adduser --system --ingroup broker --home /app --no-create-home broker \
    && chown broker:broker /app

ENV PATH="/app/.venv/bin:$PATH"

USER broker

EXPOSE 8080
CMD ["python", "-m", "gatebroker.runtime"]
