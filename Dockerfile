# syntax=docker/dockerfile:1
FROM python:3.14-slim-trixie AS builder

COPY --from=ghcr.io/astral-sh/uv:0.13.3 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-install-project

COPY README.md ./
COPY src/ ./src/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable

FROM python:3.14-slim-trixie AS runtime
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    KEYBOX_FILE=/data/keybox.xml
WORKDIR /app

RUN groupadd --gid 10001 keyboxstore \
    && useradd --uid 10001 --gid keyboxstore --no-create-home keyboxstore \
    && mkdir /data \
    && chown keyboxstore:keyboxstore /data \
    && chmod 700 /data
COPY --from=builder /app/.venv /app/.venv

USER keyboxstore
EXPOSE 8000
CMD ["uvicorn", "keyboxstore.app:app", "--host", "0.0.0.0", "--port", "8000"]
