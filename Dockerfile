# syntax=docker/dockerfile:1
FROM python:3.13-slim

# Pin uv so the same Git revision produces the same toolchain on amd64/arm64.
COPY --from=ghcr.io/astral-sh/uv:0.11.6 /uv /uvx /bin/

ARG INTEL_BUILD_SHA=dev

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    INTEL_BUILD_SHA=${INTEL_BUILD_SHA}

WORKDIR /app

# Install deps first for layer caching
COPY pyproject.toml uv.lock ./
RUN uv sync -v --frozen --no-install-project --no-dev

# App source
COPY README.md ./README.md
COPY src ./src
COPY migrations ./migrations
COPY alembic.ini ./alembic.ini
COPY sources ./sources
COPY config ./config
COPY entrypoint.sh ./entrypoint.sh
RUN uv sync --frozen --no-dev && chmod +x entrypoint.sh

# blob volume mount point
RUN mkdir -p /app/data/blobs

EXPOSE 8000
ENTRYPOINT ["./entrypoint.sh"]
CMD ["api"]
