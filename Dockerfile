# syntax=docker/dockerfile:1
FROM python:3.13-slim

# uv for fast, reproducible installs
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 
    
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
COPY entrypoint.sh ./entrypoint.sh
RUN uv sync --frozen --no-dev && chmod +x entrypoint.sh

# blob volume mount point
RUN mkdir -p /app/data/blobs

EXPOSE 8000
ENTRYPOINT ["./entrypoint.sh"]
CMD ["api"]
