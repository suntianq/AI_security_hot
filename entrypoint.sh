#!/usr/bin/env bash
set -euo pipefail

# Wait for the database, run migrations, then dispatch on the first arg.
# Usage: entrypoint.sh [api|worker|cli ...]

cmd="${1:-api}"; shift || true

# Only ONE container should own schema migrations — running them from every
# container races on CREATE TABLE alembic_version. The worker owns it by
# default (RUN_MIGRATIONS=1); the api waits for the schema instead.
if [ "${RUN_MIGRATIONS:-0}" = "1" ]; then
  echo "[entrypoint] running migrations..."
  uv run --no-sync alembic upgrade head
  echo "[entrypoint] syncing source registry..."
  uv run --no-sync intel sync || echo "[entrypoint] sync failed (non-fatal on first boot)"
else
  echo "[entrypoint] waiting for schema (migrations owned by another container)..."
  until uv run --no-sync alembic current 2>/dev/null | grep -q '(head)'; do
    echo "[entrypoint] schema not ready yet, waiting 2s..."
    sleep 2
  done
  echo "[entrypoint] schema ready."
fi

case "$cmd" in
  api)
    exec uv run --no-sync intel serve --host 0.0.0.0 --port 8000
    ;;
  worker)
    exec uv run --no-sync intel worker
    ;;
  cli)
    exec uv run --no-sync intel "$@"
    ;;
  *)
    exec uv run --no-sync intel "$cmd" "$@"
    ;;
esac
