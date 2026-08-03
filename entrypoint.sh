#!/usr/bin/env bash
set -euo pipefail

# Migrations are an explicit one-shot command. Long-running services only start
# after the database matches this image, preventing API/worker version skew.
# Usage: entrypoint.sh [migrate|api|worker|cli ...]

cmd="${1:-api}"; shift || true

wait_for_schema() {
  local timeout="${SCHEMA_WAIT_SECONDS:-120}"
  local deadline=$((SECONDS + timeout))
  echo "[entrypoint] verifying schema (timeout=${timeout}s)..."
  until uv run --no-sync alembic current 2>/dev/null | grep -q '(head)'; do
    if (( SECONDS >= deadline )); then
      echo "[entrypoint] schema is not at this image's Alembic head" >&2
      exit 1
    fi
    sleep 2
  done
  echo "[entrypoint] schema ready."
}

case "$cmd" in
  migrate)
    echo "[entrypoint] running migrations..."
    uv run --no-sync alembic upgrade head
    echo "[entrypoint] syncing source registry..."
    uv run --no-sync intel sync
    ;;
  api)
    wait_for_schema
    exec uv run --no-sync intel serve --host 0.0.0.0 --port 8000
    ;;
  worker)
    wait_for_schema
    exec uv run --no-sync intel worker
    ;;
  cli)
    exec uv run --no-sync intel "$@"
    ;;
  *)
    exec uv run --no-sync intel "$cmd" "$@"
    ;;
esac
