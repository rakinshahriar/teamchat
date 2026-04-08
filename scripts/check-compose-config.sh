#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f ".env.example" ]]; then
  echo "ERROR: .env.example not found"
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker is not installed or not on PATH"
  exit 1
fi

# Use example values to ensure docker-compose.yml can be fully resolved in CI.
cp .env.example .env.ci
trap 'rm -f .env.ci' EXIT

docker compose --env-file .env.ci config >/dev/null

echo "OK: docker compose config resolved successfully using .env.example"
