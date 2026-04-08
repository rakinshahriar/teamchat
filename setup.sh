#!/usr/bin/env bash
set -euo pipefail

ENV_FILE=".env"
EXAMPLE_FILE=".env.example"

if [[ ! -f "$EXAMPLE_FILE" ]]; then
  echo "Error: $EXAMPLE_FILE not found. Run this from the repository root."
  exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
  cp "$EXAMPLE_FILE" "$ENV_FILE"
  echo "Created .env from .env.example"
else
  echo ".env already exists. Keeping existing values."
fi

generate_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    # Fallback when openssl is unavailable.
    date +%s | shasum | awk '{print $1 $1}'
  fi
}

set_env_value() {
  local key="$1"
  local value="$2"

  if grep -Eq "^${key}=" "$ENV_FILE"; then
    awk -v k="$key" -v v="$value" 'BEGIN{updated=0} $0 ~ "^"k"=" {print k"="v; updated=1; next} {print} END{if(updated==0) print k"="v}' "$ENV_FILE" > "$ENV_FILE.tmp"
    mv "$ENV_FILE.tmp" "$ENV_FILE"
  else
    printf "%s=%s\n" "$key" "$value" >> "$ENV_FILE"
  fi
}

current_secret="$(grep -E '^TOKEN_SECRET=' "$ENV_FILE" | head -n1 | cut -d '=' -f2- || true)"
if [[ -z "$current_secret" || "$current_secret" == "replace-with-a-random-secret-at-least-32-characters-long" || ${#current_secret} -lt 32 ]]; then
  new_secret="$(generate_secret)"
  set_env_value "TOKEN_SECRET" "$new_secret"
  echo "Set TOKEN_SECRET in .env"
fi

echo "\nLocal setup complete."
echo "Next steps:"
echo "  1) docker compose up -d --build"
echo "  2) docker compose ps"
echo "  3) Open http://localhost:3000"
