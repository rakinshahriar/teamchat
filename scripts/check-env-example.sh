#!/usr/bin/env bash
set -euo pipefail

FILE=".env.example"

if [[ ! -f "$FILE" ]]; then
  echo "ERROR: $FILE not found"
  exit 1
fi

required_keys=(
  POSTGRES_USER
  POSTGRES_PASSWORD
  POSTGRES_DB
  WEB_PORT
  TOKEN_SECRET
  COOKIE_SECURE
  WEB_ORIGIN
  APP_BASE_URL
  REQUIRE_EMAIL_VERIFICATION
  EMAIL_DRY_RUN
  SMTP_FROM_EMAIL
)

missing=0
for key in "${required_keys[@]}"; do
  if ! grep -Eq "^${key}=" "$FILE"; then
    echo "ERROR: Missing required key in $FILE: $key"
    missing=1
  fi
done

# Guard against common placeholder or weak values for TOKEN_SECRET in example file.
secret_value="$(grep -E '^TOKEN_SECRET=' "$FILE" | head -n1 | cut -d '=' -f2- || true)"
if [[ -z "$secret_value" ]]; then
  echo "ERROR: TOKEN_SECRET value is empty in $FILE"
  missing=1
fi

if [[ "$missing" -ne 0 ]]; then
  exit 1
fi

echo "OK: $FILE contains required keys for local bootstrap"
