# TeamChat

TeamChat is a small full-stack chat app.

It includes:
- A web frontend
- A Python API
- A PostgreSQL database

Everything runs with Docker Compose.

## What You Can Do
- Sign in with email and password
- Sign in with Google (working)
- GitHub SSO (in progress, not fully implemented)
- Company OIDC SSO (in progress, not fully implemented)
- Verify email and reset password
- Chat with accepted connections
- Use groups, including company groups for SSO users
- Use the admin page (rank-based controls)

## Quick Start (Local)
1. Run the bootstrap script from the repo root.

```bash
chmod +x setup.sh
./setup.sh
```

What it does:
- Creates `.env` from `.env.example` if missing.
- Ensures `TOKEN_SECRET` exists and is at least 32 characters.
- Keeps existing `.env` values if you already customized them.

2. Start the stack.

```bash
docker compose up -d --build
```

3. Check health.

```bash
docker compose ps
curl -fsS http://127.0.0.1:8000/health
curl -fsS http://127.0.0.1:3000/health
```

4. Open the app.

```text
http://localhost:3000
```

## Manual Env Setup (If You Prefer)
If you do not want to use `setup.sh`:

```bash
cp .env.example .env
```

Then set at least these values:
- `TOKEN_SECRET` (required, minimum 32 characters)
- `WEB_ORIGIN` (default local: `http://localhost:3000`)
- `APP_BASE_URL` (default local: `http://localhost:3000`)
- `COOKIE_SECURE` (`false` for local HTTP, `true` for HTTPS)

For local development defaults in this repo:
- `REQUIRE_EMAIL_VERIFICATION=false`
- `EMAIL_DRY_RUN=true`

These defaults avoid SMTP-related setup failures on first run.

## App URLs
- Web app: /
- Admin: /admin.html
- Verify email: /verify.html
- Reset password: /reset-password.html

## OIDC Company SSO Example
Set OIDC_PROVIDERS_JSON in .env as JSON keyed by company domain.

```json
{
  "acme.com": {
    "issuer": "https://login.microsoftonline.com/<tenant-id>/v2.0",
    "client_id": "your-client-id",
    "client_secret": "your-client-secret",
    "scope": "openid profile email"
  }
}
```

Behavior:
- Users from the same configured company key can be auto-grouped into a company group.
- Group members can leave groups from the UI.

## DietPi Deploy
If you use the helper script used in this repo:

```bash
$HOME/bin/deploy2pi "$PWD" "/opt/stacks/pi-remote-dev"
```

Deployment notes:
- This repo includes `.deployignore` to avoid syncing local secrets/artifacts (for deploy tools that support exclude files).
- Keep the remote `.env` managed on the Pi host.

Then verify remotely:

```bash
ssh -o BatchMode=yes dietpi 'cd /opt/stacks/pi-remote-dev && docker compose ps'
```

Optional cleanup before deploy (safe for unused Docker artifacts):

```bash
ssh -o BatchMode=yes dietpi 'docker image prune -af && docker builder prune -af'
```

## Security Notes
- Never commit .env
- .env.example is safe to commit
- Set COOKIE_SECURE=true when running behind HTTPS

## Common Setup Errors
- `TOKEN_SECRET must be set and at least 32 characters`:
  - Run `./setup.sh` again or set `TOKEN_SECRET` manually in `.env`.
- `COOKIE_SECURE must be true for non-local WEB_ORIGIN`:
  - For local use `WEB_ORIGIN=http://localhost:3000` and `COOKIE_SECURE=false`.
  - For deployed HTTPS use `COOKIE_SECURE=true`.

## License
This project is licensed under the MIT License.
See LICENSE for details.
