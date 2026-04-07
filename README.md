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
1. Create your env file.

```bash
cp .env.example .env
```

2. Open .env and fill the required values.

Required for basic login flow:
- DATABASE_URL (or use the default from docker-compose)
- WEB_ORIGIN
- APP_BASE_URL
- PUBLIC_API_BASE_URL
- COOKIE_SECURE

Required for email verification and reset:
- SMTP_HOST
- SMTP_PORT
- SMTP_USERNAME
- SMTP_PASSWORD
- SMTP_FROM_EMAIL

Optional SSO providers:
- GOOGLE_CLIENT_ID
- GITHUB_CLIENT_ID
- GITHUB_CLIENT_SECRET
- OIDC_PROVIDERS_JSON

Current SSO status:
- Google login works.
- GitHub SSO and company OIDC SSO are not fully implemented yet.

3. Start the stack.

```bash
docker compose up -d --build
```

4. Check health.

```bash
docker compose ps
curl -fsS http://127.0.0.1:8000/health
curl -fsS http://127.0.0.1:3000/health
```

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

Then verify remotely:

```bash
ssh -o BatchMode=yes dietpi 'cd /opt/stacks/pi-remote-dev && docker compose ps'
```

## Security Notes
- Never commit .env
- .env.example is safe to commit
- Set COOKIE_SECURE=true when running behind HTTPS

## License
This project is licensed under the MIT License.
See LICENSE for details.
