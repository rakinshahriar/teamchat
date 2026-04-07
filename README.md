# TeamChat

TeamChat is a simple full-stack app with:
- A web app
- A Python API
- A PostgreSQL database

Everything runs with Docker Compose.

## What It Does
- Login with Google
- Login with email and password
- Email verification and password reset
- Save private messages per user
- Admin dashboard with rank controls

## Quick Start
1. Create your env file:

```bash
cp .env.example .env
```

2. In `.env`, fill at least:
- `GOOGLE_CLIENT_ID`
- `WEB_ORIGIN`
- `PUBLIC_API_BASE_URL`
- `APP_BASE_URL`
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_EMAIL`

3. Start the app:

```bash
docker compose up -d --build
```

4. Check everything is up:

```bash
docker compose ps
curl -fsS http://127.0.0.1:8000/health
curl -fsS http://127.0.0.1:3000/health
```

## Main Pages
- App: `/`
- Admin: `/admin.html`
- Verify email: `/verify.html`
- Reset password: `/reset-password.html`

## Admin Rules (Simple)
- Rank 7 is highest, Rank 1 is lowest.
- Promote and ban: you must be at least 2 ranks above.
- Demote: you must be above Rank 2 and higher than the target user.
- Unban: you must be at least 2 ranks above the target.

## Security Notes
- Never commit `.env`.
- `.env.example` is safe to commit.
- Use `COOKIE_SECURE=true` when running behind HTTPS.
