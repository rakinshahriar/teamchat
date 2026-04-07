# FrontEnd OAuth Database (Web + API + Database)

This project runs a small full app on your Pi:
- Web frontend
- Python API
- PostgreSQL database

It is deployed with Docker Compose.

## What Users Can Do
- Log in with Google
- Log in with email/password
- Verify email and reset password by email
- Save and view private messages
- Use admin dashboard (if they have enough rank)

## Admin / Rank Rules (Simple)
- Rank 7 = highest
- Rank 1 = lowest
- Demote: you must be exactly 1 rank above
- Promote: you must be 2+ ranks above
- Ban: you must be 2+ ranks above
- Unban: you must be higher than the rank that banned the user

## Quick Start
1. On the Pi, open this project folder and create your env file:

```bash
cp .env.example .env
```

2. Fill required values in `.env`:
- `GOOGLE_CLIENT_ID`
- `WEB_ORIGIN`
- `APP_BASE_URL`
- `SMTP_HOST`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_EMAIL`

3. Build and start everything:

```bash
docker compose up -d --build
```

4. Check containers:

```bash
docker compose ps
```

5. Watch logs (if needed):

```bash
docker compose logs -f --tail=200
```

## Main URLs
- App: `/`
- Email verify page: `/verify.html`
- Password reset page: `/reset-password.html`
- Admin page: `/admin.html`

## Important Security Notes
- Never commit `.env`
- `.env.example` is safe to commit
- Use `COOKIE_SECURE=true` when using HTTPS

## OAuth Checklist
- Add your app origin in Google OAuth Authorized JavaScript Origins
- Make sure `.env` `GOOGLE_CLIENT_ID` matches that OAuth app
- Ensure the Pi can resolve Google endpoints from Docker containers
