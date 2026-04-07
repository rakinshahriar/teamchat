import hashlib
import json
import smtplib
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any, Optional

import psycopg
from fastapi import Cookie, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from pydantic import BaseModel, Field
from psycopg.rows import dict_row

app = FastAPI()

DATABASE_URL = os.getenv("DATABASE_URL", "")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
SESSION_COOKIE_NAME = "session_token"
SESSION_TTL_DAYS = int(os.getenv("SESSION_TTL_DAYS", "7"))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
WEB_ORIGIN = os.getenv("WEB_ORIGIN", "http://localhost:3000")
APP_BASE_URL = os.getenv("APP_BASE_URL", WEB_ORIGIN).rstrip("/")
REQUIRE_EMAIL_VERIFICATION = os.getenv("REQUIRE_EMAIL_VERIFICATION", "true").lower() == "true"
TOKEN_PREVIEW_IN_RESPONSE = os.getenv("TOKEN_PREVIEW_IN_RESPONSE", "true").lower() == "true"
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "").strip()
SMTP_USE_SSL = os.getenv("SMTP_USE_SSL", "false").lower() == "true"
SMTP_USE_STARTTLS = os.getenv("SMTP_USE_STARTTLS", "true").lower() == "true"

app.add_middleware(
    CORSMiddleware,
    allow_origins=[WEB_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class GoogleAuthRequest(BaseModel):
    credential: str = Field(min_length=20)


class RegisterRequest(BaseModel):
    email: str = Field(min_length=5, max_length=320)
    password: str = Field(min_length=8, max_length=128)
    display_name: Optional[str] = Field(default=None, max_length=120)


class LoginRequest(BaseModel):
    email: str = Field(min_length=5, max_length=320)
    password: str = Field(min_length=1, max_length=128)


class VerifyEmailRequest(BaseModel):
    token: str = Field(min_length=20, max_length=200)


class VerificationRequest(BaseModel):
    email: str = Field(min_length=5, max_length=320)


class PasswordResetConfirmRequest(BaseModel):
    token: str = Field(min_length=20, max_length=200)
    new_password: str = Field(min_length=8, max_length=128)


class MessageCreateRequest(BaseModel):
    content: str = Field(min_length=1, max_length=2000)


class RankUpdateRequest(BaseModel):
    user_id: str = Field(min_length=10, max_length=100)
    rank: int = Field(ge=1, le=7)


class UserActionRequest(BaseModel):
    user_id: str = Field(min_length=10, max_length=100)


class BanUserRequest(BaseModel):
    user_id: str = Field(min_length=10, max_length=100)
    reason: str = Field(min_length=3, max_length=300)


PASSWORD_MIN_LENGTH = 10
MAX_FAILED_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
EMAIL_REGEX = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
EMAIL_VERIFICATION_HOURS = 24
PASSWORD_RESET_MINUTES = 5
MIN_RANK = 1
MAX_RANK = 7
ADMIN_MIN_RANK = 2
SUPER_ADMIN_RANK = 7


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _new_token_pair() -> tuple[str, str]:
    raw_token = secrets.token_urlsafe(48)
    return raw_token, _hash_token(raw_token)


def _db() -> psycopg.Connection:
    if not DATABASE_URL:
        raise HTTPException(status_code=500, detail="DATABASE_URL is not configured")
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def _smtp_is_configured() -> bool:
    return bool(SMTP_HOST and SMTP_FROM_EMAIL)


def _send_email(to_email: str, subject: str, text_body: str) -> None:
    if not _smtp_is_configured():
        raise HTTPException(status_code=503, detail="SMTP is not configured for verification emails")

    msg = EmailMessage()
    msg["From"] = SMTP_FROM_EMAIL
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(text_body)

    try:
        if SMTP_USE_SSL:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=20) as smtp:
                if SMTP_USERNAME:
                    smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as smtp:
                smtp.ehlo()
                if SMTP_USE_STARTTLS:
                    smtp.starttls()
                    smtp.ehlo()
                if SMTP_USERNAME:
                    smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
                smtp.send_message(msg)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Failed to deliver verification email") from exc


def _normalize_email(email: str) -> str:
    return email.strip().lower()


def _validate_email(email: str) -> None:
    if not EMAIL_REGEX.match(email):
        raise HTTPException(status_code=400, detail="Invalid email address")


def _validate_password_strength(password: str) -> None:
    if len(password) < PASSWORD_MIN_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"Password must be at least {PASSWORD_MIN_LENGTH} characters",
        )
    checks = [
        re.search(r"[a-z]", password),
        re.search(r"[A-Z]", password),
        re.search(r"\d", password),
        re.search(r"[^A-Za-z0-9]", password),
    ]
    if not all(checks):
        raise HTTPException(
            status_code=400,
            detail="Password must include upper, lower, number, and symbol",
        )


def _hash_password(password: str, salt: Optional[bytes] = None) -> tuple[str, str]:
    real_salt = salt or os.urandom(16)
    password_hash = hashlib.scrypt(
        password.encode("utf-8"),
        salt=real_salt,
        n=2**14,
        r=8,
        p=1,
        dklen=64,
    )
    return real_salt.hex(), password_hash.hex()


def _verify_password(password: str, salt_hex: str, expected_hash_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    computed = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=64,
    ).hex()
    return secrets.compare_digest(computed, expected_hash_hex)


def _client_ip(request: Request) -> Optional[str]:
    forwarded_for = request.headers.get("x-forwarded-for", "").strip()
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client:
        return request.client.host
    return None


def _set_auth_cookie(response: Response, raw_token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=raw_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=SESSION_TTL_DAYS * 24 * 60 * 60,
        path="/",
    )


def _clear_auth_cookie(response: Response) -> None:
    response.delete_cookie(key=SESSION_COOKIE_NAME, path="/")


def _to_uuid(value: Any) -> uuid.UUID:
    if isinstance(value, uuid.UUID):
        return value
    return uuid.UUID(str(value))


def _normalize_rank(rank: Any) -> int:
    try:
        value = int(rank)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid rank") from exc
    if value < MIN_RANK or value > MAX_RANK:
        raise HTTPException(status_code=400, detail=f"Rank must be between {MIN_RANK} and {MAX_RANK}")
    return value


def _legacy_role_from_rank(rank: int) -> str:
    if rank >= SUPER_ADMIN_RANK:
        return "super_admin"
    if rank >= ADMIN_MIN_RANK:
        return "admin"
    return "user"


def _insert_security_event(
    cur: psycopg.Cursor,
    user_id: Optional[uuid.UUID],
    event_type: str,
    details: dict[str, Any],
) -> None:
    cur.execute(
        """
        INSERT INTO security_events (user_id, event_type, details)
        VALUES (%s, %s, %s::jsonb)
        """,
        (user_id, event_type, json.dumps(details)),
    )


def _create_session(
    cur: psycopg.Cursor,
    user_id: uuid.UUID,
    user_agent: Optional[str],
    ip_address: Optional[str],
) -> str:
    raw_session_token = secrets.token_urlsafe(48)
    session_hash = _hash_token(raw_session_token)
    expires_at = _utc_now() + timedelta(days=SESSION_TTL_DAYS)
    cur.execute(
        """
        INSERT INTO sessions (id, user_id, session_hash, user_agent, ip_address, expires_at)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (
            uuid.uuid4(),
            user_id,
            session_hash,
            user_agent,
            ip_address,
            expires_at,
        ),
    )
    return raw_session_token


def _require_user(session_token: Optional[str]) -> dict[str, Any]:
    if not session_token:
        raise HTTPException(status_code=401, detail="Authentication required")

    token_hash = _hash_token(session_token)
    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                                SELECT u.id, u.email, u.display_name, u.picture_url, u.role, u.rank, u.is_banned, s.id AS session_id
                FROM sessions s
                JOIN users u ON u.id = s.user_id
                WHERE s.session_hash = %s
                  AND s.expires_at > NOW()
                """,
                (token_hash,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=401, detail="Invalid or expired session")
            if row.get("is_banned"):
                raise HTTPException(status_code=403, detail="Account is banned")
            cur.execute("UPDATE sessions SET last_seen_at = NOW() WHERE id = %s", (row["session_id"],))
        conn.commit()
    return row


def _require_min_rank(session_token: Optional[str], minimum_rank: int) -> dict[str, Any]:
    user = _require_user(session_token)
    min_rank = _normalize_rank(minimum_rank)
    user_rank = _normalize_rank(user.get("rank") or MIN_RANK)
    if user_rank < min_rank:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def _issue_email_verification_token(cur: psycopg.Cursor, user_id: uuid.UUID) -> tuple[str, datetime]:
    raw_token, token_hash = _new_token_pair()
    expires_at = _utc_now() + timedelta(hours=EMAIL_VERIFICATION_HOURS)
    cur.execute("DELETE FROM email_verification_tokens WHERE user_id = %s", (user_id,))
    cur.execute(
        """
        INSERT INTO email_verification_tokens (id, user_id, token_hash, expires_at)
        VALUES (%s, %s, %s, %s)
        """,
        (uuid.uuid4(), user_id, token_hash, expires_at),
    )
    return raw_token, expires_at


def _issue_password_reset_token(cur: psycopg.Cursor, user_id: uuid.UUID) -> tuple[str, datetime]:
    raw_token, token_hash = _new_token_pair()
    expires_at = _utc_now() + timedelta(minutes=PASSWORD_RESET_MINUTES)
    cur.execute("DELETE FROM password_reset_tokens WHERE user_id = %s", (user_id,))
    cur.execute(
        """
        INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at)
        VALUES (%s, %s, %s, %s)
        """,
        (uuid.uuid4(), user_id, token_hash, expires_at),
    )
    return raw_token, expires_at


def _send_verification_email(email: str, verification_link: str) -> None:
    _send_email(
        to_email=email,
        subject="Verify your Message Vault account",
        text_body=(
            "Welcome to Message Vault.\n\n"
            "Please verify your email using this link:\n"
            f"{verification_link}\n\n"
            "If you did not request this, you can ignore this email."
        ),
    )


def _send_reset_email(email: str, reset_link: str) -> None:
    _send_email(
        to_email=email,
        subject="Reset your Message Vault password",
        text_body=(
            "A password reset was requested for your account.\n\n"
            "Use this link to set a new password:\n"
            f"{reset_link}\n\n"
            "If you did not request this, you can ignore this email."
        ),
    )


@app.on_event("startup")
def startup() -> None:
    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id UUID PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE,
                    display_name TEXT NOT NULL,
                    picture_url TEXT,
                    role TEXT NOT NULL DEFAULT 'user',
                    rank INTEGER NOT NULL DEFAULT 1,
                    is_banned BOOLEAN NOT NULL DEFAULT FALSE,
                    banned_by_rank INTEGER,
                    banned_reason TEXT,
                    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    last_login_at TIMESTAMPTZ
                )
                """
            )
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user'")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS rank INTEGER NOT NULL DEFAULT 1")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_banned BOOLEAN NOT NULL DEFAULT FALSE")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS banned_by_rank INTEGER")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS banned_reason TEXT")
            cur.execute("UPDATE users SET role = 'user' WHERE role IS NULL OR role = ''")
            cur.execute(
                """
                UPDATE users
                SET rank = CASE
                    WHEN role = 'super_admin' THEN 7
                    WHEN role = 'admin' THEN 2
                    ELSE 1
                END
                WHERE rank IS NULL OR rank < 1 OR rank > 7
                """
            )
            cur.execute("ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check")
            cur.execute(
                "ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('user', 'admin', 'super_admin'))"
            )
            cur.execute("ALTER TABLE users DROP CONSTRAINT IF EXISTS users_rank_check")
            cur.execute("ALTER TABLE users ADD CONSTRAINT users_rank_check CHECK (rank BETWEEN 1 AND 7)")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS user_security_profiles (
                    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                    auth_provider TEXT NOT NULL,
                    password_login_enabled BOOLEAN NOT NULL DEFAULT FALSE,
                    mfa_required BOOLEAN NOT NULL DEFAULT FALSE,
                    requirements_version TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    id UUID PRIMARY KEY,
                    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    session_hash TEXT NOT NULL UNIQUE,
                    user_agent TEXT,
                    ip_address TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    expires_at TIMESTAMPTZ NOT NULL
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id BIGSERIAL PRIMARY KEY,
                    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    content TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    id BIGSERIAL PRIMARY KEY,
                    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
                    event_type TEXT NOT NULL,
                    details JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS user_password_credentials (
                    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                    password_salt TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    password_algo TEXT NOT NULL DEFAULT 'scrypt-v1',
                    failed_attempts INTEGER NOT NULL DEFAULT 0,
                    locked_until TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS email_verification_tokens (
                    id UUID PRIMARY KEY,
                    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    token_hash TEXT NOT NULL UNIQUE,
                    expires_at TIMESTAMPTZ NOT NULL,
                    used_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    id UUID PRIMARY KEY,
                    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    token_hash TEXT NOT NULL UNIQUE,
                    expires_at TIMESTAMPTZ NOT NULL,
                    used_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )

            # Bootstrap one top-rank admin if none exists yet.
            cur.execute("SELECT COUNT(*) AS count FROM users WHERE rank = %s", (SUPER_ADMIN_RANK,))
            rank_count = cur.fetchone()
            if rank_count and int(rank_count["count"]) == 0:
                cur.execute("SELECT id FROM users ORDER BY created_at ASC LIMIT 1")
                first_user = cur.fetchone()
                if first_user:
                    cur.execute(
                        "UPDATE users SET rank = %s, role = 'super_admin' WHERE id = %s",
                        (SUPER_ADMIN_RANK, first_user["id"]),
                    )
                    _insert_security_event(
                        cur,
                        first_user["id"],
                        "rank_changed",
                        {
                            "actor": "system_bootstrap",
                            "old_rank": 1,
                            "new_rank": SUPER_ADMIN_RANK,
                        },
                    )
        conn.commit()


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "api",
        "database_url_set": bool(DATABASE_URL),
        "google_client_id_set": bool(GOOGLE_CLIENT_ID),
        "rbac_enabled": True,
        "smtp_configured": _smtp_is_configured(),
    }


@app.post("/auth/google")
def auth_google(
    payload: GoogleAuthRequest,
    request: Request,
    response: Response,
    user_agent: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google authentication is not configured",
        )

    try:
        token_info = id_token.verify_oauth2_token(
            payload.credential,
            google_requests.Request(),
            GOOGLE_CLIENT_ID,
        )
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid Google credential") from exc

    email = token_info.get("email")
    email_verified = bool(token_info.get("email_verified"))
    display_name = token_info.get("name") or email
    picture_url = token_info.get("picture")

    if not email or not email_verified:
        raise HTTPException(status_code=401, detail="Google email must be verified")

    new_user = False
    user_id: uuid.UUID

    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, is_banned FROM users WHERE email = %s", (email,))
            existing = cur.fetchone()

            if existing:
                if existing.get("is_banned"):
                    raise HTTPException(status_code=403, detail="Account is banned")
                user_id = existing["id"]
                cur.execute(
                    """
                    UPDATE users
                    SET display_name = %s, picture_url = %s, last_login_at = NOW(), email_verified = TRUE
                    WHERE id = %s
                    """,
                    (display_name, picture_url, user_id),
                )
            else:
                new_user = True
                user_id = uuid.uuid4()
                cur.execute(
                    """
                    INSERT INTO users (id, email, display_name, picture_url, last_login_at)
                    VALUES (%s, %s, %s, %s, NOW())
                    """,
                    (user_id, email, display_name, picture_url),
                )
                cur.execute("UPDATE users SET email_verified = TRUE WHERE id = %s", (user_id,))
                cur.execute(
                    """
                    INSERT INTO user_security_profiles (
                        user_id, auth_provider, password_login_enabled, mfa_required, requirements_version
                    )
                    VALUES (%s, 'google', FALSE, FALSE, 'v1')
                    ON CONFLICT (user_id) DO NOTHING
                    """,
                    (user_id,),
                )
                cur.execute(
                    """
                    INSERT INTO security_events (user_id, event_type, details)
                    VALUES (%s, 'user_created', %s::jsonb)
                    """,
                    (user_id, '{"source":"google_oauth"}'),
                )

            raw_session_token = _create_session(
                cur,
                user_id,
                user_agent,
                _client_ip(request),
            )
            _insert_security_event(cur, user_id, "login_success", {"provider": "google"})
        conn.commit()

    _set_auth_cookie(response, raw_session_token)
    return {
        "status": "ok",
        "new_user": new_user,
    }


@app.post("/auth/register")
def auth_register(
    payload: RegisterRequest,
    request: Request,
    response: Response,
    user_agent: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    email = _normalize_email(payload.email)
    _validate_email(email)
    _validate_password_strength(payload.password)

    inferred_name = email.split("@", 1)[0]
    display_name = (payload.display_name or inferred_name).strip()[:120]
    if not display_name:
        raise HTTPException(status_code=400, detail="Display name is required")

    new_user = False
    verification_link: Optional[str] = None

    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            existing = cur.fetchone()

            if existing:
                user_id = existing["id"]
                cur.execute("SELECT user_id FROM user_password_credentials WHERE user_id = %s", (user_id,))
                has_password = cur.fetchone()
                if has_password:
                    raise HTTPException(status_code=409, detail="Account already registered")
            else:
                new_user = True
                user_id = uuid.uuid4()
                cur.execute(
                    """
                    INSERT INTO users (id, email, display_name, email_verified)
                    VALUES (%s, %s, %s, FALSE)
                    """,
                    (user_id, email, display_name),
                )
                _insert_security_event(cur, user_id, "user_created", {"source": "manual_registration"})

            salt_hex, password_hash_hex = _hash_password(payload.password)
            cur.execute(
                """
                INSERT INTO user_password_credentials (user_id, password_salt, password_hash)
                VALUES (%s, %s, %s)
                ON CONFLICT (user_id) DO UPDATE
                SET password_salt = EXCLUDED.password_salt,
                    password_hash = EXCLUDED.password_hash,
                    updated_at = NOW(),
                    failed_attempts = 0,
                    locked_until = NULL
                """,
                (user_id, salt_hex, password_hash_hex),
            )

            cur.execute(
                """
                INSERT INTO user_security_profiles (
                    user_id, auth_provider, password_login_enabled, mfa_required, requirements_version
                )
                VALUES (%s, 'password', TRUE, FALSE, 'v1')
                ON CONFLICT (user_id) DO UPDATE
                SET auth_provider = CASE
                    WHEN user_security_profiles.auth_provider = 'google' THEN 'google+password'
                    ELSE 'password'
                END,
                    password_login_enabled = TRUE,
                    updated_at = NOW()
                """,
                (user_id,),
            )

            raw_verification_token, _ = _issue_email_verification_token(cur, _to_uuid(user_id))
            verification_link = f"{APP_BASE_URL}/verify.html?token={raw_verification_token}"

            _insert_security_event(cur, user_id, "password_registered", {"provider": "password"})
            _insert_security_event(cur, user_id, "email_verification_sent", {"channel": "app_link"})
        conn.commit()

    if verification_link:
        _send_verification_email(email, verification_link)

    return {"status": "ok", "new_user": new_user, "verification_required": True}


@app.post("/auth/login")
def auth_login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    user_agent: Optional[str] = Header(default=None),
) -> dict[str, str]:
    email = _normalize_email(payload.email)
    _validate_email(email)

    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    u.id,
                    u.is_banned,
                    u.banned_by_rank,
                    u.banned_reason,
                    c.password_salt,
                    c.password_hash,
                    c.failed_attempts,
                    c.locked_until
                FROM users u
                LEFT JOIN user_password_credentials c ON c.user_id = u.id
                WHERE u.email = %s
                """,
                (email,),
            )
            row = cur.fetchone()

            if not row or not row["password_salt"] or not row["password_hash"]:
                raise HTTPException(status_code=401, detail="Invalid email or password")

            user_id = row["id"]
            if row.get("is_banned"):
                raise HTTPException(status_code=403, detail="Account is banned")
            locked_until = row["locked_until"]
            if locked_until and locked_until > _utc_now():
                raise HTTPException(status_code=423, detail="Account temporarily locked due to failed attempts")

            if REQUIRE_EMAIL_VERIFICATION:
                cur.execute("SELECT email_verified FROM users WHERE id = %s", (user_id,))
                verified_row = cur.fetchone()
                if not verified_row or not verified_row["email_verified"]:
                    raise HTTPException(status_code=403, detail="Email not verified")

            is_valid = _verify_password(payload.password, row["password_salt"], row["password_hash"])

            if not is_valid:
                failed_attempts = int(row["failed_attempts"] or 0) + 1
                if failed_attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
                    lock_until = _utc_now() + timedelta(minutes=LOCKOUT_MINUTES)
                    cur.execute(
                        """
                        UPDATE user_password_credentials
                        SET failed_attempts = %s, locked_until = %s, updated_at = NOW()
                        WHERE user_id = %s
                        """,
                        (failed_attempts, lock_until, user_id),
                    )
                    _insert_security_event(
                        cur,
                        user_id,
                        "login_locked",
                        {"provider": "password", "failed_attempts": failed_attempts},
                    )
                else:
                    cur.execute(
                        """
                        UPDATE user_password_credentials
                        SET failed_attempts = %s, updated_at = NOW()
                        WHERE user_id = %s
                        """,
                        (failed_attempts, user_id),
                    )
                _insert_security_event(cur, user_id, "login_failed", {"provider": "password"})
                conn.commit()
                raise HTTPException(status_code=401, detail="Invalid email or password")

            cur.execute(
                """
                UPDATE user_password_credentials
                SET failed_attempts = 0, locked_until = NULL, updated_at = NOW()
                WHERE user_id = %s
                """,
                (user_id,),
            )
            cur.execute("UPDATE users SET last_login_at = NOW() WHERE id = %s", (user_id,))
            raw_session_token = _create_session(cur, user_id, user_agent, _client_ip(request))
            _insert_security_event(cur, user_id, "login_success", {"provider": "password"})
        conn.commit()

    _set_auth_cookie(response, raw_session_token)
    return {"status": "ok"}


@app.post("/auth/verify-email")
def auth_verify_email(payload: VerifyEmailRequest) -> dict[str, str]:
    token_hash = _hash_token(payload.token)
    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT user_id, expires_at, used_at
                FROM email_verification_tokens
                WHERE token_hash = %s
                """,
                (token_hash,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=400, detail="Invalid verification token")
            if row["used_at"] is not None or row["expires_at"] <= _utc_now():
                raise HTTPException(status_code=400, detail="Verification token expired or already used")

            user_id = row["user_id"]
            cur.execute("UPDATE users SET email_verified = TRUE WHERE id = %s", (user_id,))
            cur.execute(
                "UPDATE email_verification_tokens SET used_at = NOW() WHERE token_hash = %s",
                (token_hash,),
            )
            _insert_security_event(cur, user_id, "email_verified", {"method": "token"})
        conn.commit()
    return {"status": "ok"}


@app.post("/auth/resend-verification")
def auth_resend_verification(payload: VerificationRequest) -> dict[str, Any]:
    email = _normalize_email(payload.email)
    _validate_email(email)
    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, email_verified FROM users WHERE email = %s", (email,))
            row = cur.fetchone()
            if not row:
                return {"status": "ok"}
            if row["email_verified"]:
                return {"status": "ok", "already_verified": True}

            raw_verification_token, _ = _issue_email_verification_token(cur, row["id"])
            verification_link = f"{APP_BASE_URL}/verify.html?token={raw_verification_token}"
            _insert_security_event(cur, row["id"], "email_verification_sent", {"channel": "app_link"})
        conn.commit()

    _send_verification_email(email, verification_link)
    return {"status": "ok"}


@app.post("/auth/password-reset/request")
def auth_password_reset_request(payload: VerificationRequest) -> dict[str, Any]:
    email = _normalize_email(payload.email)
    _validate_email(email)
    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT u.id
                FROM users u
                JOIN user_password_credentials c ON c.user_id = u.id
                WHERE u.email = %s
                """,
                (email,),
            )
            row = cur.fetchone()
            if not row:
                return {"status": "ok"}

            raw_token, _ = _issue_password_reset_token(cur, row["id"])
            reset_link = f"{APP_BASE_URL}/reset-password.html?token={raw_token}"
            _insert_security_event(cur, row["id"], "password_reset_requested", {"channel": "app_link"})
        conn.commit()

    _send_reset_email(email, reset_link)
    return {"status": "ok"}


@app.post("/auth/password-reset/confirm")
def auth_password_reset_confirm(payload: PasswordResetConfirmRequest) -> dict[str, str]:
    _validate_password_strength(payload.new_password)
    token_hash = _hash_token(payload.token)

    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT user_id, expires_at, used_at
                FROM password_reset_tokens
                WHERE token_hash = %s
                """,
                (token_hash,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=400, detail="Invalid reset token")
            if row["used_at"] is not None or row["expires_at"] <= _utc_now():
                raise HTTPException(status_code=400, detail="Reset token expired or already used")

            user_id = row["user_id"]
            salt_hex, password_hash_hex = _hash_password(payload.new_password)
            cur.execute(
                """
                UPDATE user_password_credentials
                SET password_salt = %s,
                    password_hash = %s,
                    updated_at = NOW(),
                    failed_attempts = 0,
                    locked_until = NULL
                WHERE user_id = %s
                """,
                (salt_hex, password_hash_hex, user_id),
            )
            cur.execute(
                "UPDATE password_reset_tokens SET used_at = NOW() WHERE token_hash = %s",
                (token_hash,),
            )
            _insert_security_event(cur, user_id, "password_reset_completed", {"method": "token"})
        conn.commit()
    return {"status": "ok"}


@app.post("/logout")
def logout(response: Response, session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME)) -> dict[str, str]:
    if session_token:
        with _db() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM sessions WHERE session_hash = %s", (_hash_token(session_token),))
            conn.commit()
    _clear_auth_cookie(response)
    return {"status": "ok"}


@app.get("/me")
def me(session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME)) -> dict[str, Any]:
    user = _require_user(session_token)
    rank = _normalize_rank(user.get("rank") or MIN_RANK)
    legacy_role = _legacy_role_from_rank(rank)
    return {
        "id": str(user["id"]),
        "email": user["email"],
        "display_name": user["display_name"],
        "picture_url": user["picture_url"],
        "role": legacy_role,
        "rank": rank,
        "is_admin": rank >= ADMIN_MIN_RANK,
        "is_super_admin": rank >= SUPER_ADMIN_RANK,
    }


@app.get("/messages")
def list_messages(session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME)) -> dict[str, Any]:
    user = _require_user(session_token)
    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, content, created_at
                FROM messages
                WHERE user_id = %s
                ORDER BY created_at DESC
                LIMIT 200
                """,
                (user["id"],),
            )
            rows = cur.fetchall()
    return {
        "messages": [
            {
                "id": row["id"],
                "content": row["content"],
                "created_at": row["created_at"].isoformat(),
            }
            for row in rows
        ]
    }


@app.post("/messages")
def create_message(
    payload: MessageCreateRequest,
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> dict[str, Any]:
    user = _require_user(session_token)
    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO messages (user_id, content)
                VALUES (%s, %s)
                RETURNING id, content, created_at
                """,
                (user["id"], payload.content.strip()),
            )
            row = cur.fetchone()
        conn.commit()
    return {
        "id": row["id"],
        "content": row["content"],
        "created_at": row["created_at"].isoformat(),
    }


@app.get("/admin/users")
def admin_users(session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME)) -> dict[str, Any]:
    _require_min_rank(session_token, ADMIN_MIN_RANK)
    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT u.id, u.email, u.display_name, u.role, u.rank, u.email_verified, u.created_at, u.last_login_at,
                      u.is_banned, u.banned_by_rank, u.banned_reason, usp.auth_provider, usp.password_login_enabled
                FROM users u
                LEFT JOIN user_security_profiles usp ON usp.user_id = u.id
                ORDER BY u.created_at DESC
                LIMIT 500
                """
            )
            rows = cur.fetchall()
    return {
        "users": [
            {
                "id": str(row["id"]),
                "email": row["email"],
                "display_name": row["display_name"],
                "rank": int(row["rank"]),
                "role": _legacy_role_from_rank(int(row["rank"])),
                "email_verified": row["email_verified"],
                "is_banned": bool(row["is_banned"]),
                "banned_by_rank": int(row["banned_by_rank"]) if row["banned_by_rank"] is not None else None,
                "banned_reason": row["banned_reason"],
                "created_at": row["created_at"].isoformat() if row["created_at"] else None,
                "last_login_at": row["last_login_at"].isoformat() if row["last_login_at"] else None,
                "auth_provider": row["auth_provider"],
                "password_login_enabled": row["password_login_enabled"],
            }
            for row in rows
        ]
    }


@app.post("/admin/users/rank")
@app.post("/admin/users/role")
def admin_update_user_rank(
    payload: RankUpdateRequest,
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> dict[str, Any]:
    actor = _require_min_rank(session_token, ADMIN_MIN_RANK)
    actor_rank = _normalize_rank(actor.get("rank") or MIN_RANK)
    new_rank = _normalize_rank(payload.rank)

    try:
        target_user_id = _to_uuid(payload.user_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid user_id") from exc

    if str(target_user_id) == str(actor["id"]):
        raise HTTPException(status_code=400, detail="You cannot change your own rank")

    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, email, rank FROM users WHERE id = %s", (target_user_id,))
            target = cur.fetchone()
            if not target:
                raise HTTPException(status_code=404, detail="User not found")

            target_rank = _normalize_rank(target.get("rank") or MIN_RANK)

            if actor_rank <= target_rank:
                raise HTTPException(status_code=403, detail="You can only manage lower-level users")

            if new_rank >= actor_rank:
                raise HTTPException(status_code=403, detail="You can only assign ranks lower than your own")

            # Promotion authority: one step at a time, and never to your own rank.
            if new_rank != target_rank + 1:
                raise HTTPException(status_code=403, detail="You can only promote one rank at a time")

            if new_rank > actor_rank - 1:
                raise HTTPException(status_code=403, detail="You can only promote up to one level below your rank")

            if target_rank == new_rank:
                return {
                    "status": "ok",
                    "user_id": str(target["id"]),
                    "email": target["email"],
                    "rank": target_rank,
                    "role": _legacy_role_from_rank(target_rank),
                    "unchanged": True,
                }

            cur.execute(
                "UPDATE users SET rank = %s, role = %s WHERE id = %s",
                (new_rank, _legacy_role_from_rank(new_rank), target_user_id),
            )
            _insert_security_event(
                cur,
                target_user_id,
                "rank_changed",
                {
                    "actor_user_id": str(actor["id"]),
                    "old_rank": target_rank,
                    "new_rank": new_rank,
                },
            )
        conn.commit()

    return {
        "status": "ok",
        "user_id": str(target_user_id),
        "email": target["email"],
        "rank": new_rank,
        "role": _legacy_role_from_rank(new_rank),
    }


def _load_target_user(cur: psycopg.Cursor, target_user_id: uuid.UUID) -> dict[str, Any]:
    cur.execute(
        "SELECT id, email, rank, is_banned, banned_by_rank, banned_reason FROM users WHERE id = %s",
        (target_user_id,),
    )
    target = cur.fetchone()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    return target


@app.post("/admin/users/promote")
def admin_promote_user(
    payload: UserActionRequest,
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> dict[str, Any]:
    actor = _require_min_rank(session_token, ADMIN_MIN_RANK)
    actor_rank = _normalize_rank(actor.get("rank") or MIN_RANK)
    try:
        target_user_id = _to_uuid(payload.user_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid user_id") from exc
    if str(target_user_id) == str(actor["id"]):
        raise HTTPException(status_code=400, detail="You cannot promote yourself")

    with _db() as conn:
        with conn.cursor() as cur:
            target = _load_target_user(cur, target_user_id)
            target_rank = _normalize_rank(target.get("rank") or MIN_RANK)
            if target.get("is_banned"):
                raise HTTPException(status_code=400, detail="Cannot promote a banned user")
            if actor_rank < target_rank + 2:
                raise HTTPException(status_code=403, detail="Only users two levels above can promote")
            if target_rank >= MAX_RANK:
                raise HTTPException(status_code=400, detail="User is already at max rank")

            new_rank = target_rank + 1
            cur.execute(
                "UPDATE users SET rank = %s, role = %s WHERE id = %s",
                (new_rank, _legacy_role_from_rank(new_rank), target_user_id),
            )
            _insert_security_event(
                cur,
                target_user_id,
                "rank_promoted",
                {
                    "actor_user_id": str(actor["id"]),
                    "old_rank": target_rank,
                    "new_rank": new_rank,
                },
            )
        conn.commit()

    return {"status": "ok", "email": target["email"], "rank": new_rank}


@app.post("/admin/users/demote")
def admin_demote_user(
    payload: UserActionRequest,
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> dict[str, Any]:
    actor = _require_min_rank(session_token, ADMIN_MIN_RANK)
    actor_rank = _normalize_rank(actor.get("rank") or MIN_RANK)
    try:
        target_user_id = _to_uuid(payload.user_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid user_id") from exc
    if str(target_user_id) == str(actor["id"]):
        raise HTTPException(status_code=400, detail="You cannot demote yourself")

    with _db() as conn:
        with conn.cursor() as cur:
            target = _load_target_user(cur, target_user_id)
            target_rank = _normalize_rank(target.get("rank") or MIN_RANK)
            if target.get("is_banned"):
                raise HTTPException(status_code=400, detail="Cannot demote a banned user")
            if actor_rank <= 2:
                raise HTTPException(status_code=403, detail="Only ranks above 2 can demote users")
            if actor_rank <= target_rank:
                raise HTTPException(status_code=403, detail="You can only demote lower-rank users")
            if target_rank <= MIN_RANK:
                raise HTTPException(status_code=400, detail="User is already at minimum rank")

            new_rank = target_rank - 1
            cur.execute(
                "UPDATE users SET rank = %s, role = %s WHERE id = %s",
                (new_rank, _legacy_role_from_rank(new_rank), target_user_id),
            )
            _insert_security_event(
                cur,
                target_user_id,
                "rank_demoted",
                {
                    "actor_user_id": str(actor["id"]),
                    "old_rank": target_rank,
                    "new_rank": new_rank,
                },
            )
        conn.commit()

    return {"status": "ok", "email": target["email"], "rank": new_rank}


@app.post("/admin/users/ban")
def admin_ban_user(
    payload: BanUserRequest,
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> dict[str, Any]:
    actor = _require_min_rank(session_token, ADMIN_MIN_RANK)
    actor_rank = _normalize_rank(actor.get("rank") or MIN_RANK)
    try:
        target_user_id = _to_uuid(payload.user_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid user_id") from exc
    if str(target_user_id) == str(actor["id"]):
        raise HTTPException(status_code=400, detail="You cannot ban yourself")

    with _db() as conn:
        with conn.cursor() as cur:
            target = _load_target_user(cur, target_user_id)
            target_rank = _normalize_rank(target.get("rank") or MIN_RANK)
            reason = payload.reason.strip()
            if actor_rank < target_rank + 2:
                raise HTTPException(status_code=403, detail="Only users two levels above can ban")

            if target.get("is_banned"):
                return {"status": "ok", "email": target["email"], "banned": True, "unchanged": True}

            cur.execute(
                "UPDATE users SET is_banned = TRUE, banned_by_rank = %s, banned_reason = %s, rank = %s, role = %s WHERE id = %s",
                (actor_rank, reason, MIN_RANK, _legacy_role_from_rank(MIN_RANK), target_user_id),
            )
            cur.execute("DELETE FROM sessions WHERE user_id = %s", (target_user_id,))
            _insert_security_event(
                cur,
                target_user_id,
                "user_banned",
                {
                    "actor_user_id": str(actor["id"]),
                    "old_rank": target_rank,
                    "reason": reason,
                },
            )
        conn.commit()

    return {"status": "ok", "email": target["email"], "banned": True}


@app.post("/admin/users/unban")
def admin_unban_user(
    payload: UserActionRequest,
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> dict[str, Any]:
    actor = _require_min_rank(session_token, ADMIN_MIN_RANK)
    actor_rank = _normalize_rank(actor.get("rank") or MIN_RANK)
    try:
        target_user_id = _to_uuid(payload.user_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid user_id") from exc
    if str(target_user_id) == str(actor["id"]):
        raise HTTPException(status_code=400, detail="You cannot unban yourself")

    with _db() as conn:
        with conn.cursor() as cur:
            target = _load_target_user(cur, target_user_id)
            target_rank = _normalize_rank(target.get("rank") or MIN_RANK)
            banned_by_rank = target.get("banned_by_rank")
            if banned_by_rank is not None:
                banned_by_rank = _normalize_rank(banned_by_rank)
            if actor_rank < target_rank + 2:
                raise HTTPException(status_code=403, detail="Only users two levels above can unban")
            if banned_by_rank is not None and actor_rank <= banned_by_rank and actor_rank < SUPER_ADMIN_RANK:
                raise HTTPException(status_code=403, detail="Only a higher rank than the banning rank can unban")

            if not target.get("is_banned"):
                return {"status": "ok", "email": target["email"], "banned": False, "unchanged": True}

            cur.execute(
                "UPDATE users SET is_banned = FALSE, banned_by_rank = NULL, banned_reason = NULL WHERE id = %s",
                (target_user_id,),
            )
            _insert_security_event(
                cur,
                target_user_id,
                "user_unbanned",
                {
                    "actor_user_id": str(actor["id"]),
                    "rank": target_rank,
                    "banned_by_rank": banned_by_rank,
                },
            )
        conn.commit()

    return {"status": "ok", "email": target["email"], "banned": False}


@app.get("/admin/security-events")
def admin_security_events(
    limit: int = 100,
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> dict[str, Any]:
    _require_min_rank(session_token, ADMIN_MIN_RANK)
    safe_limit = max(1, min(limit, 500))
    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT se.id, se.user_id, u.email, se.event_type, se.details, se.created_at
                FROM security_events se
                LEFT JOIN users u ON u.id = se.user_id
                ORDER BY se.created_at DESC
                LIMIT %s
                """,
                (safe_limit,),
            )
            rows = cur.fetchall()
    return {
        "events": [
            {
                "id": row["id"],
                "user_id": str(row["user_id"]) if row["user_id"] else None,
                "email": row["email"],
                "event_type": row["event_type"],
                "details": row["details"],
                "created_at": row["created_at"].isoformat(),
            }
            for row in rows
        ]
    }
