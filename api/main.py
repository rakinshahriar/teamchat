import hashlib
import hmac
import json
import smtplib
import os
import re
import secrets
import struct
import threading
import time
import uuid
import base64
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any, Optional
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

import psycopg
import requests
from fastapi import Cookie, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from pydantic import BaseModel, Field
from psycopg.rows import dict_row

app = FastAPI()


def _env_int(name: str, default: int) -> int:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default

DATABASE_URL = os.getenv("DATABASE_URL", "")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "").strip()
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
OIDC_PROVIDERS_JSON = os.getenv("OIDC_PROVIDERS_JSON", "").strip()
SESSION_COOKIE_NAME = "session_token"
SSO_STATE_COOKIE_NAME = "sso_state"
SSO_COMPANY_COOKIE_NAME = "sso_company"
SSO_PKCE_COOKIE_NAME = "sso_pkce_verifier"
SSO_PROVIDER_COOKIE_NAME = "sso_provider_key"
SSO_INTENT_COOKIE_NAME = "sso_intent"
SSO_DISPLAY_NAME_COOKIE_NAME = "sso_display_name"
SSO_TOS_ACCEPTED_COOKIE_NAME = "sso_tos_accepted"
SESSION_TTL_DAYS = int(os.getenv("SESSION_TTL_DAYS", "7"))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
WEB_ORIGIN = os.getenv("WEB_ORIGIN", "http://localhost:3000")
APP_BASE_URL = os.getenv("APP_BASE_URL", WEB_ORIGIN).rstrip("/")
PUBLIC_API_BASE_URL = os.getenv("PUBLIC_API_BASE_URL", "").strip().rstrip("/")
REQUIRE_EMAIL_VERIFICATION = os.getenv("REQUIRE_EMAIL_VERIFICATION", "true").lower() == "true"
TOKEN_PREVIEW_IN_RESPONSE = os.getenv("TOKEN_PREVIEW_IN_RESPONSE", "false").lower() == "true"
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = _env_int("SMTP_PORT", 587)
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "").strip()
SMTP_USE_SSL = os.getenv("SMTP_USE_SSL", "false").lower() == "true"
SMTP_USE_STARTTLS = os.getenv("SMTP_USE_STARTTLS", "true").lower() == "true"
EMAIL_DRY_RUN = os.getenv("EMAIL_DRY_RUN", "false").lower() == "true"
EMAIL_PROVIDER = os.getenv("EMAIL_PROVIDER", "smtp").strip().lower()
BREVO_API_KEY = os.getenv("BREVO_API_KEY", "").strip()
BREVO_API_URL = os.getenv("BREVO_API_URL", "https://api.brevo.com/v3/smtp/email").strip()
TOKEN_SECRET = os.getenv("TOKEN_SECRET", "")


def _is_local_origin(url: str) -> bool:
    m = re.match(r"^https?://([^/:]+)", (url or "").strip(), re.IGNORECASE)
    if not m:
        return True
    host = m.group(1).lower()
    return host in {"localhost", "127.0.0.1", "::1", "api", "web", "db"}


def _validate_security_config() -> None:
    # TOKEN_SECRET signs session and one-time tokens; weak/missing values are unsafe.
    if not TOKEN_SECRET or len(TOKEN_SECRET) < 32:
        raise RuntimeError("TOKEN_SECRET must be set and at least 32 characters")
    if not COOKIE_SECURE and not _is_local_origin(WEB_ORIGIN):
        raise RuntimeError("COOKIE_SECURE must be true for non-local WEB_ORIGIN")


_validate_security_config()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[WEB_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _is_local_host(host: str) -> bool:
    host_only = (host or "").split(":", 1)[0].strip().lower()
    return host_only in {"localhost", "127.0.0.1", "::1", "api", "web", "db"}


@app.middleware("http")
async def enforce_https_and_headers(request: Request, call_next):
    forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip().lower()
    forwarded_host = request.headers.get("x-forwarded-host", "").split(",", 1)[0].strip()
    host = forwarded_host or request.headers.get("host", "").split(",", 1)[0].strip()

    if forwarded_proto == "http" and host and not _is_local_host(host):
        target = f"https://{host}{request.url.path}"
        if request.url.query:
            target = f"{target}?{request.url.query}"
        return RedirectResponse(url=target, status_code=308)

    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if forwarded_proto == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response


class GoogleAuthRequest(BaseModel):
    credential: str = Field(min_length=20)
    intent: str = Field(default="login", pattern="^(login|register)$")
    display_name: Optional[str] = Field(default=None, max_length=120)
    tos_accepted: bool = Field(default=False)


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


class ConnectionRequestCreateRequest(BaseModel):
    target_user_id: str = Field(min_length=10, max_length=100)


class ConnectionRequestActionRequest(BaseModel):
    requester_user_id: str = Field(min_length=10, max_length=100)


class ConnectionMessageCreateRequest(BaseModel):
    recipient_user_id: str = Field(min_length=10, max_length=100)
    content: str = Field(min_length=1, max_length=2000)


class GroupCreateRequest(BaseModel):
    name: str = Field(min_length=2, max_length=80)


class GroupAddMemberRequest(BaseModel):
    user_id: str = Field(min_length=10, max_length=100)


class GroupMessageCreateRequest(BaseModel):
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
EMAIL_VERIFICATION_MINUTES = 5
PASSWORD_RESET_MINUTES = 15
MIN_RANK = 1
MAX_RANK = 7
ADMIN_MIN_RANK = 2
SUPER_ADMIN_RANK = 7


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


# Token type identifiers embedded inside signed tokens
_TOKEN_TYPE_VERIFY = "v"
_TOKEN_TYPE_RESET = "r"


def _make_signed_token(expiry_minutes: int, token_type: str) -> str:
    """Create a self-expiring HMAC-signed token: <nonce>.<type>.<expiry_b64u>.<sig_b64u>

    token_type must be one of the _TOKEN_TYPE_* constants.
    It is included in the HMAC message so a verify token cannot be
    accepted by the reset endpoint and vice-versa.
    Expiry and HMAC signature are base64url-encoded (no padding) for compactness.
    """
    nonce = secrets.token_urlsafe(32)
    expiry_ts = int((_utc_now() + timedelta(minutes=expiry_minutes)).timestamp())
    expiry_b64 = base64.urlsafe_b64encode(struct.pack(">I", expiry_ts)).rstrip(b"=").decode()
    msg = f"{nonce}|{token_type}|{expiry_ts}".encode()
    sig_b64 = base64.urlsafe_b64encode(hmac.new(TOKEN_SECRET.encode(), msg, hashlib.sha256).digest()).rstrip(b"=").decode()
    return f"{nonce}.{token_type}.{expiry_b64}.{sig_b64}"


def _verify_signed_token(token_str: str, expected_type: str, expired_detail: str) -> None:
    """Verify HMAC signature, token type, and expiry of a signed token.
    Raises HTTPException(400) on invalid/tampered/wrong-type/expired token.
    Replay protection is done separately via DELETE-RETURNING in the DB.
    """
    parts = token_str.split(".")
    if len(parts) != 4:
        raise HTTPException(status_code=400, detail="Invalid token format")
    nonce, token_type, expiry_b64, provided_sig_b64 = parts
    if token_type != expected_type:
        raise HTTPException(status_code=400, detail="Invalid token")
    try:
        expiry_ts = struct.unpack(">I", base64.urlsafe_b64decode(expiry_b64 + "=="))[0]
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid token format")
    msg = f"{nonce}|{token_type}|{expiry_ts}".encode()
    expected_sig_bytes = hmac.new(TOKEN_SECRET.encode(), msg, hashlib.sha256).digest()
    try:
        provided_sig_bytes = base64.urlsafe_b64decode(provided_sig_b64 + "==")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid token format")
    if not hmac.compare_digest(expected_sig_bytes, provided_sig_bytes):
        raise HTTPException(status_code=400, detail="Invalid token")
    if expiry_ts <= int(_utc_now().timestamp()):
        raise HTTPException(status_code=400, detail=expired_detail)


def _db() -> psycopg.Connection:
    if not DATABASE_URL:
        raise HTTPException(status_code=500, detail="DATABASE_URL is not configured")
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


# def _smtp_is_configured() -> bool:
#     # SMTP transport is intentionally disabled; Brevo API is the only active provider.
#     return False


def _brevo_api_is_configured() -> bool:
    return bool(BREVO_API_KEY and SMTP_FROM_EMAIL)


def _email_is_configured() -> bool:
    # SMTP is disabled; treat Brevo API as the only valid provider.
    return _brevo_api_is_configured()


def _send_email(to_email: str, subject: str, text_body: str, html_body: Optional[str] = None) -> None:
    if EMAIL_DRY_RUN:
        print(f"[EMAIL_DRY_RUN] To: {to_email} | Subject: {subject}", flush=True)
        return
    provider = EMAIL_PROVIDER if EMAIL_PROVIDER in {"smtp", "brevo_api"} else "smtp"

    if provider != "brevo_api":
        raise HTTPException(status_code=503, detail="SMTP transport is disabled; set EMAIL_PROVIDER=brevo_api")

    if provider == "brevo_api":
        if not _brevo_api_is_configured():
            raise HTTPException(status_code=503, detail="Brevo API is not configured for emails")
        payload: dict[str, Any] = {
            "sender": {"email": SMTP_FROM_EMAIL},
            "to": [{"email": to_email}],
            "subject": subject,
            "textContent": text_body,
        }
        if html_body:
            payload["htmlContent"] = html_body
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "api-key": BREVO_API_KEY,
        }
        try:
            resp = requests.post(BREVO_API_URL, json=payload, headers=headers, timeout=20)
            if resp.status_code >= 400:
                detail = f"Brevo API send failed: HTTP {resp.status_code}"
                if resp.text:
                    detail = f"{detail} | {resp.text[:300]}"
                raise HTTPException(status_code=502, detail=detail)
            return
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=502, detail="Failed to deliver email via Brevo API") from exc

    # SMTP path intentionally disabled.
    raise HTTPException(status_code=503, detail="SMTP transport is disabled; set EMAIL_PROVIDER=brevo_api")


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


def _connection_pair(user_a: uuid.UUID, user_b: uuid.UUID) -> tuple[uuid.UUID, uuid.UUID]:
    if str(user_a) < str(user_b):
        return user_a, user_b
    return user_b, user_a


def _are_connected(cur: psycopg.Cursor, user_a: uuid.UUID, user_b: uuid.UUID) -> bool:
    low_id, high_id = _connection_pair(user_a, user_b)
    cur.execute(
        """
        SELECT 1
        FROM connections
        WHERE user_low_id = %s AND user_high_id = %s
        """,
        (low_id, high_id),
    )
    return cur.fetchone() is not None


def _require_group_member(cur: psycopg.Cursor, group_id: uuid.UUID, user_id: uuid.UUID) -> None:
    cur.execute(
        """
        SELECT 1
        FROM group_members
        WHERE group_id = %s AND user_id = %s
        """,
        (group_id, user_id),
    )
    if not cur.fetchone():
        raise HTTPException(status_code=403, detail="You must be a group member")


def _company_key_from_email(email: str) -> Optional[str]:
    parts = _normalize_email(email).split("@", 1)
    if len(parts) != 2:
        return None
    domain = parts[1].strip().lower()
    if not domain or "." not in domain:
        return None
    return domain


def _ensure_company_group_membership(
    cur: psycopg.Cursor,
    user_id: uuid.UUID,
    email: str,
    provider: str,
    provider_company_key: Optional[str] = None,
) -> None:
    normalized_provider = (provider or "").strip().lower()
    company_key = (provider_company_key or "").strip().lower() or _company_key_from_email(email)
    if not normalized_provider or not company_key:
        return

    cur.execute(
        """
        SELECT id
        FROM chat_groups
        WHERE group_type = 'company'
          AND sso_provider = %s
          AND company_key = %s
        LIMIT 1
        """,
        (normalized_provider, company_key),
    )
    row = cur.fetchone()
    if row:
        group_id = row["id"]
    else:
        group_id = uuid.uuid4()
        group_name = f"Company: {company_key}"
        cur.execute(
            """
            INSERT INTO chat_groups (id, name, created_by_user_id, group_type, company_key, sso_provider)
            VALUES (%s, %s, %s, 'company', %s, %s)
            """,
            (group_id, group_name, user_id, company_key, normalized_provider),
        )

    cur.execute(
        """
        INSERT INTO group_members (group_id, user_id)
        VALUES (%s, %s)
        ON CONFLICT (group_id, user_id) DO NOTHING
        """,
        (group_id, user_id),
    )


def _normalize_company_key(raw: str) -> str:
    value = (raw or "").strip().lower()
    if "@" in value:
        value = value.split("@", 1)[1]
    value = re.sub(r"[^a-z0-9._-]", "", value)
    return value[:160]


def _load_oidc_providers() -> dict[str, dict[str, Any]]:
    if not OIDC_PROVIDERS_JSON:
        return {}
    try:
        parsed = json.loads(OIDC_PROVIDERS_JSON)
    except Exception:
        return {}
    if not isinstance(parsed, dict):
        return {}

    providers: dict[str, dict[str, Any]] = {}
    for raw_key, cfg in parsed.items():
        key = _normalize_company_key(str(raw_key))
        if not key or not isinstance(cfg, dict):
            continue
        issuer = str(cfg.get("issuer", "")).strip().rstrip("/")
        client_id = str(cfg.get("client_id", "")).strip()
        client_secret = str(cfg.get("client_secret", ""))
        scope = str(cfg.get("scope", "openid profile email")).strip() or "openid profile email"
        if not issuer or not client_id or not client_secret:
            continue
        providers[key] = {
            "issuer": issuer,
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope,
        }
    return providers


def _discover_oidc_endpoints(issuer: str) -> dict[str, str]:
    url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    try:
        res = requests.get(url, timeout=15)
        res.raise_for_status()
        payload = res.json()
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Failed to load OIDC discovery document") from exc

    authorization_endpoint = payload.get("authorization_endpoint")
    token_endpoint = payload.get("token_endpoint")
    userinfo_endpoint = payload.get("userinfo_endpoint")
    if not authorization_endpoint or not token_endpoint or not userinfo_endpoint:
        raise HTTPException(status_code=502, detail="OIDC provider discovery is missing required endpoints")
    return {
        "authorization_endpoint": authorization_endpoint,
        "token_endpoint": token_endpoint,
        "userinfo_endpoint": userinfo_endpoint,
    }


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")


def _oauth_callback_base(request: Request) -> str:
    if PUBLIC_API_BASE_URL:
        return PUBLIC_API_BASE_URL
    return str(request.base_url).rstrip("/")


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
    raw_token = _make_signed_token(EMAIL_VERIFICATION_MINUTES, _TOKEN_TYPE_VERIFY)
    token_hash = _hash_token(raw_token)
    expires_at = _utc_now() + timedelta(minutes=EMAIL_VERIFICATION_MINUTES)
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
    raw_token = _make_signed_token(PASSWORD_RESET_MINUTES, _TOKEN_TYPE_RESET)
    token_hash = _hash_token(raw_token)
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


def _send_verification_email(email: str, verification_link: str, display_name: str = "") -> None:
    name = display_name.strip() or "there"
    text_body = (
        f"Dear {name},\n\n"
        "Welcome to Message Vault!\n\n"
        "Your account has been created. To verify your email address, click here:\n\n"
        f"  {verification_link}\n\n"
        "If you have problems with the above link, copy and paste it into your browser.\n\n"
        "If you did not create this account, you can safely ignore this email.\n\n"
        "Regards,\nThe TestProd Team"
    )
    html_body = f"""<!DOCTYPE html>
<html>
<body style="font-family:sans-serif;color:#222;max-width:520px;margin:0 auto;padding:24px">
  <p>Dear {name},</p>
  <p>Welcome to <strong>Message Vault</strong>!</p>
  <p>Your account has been created. To verify your email address, <a href="{verification_link}" style="color:#1d4ed8;font-weight:bold;font-size:17px">click here</a>.</p>
  <p style="color:#666;font-size:13px">If you have problems with the above link, copy and paste the URL below into your browser:<br>
    {verification_link}</p>
  <p style="color:#666;font-size:13px">If you did not create this account, you can safely ignore this email.</p>
  <hr style="border:none;border-top:1px solid #eee;margin:24px 0">
  <p style="color:#888;font-size:12px">Regards,<br>The TestProd Team</p>
</body>
</html>"""
    _send_email(
        to_email=email,
        subject="Verify your Message Vault account",
        text_body=text_body,
        html_body=html_body,
    )


def _send_reset_email(email: str, reset_link: str, display_name: str = "") -> None:
    name = display_name.strip() or "there"
    text_body = (
        f"Dear {name},\n\n"
        "We received a request to reset your Message Vault password.\n\n"
        "To set a new password, click here:\n\n"
        f"  {reset_link}\n\n"
        "If you have problems with the above link, copy and paste it into your browser.\n\n"
        "This link will expire in 15 minutes.\n\n"
        "If you did not request a password reset, you can safely ignore this email — your password will not change.\n\n"
        "Regards,\nThe TestProd Team"
    )
    html_body = f"""<!DOCTYPE html>
<html>
<body style="font-family:sans-serif;color:#222;max-width:520px;margin:0 auto;padding:24px">
  <p>Dear {name},</p>
  <p>We received a request to reset your <strong>Message Vault</strong> password.</p>
  <p>To set a new password, <a href="{reset_link}" style="color:#1d4ed8;font-weight:bold;font-size:17px">click here</a>.</p>
  <p style="color:#666;font-size:13px">If you have problems with the above link, copy and paste the URL below into your browser:<br>
    {reset_link}</p>
  <p style="color:#666;font-size:13px">This link will expire in <strong>15 minutes</strong>.<br>
  If you did not request a password reset, you can safely ignore this email — your password will not change.</p>
  <hr style="border:none;border-top:1px solid #eee;margin:24px 0">
  <p style="color:#888;font-size:12px">Regards,<br>The TestProd Team</p>
</body>
</html>"""
    _send_email(
        to_email=email,
        subject="Reset your Message Vault password",
        text_body=text_body,
        html_body=html_body,
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
                CREATE TABLE IF NOT EXISTS connection_requests (
                    id UUID PRIMARY KEY,
                    requester_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    recipient_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    responded_at TIMESTAMPTZ,
                    UNIQUE (requester_user_id, recipient_user_id)
                )
                """
            )
            cur.execute(
                "ALTER TABLE connection_requests DROP CONSTRAINT IF EXISTS connection_requests_status_check"
            )
            cur.execute(
                "ALTER TABLE connection_requests ADD CONSTRAINT connection_requests_status_check CHECK (status IN ('pending', 'accepted', 'declined'))"
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS connections (
                    user_low_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    user_high_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    PRIMARY KEY (user_low_id, user_high_id)
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS direct_messages (
                    id BIGSERIAL PRIMARY KEY,
                    sender_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    recipient_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    content TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_direct_messages_pair_time ON direct_messages (sender_user_id, recipient_user_id, created_at DESC)"
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS chat_groups (
                    id UUID PRIMARY KEY,
                    name TEXT NOT NULL,
                    created_by_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    group_type TEXT NOT NULL DEFAULT 'custom',
                    company_key TEXT,
                    sso_provider TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            cur.execute("ALTER TABLE chat_groups ADD COLUMN IF NOT EXISTS group_type TEXT NOT NULL DEFAULT 'custom'")
            cur.execute("ALTER TABLE chat_groups ADD COLUMN IF NOT EXISTS company_key TEXT")
            cur.execute("ALTER TABLE chat_groups ADD COLUMN IF NOT EXISTS sso_provider TEXT")
            cur.execute("ALTER TABLE chat_groups DROP CONSTRAINT IF EXISTS chat_groups_group_type_check")
            cur.execute(
                "ALTER TABLE chat_groups ADD CONSTRAINT chat_groups_group_type_check CHECK (group_type IN ('custom', 'company'))"
            )
            cur.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_chat_groups_company_unique ON chat_groups (sso_provider, company_key) WHERE group_type = 'company'"
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS group_members (
                    group_id UUID NOT NULL REFERENCES chat_groups(id) ON DELETE CASCADE,
                    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    PRIMARY KEY (group_id, user_id)
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS group_messages (
                    id BIGSERIAL PRIMARY KEY,
                    group_id UUID NOT NULL REFERENCES chat_groups(id) ON DELETE CASCADE,
                    sender_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    content TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_group_messages_group_time ON group_messages (group_id, created_at DESC)"
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
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS email_verification_rate_limit (
                    id UUID PRIMARY KEY,
                    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_evrl_user_requested
                ON email_verification_rate_limit(user_id, requested_at)
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

    # Start background cleanup thread
    t = threading.Thread(target=_token_cleanup_loop, daemon=True)
    t.start()


_CLEANUP_LOCAL_TZ = ZoneInfo("Australia/Sydney")
_CLEANUP_HOUR_LOCAL = 3
_CLEANUP_MINUTE_LOCAL = 0


def _seconds_until_next_daily_cleanup(now_utc: Optional[datetime] = None) -> float:
    current_utc = now_utc or datetime.now(timezone.utc)
    current_local = current_utc.astimezone(_CLEANUP_LOCAL_TZ)
    next_local = current_local.replace(
        hour=_CLEANUP_HOUR_LOCAL,
        minute=_CLEANUP_MINUTE_LOCAL,
        second=0,
        microsecond=0,
    )
    if current_local >= next_local:
        next_local += timedelta(days=1)
    next_utc = next_local.astimezone(timezone.utc)
    return max(1.0, (next_utc - current_utc).total_seconds())


def _token_cleanup_loop() -> None:
    """Daemon thread: daily cleanup at 03:00 Australia/Sydney, single pass."""
    while True:
        sleep_seconds = _seconds_until_next_daily_cleanup()
        next_local = (datetime.now(timezone.utc) + timedelta(seconds=sleep_seconds)).astimezone(_CLEANUP_LOCAL_TZ)
        print(f"[cleanup] next scheduled run at {next_local.isoformat()} (Australia/Sydney)")
        time.sleep(sleep_seconds)

        try:
            _purge_expired_tokens()
        except Exception as exc:  # noqa: BLE001
            print(f"[cleanup] error during token purge: {exc}")


def _purge_expired_tokens() -> None:
    now = datetime.now(timezone.utc)
    with _db() as conn:
        with conn.cursor() as cur:
            # Purge all verification tokens on each scheduled cleanup run.
            cur.execute("DELETE FROM email_verification_tokens")
            vt_deleted = cur.rowcount

            # Purge all password reset tokens on each scheduled cleanup run.
            cur.execute("DELETE FROM password_reset_tokens")
            rt_deleted = cur.rowcount

            # Expired sessions
            cur.execute("DELETE FROM sessions WHERE expires_at < %s", (now,))
            sess_deleted = cur.rowcount

            # Rate-limit rows older than 24 h (no longer affect today's quota)
            cur.execute(
                "DELETE FROM email_verification_rate_limit WHERE requested_at < %s",
                (now - timedelta(hours=24),),
            )
            rl_deleted = cur.rowcount

        conn.commit()
    print(
        f"[cleanup] purged: verification_tokens={vt_deleted}, reset_tokens={rt_deleted}, "
        f"sessions={sess_deleted}, rate_limit_rows={rl_deleted}"
    )


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "api",
        "database_url_set": bool(DATABASE_URL),
        "google_client_id_set": bool(GOOGLE_CLIENT_ID),
        "github_sso_configured": bool(GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET),
        "oidc_provider_count": len(_load_oidc_providers()),
        "rbac_enabled": True,
        "email_provider": EMAIL_PROVIDER if EMAIL_PROVIDER in {"smtp", "brevo_api"} else "smtp",
        "email_configured": _email_is_configured(),
        "smtp_configured": False,
    }


@app.get("/auth/sso/oidc/start")
def auth_sso_oidc_start(
    company: str,
    request: Request,
    intent: str = "login",
    display_name: Optional[str] = None,
    tos_accepted: bool = False,
) -> RedirectResponse:
    intent_value = (intent or "login").strip().lower()
    if intent_value not in {"login", "register"}:
        raise HTTPException(status_code=400, detail="Invalid SSO intent")
    signup_display_name = (display_name or "").strip()[:120]
    if intent_value == "register" and not signup_display_name:
        raise HTTPException(status_code=400, detail="Display name is required for SSO signup")
    if intent_value == "register" and not tos_accepted:
        raise HTTPException(status_code=400, detail="Terms of Service acceptance is required for SSO signup")

    company_key = _normalize_company_key(company)
    providers = _load_oidc_providers()
    provider_key = company_key
    config = providers.get(provider_key)
    if not config and len(providers) == 1:
        provider_key, config = next(iter(providers.items()))
    if not config:
        raise HTTPException(status_code=404, detail="No SSO provider configured for this company")

    endpoints = _discover_oidc_endpoints(config["issuer"])
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    redirect_uri = f"{_oauth_callback_base(request)}/auth/sso/oidc/callback"
    params = urlencode(
        {
            "response_type": "code",
            "client_id": config["client_id"],
            "redirect_uri": redirect_uri,
            "scope": config["scope"],
            "state": state,
            "code_challenge": _pkce_challenge(verifier),
            "code_challenge_method": "S256",
        }
    )
    response = RedirectResponse(url=f"{endpoints['authorization_endpoint']}?{params}", status_code=302)
    response.set_cookie(
        key=SSO_STATE_COOKIE_NAME,
        value=state,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=10 * 60,
        path="/",
    )
    response.set_cookie(
        key=SSO_COMPANY_COOKIE_NAME,
        value=company_key,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=10 * 60,
        path="/",
    )
    response.set_cookie(
        key=SSO_PROVIDER_COOKIE_NAME,
        value=provider_key,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=10 * 60,
        path="/",
    )
    response.set_cookie(
        key=SSO_PKCE_COOKIE_NAME,
        value=verifier,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=10 * 60,
        path="/",
    )
    response.set_cookie(
        key=SSO_INTENT_COOKIE_NAME,
        value=intent_value,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=10 * 60,
        path="/",
    )
    if intent_value == "register":
        response.set_cookie(
            key=SSO_DISPLAY_NAME_COOKIE_NAME,
            value=signup_display_name,
            httponly=True,
            secure=COOKIE_SECURE,
            samesite="lax",
            max_age=10 * 60,
            path="/",
        )
        response.set_cookie(
            key=SSO_TOS_ACCEPTED_COOKIE_NAME,
            value="1",
            httponly=True,
            secure=COOKIE_SECURE,
            samesite="lax",
            max_age=10 * 60,
            path="/",
        )
    return response


@app.get("/auth/sso/oidc/callback")
def auth_sso_oidc_callback(
    code: str,
    state: str,
    request: Request,
    sso_state: Optional[str] = Cookie(default=None, alias=SSO_STATE_COOKIE_NAME),
    sso_company: Optional[str] = Cookie(default=None, alias=SSO_COMPANY_COOKIE_NAME),
    sso_provider_key: Optional[str] = Cookie(default=None, alias=SSO_PROVIDER_COOKIE_NAME),
    sso_pkce_verifier: Optional[str] = Cookie(default=None, alias=SSO_PKCE_COOKIE_NAME),
    sso_intent: Optional[str] = Cookie(default=None, alias=SSO_INTENT_COOKIE_NAME),
    sso_display_name: Optional[str] = Cookie(default=None, alias=SSO_DISPLAY_NAME_COOKIE_NAME),
    sso_tos_accepted: Optional[str] = Cookie(default=None, alias=SSO_TOS_ACCEPTED_COOKIE_NAME),
    user_agent: Optional[str] = Header(default=None),
) -> RedirectResponse:
    if not sso_state or not secrets.compare_digest(state, sso_state):
        raise HTTPException(status_code=400, detail="Invalid SSO state")
    if not sso_company or not sso_pkce_verifier:
        raise HTTPException(status_code=400, detail="Missing SSO session context")

    providers = _load_oidc_providers()
    company_key = _normalize_company_key(sso_company)
    provider_key = _normalize_company_key(sso_provider_key or sso_company)
    config = providers.get(provider_key)
    if not config:
        raise HTTPException(status_code=404, detail="No SSO provider configured for this company")

    endpoints = _discover_oidc_endpoints(config["issuer"])
    redirect_uri = f"{_oauth_callback_base(request)}/auth/sso/oidc/callback"

    try:
        token_res = requests.post(
            endpoints["token_endpoint"],
            headers={"Accept": "application/json"},
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": config["client_id"],
                "client_secret": config["client_secret"],
                "code_verifier": sso_pkce_verifier,
            },
            timeout=20,
        )
        token_res.raise_for_status()
        token_payload = token_res.json()
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Failed to exchange OIDC authorization code") from exc

    access_token = token_payload.get("access_token")
    if not access_token:
        raise HTTPException(status_code=401, detail="Invalid OIDC token response")

    try:
        userinfo_res = requests.get(
            endpoints["userinfo_endpoint"],
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {access_token}",
            },
            timeout=20,
        )
        userinfo_res.raise_for_status()
        userinfo = userinfo_res.json()
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Failed to fetch OIDC user profile") from exc

    email = _normalize_email(str(userinfo.get("email") or ""))
    raw_email_verified = userinfo.get("email_verified", False)
    email_verified = raw_email_verified is True or str(raw_email_verified).lower() == "true"
    if not email:
        raise HTTPException(status_code=401, detail="SSO account must provide an email")
    if not email_verified:
        raise HTTPException(status_code=401, detail="SSO email must be verified")

    intent_value = (sso_intent or "login").strip().lower()
    if intent_value not in {"login", "register"}:
        raise HTTPException(status_code=400, detail="Invalid SSO intent")
    if intent_value == "register" and sso_tos_accepted != "1":
        raise HTTPException(status_code=400, detail="Terms of Service acceptance is required for SSO signup")

    provider_display_name = str(userinfo.get("name") or userinfo.get("preferred_username") or email).strip()[:120]
    signup_display_name = (sso_display_name or "").strip()[:120]
    chosen_display_name = signup_display_name if intent_value == "register" else provider_display_name
    if intent_value == "register" and not chosen_display_name:
        raise HTTPException(status_code=400, detail="Display name is required for SSO signup")

    picture_url = userinfo.get("picture")
    created_via_sso_signup = False

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
                    SET picture_url = %s, last_login_at = NOW(), email_verified = TRUE
                    WHERE id = %s
                    """,
                    (picture_url, user_id),
                )
            else:
                user_id = uuid.uuid4()
                created_via_sso_signup = True
                cur.execute(
                    """
                    INSERT INTO users (id, email, display_name, picture_url, last_login_at, email_verified)
                    VALUES (%s, %s, %s, %s, NOW(), TRUE)
                    """,
                    (user_id, email, chosen_display_name, picture_url),
                )
                _insert_security_event(cur, user_id, "user_created", {"source": "oidc_sso", "company": company_key})

            cur.execute(
                """
                INSERT INTO user_security_profiles (
                    user_id, auth_provider, password_login_enabled, mfa_required, requirements_version
                )
                VALUES (%s, 'oidc', FALSE, FALSE, 'v1')
                ON CONFLICT (user_id) DO UPDATE
                SET auth_provider = CASE
                    WHEN user_security_profiles.password_login_enabled THEN 'oidc+password'
                    ELSE 'oidc'
                END,
                    updated_at = NOW()
                """,
                (user_id,),
            )

            if created_via_sso_signup:
                _ensure_company_group_membership(
                    cur,
                    user_id,
                    email,
                    provider="oidc",
                    provider_company_key=company_key,
                )

            raw_session_token = _create_session(
                cur,
                user_id,
                user_agent,
                _client_ip(request),
            )
            _insert_security_event(cur, user_id, "login_success", {"provider": "oidc", "company": company_key})
        conn.commit()

    redirect = RedirectResponse(url=WEB_ORIGIN, status_code=302)
    _set_auth_cookie(redirect, raw_session_token)
    redirect.delete_cookie(key=SSO_STATE_COOKIE_NAME, path="/")
    redirect.delete_cookie(key=SSO_COMPANY_COOKIE_NAME, path="/")
    redirect.delete_cookie(key=SSO_PROVIDER_COOKIE_NAME, path="/")
    redirect.delete_cookie(key=SSO_PKCE_COOKIE_NAME, path="/")
    redirect.delete_cookie(key=SSO_INTENT_COOKIE_NAME, path="/")
    redirect.delete_cookie(key=SSO_DISPLAY_NAME_COOKIE_NAME, path="/")
    redirect.delete_cookie(key=SSO_TOS_ACCEPTED_COOKIE_NAME, path="/")
    return redirect


@app.get("/auth/sso/github/start")
def auth_sso_github_start(request: Request) -> RedirectResponse:
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="GitHub SSO is not configured",
        )

    state = secrets.token_urlsafe(32)
    redirect_uri = f"{_oauth_callback_base(request)}/auth/sso/github/callback"
    params = urlencode(
        {
            "client_id": GITHUB_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "scope": "read:user user:email",
            "state": state,
        }
    )
    response = RedirectResponse(url=f"https://github.com/login/oauth/authorize?{params}", status_code=302)
    response.set_cookie(
        key=SSO_STATE_COOKIE_NAME,
        value=state,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=10 * 60,
        path="/",
    )
    return response


@app.get("/auth/sso/github/callback")
def auth_sso_github_callback(
    code: str,
    state: str,
    request: Request,
    sso_state: Optional[str] = Cookie(default=None, alias=SSO_STATE_COOKIE_NAME),
    user_agent: Optional[str] = Header(default=None),
) -> RedirectResponse:
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="GitHub SSO is not configured",
        )
    if not sso_state or not secrets.compare_digest(state, sso_state):
        raise HTTPException(status_code=400, detail="Invalid SSO state")

    redirect_uri = f"{_oauth_callback_base(request)}/auth/sso/github/callback"
    try:
        token_res = requests.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": redirect_uri,
                "state": state,
            },
            timeout=15,
        )
        token_res.raise_for_status()
        token_payload = token_res.json()
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Failed to exchange GitHub OAuth code") from exc

    access_token = token_payload.get("access_token")
    if not access_token:
        raise HTTPException(status_code=401, detail="Invalid GitHub OAuth response")

    try:
        profile_res = requests.get(
            "https://api.github.com/user",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {access_token}",
            },
            timeout=15,
        )
        profile_res.raise_for_status()
        profile = profile_res.json()

        emails_res = requests.get(
            "https://api.github.com/user/emails",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {access_token}",
            },
            timeout=15,
        )
        emails_res.raise_for_status()
        emails_payload = emails_res.json()
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Failed to fetch GitHub profile") from exc

    selected_email = None
    if isinstance(emails_payload, list):
        for item in emails_payload:
            if item.get("primary") and item.get("verified") and item.get("email"):
                selected_email = item["email"]
                break
        if not selected_email:
            for item in emails_payload:
                if item.get("verified") and item.get("email"):
                    selected_email = item["email"]
                    break

    email = _normalize_email(selected_email or "")
    if not email:
        raise HTTPException(status_code=401, detail="GitHub account must expose a verified email")

    display_name = (profile.get("name") or profile.get("login") or email).strip()[:120]
    picture_url = profile.get("avatar_url")
    created_via_sso_signup = False

    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, is_banned FROM users WHERE email = %s", (email,))
            existing = cur.fetchone()

            if existing:
                if intent_value == "register":
                    raise HTTPException(status_code=409, detail="Account already exists. Please sign in instead.")
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
                user_id = uuid.uuid4()
                cur.execute(
                    """
                    INSERT INTO users (id, email, display_name, picture_url, last_login_at, email_verified)
                    VALUES (%s, %s, %s, %s, NOW(), TRUE)
                    """,
                    (user_id, email, display_name, picture_url),
                )
                _insert_security_event(cur, user_id, "user_created", {"source": "github_sso"})

            cur.execute(
                """
                INSERT INTO user_security_profiles (
                    user_id, auth_provider, password_login_enabled, mfa_required, requirements_version
                )
                VALUES (%s, 'github', FALSE, FALSE, 'v1')
                ON CONFLICT (user_id) DO UPDATE
                SET auth_provider = CASE
                    WHEN user_security_profiles.password_login_enabled THEN 'github+password'
                    ELSE 'github'
                END,
                    updated_at = NOW()
                """,
                (user_id,),
            )

            raw_session_token = _create_session(
                cur,
                user_id,
                user_agent,
                _client_ip(request),
            )
            _insert_security_event(cur, user_id, "login_success", {"provider": "github"})
        conn.commit()

    redirect = RedirectResponse(url=WEB_ORIGIN, status_code=302)
    _set_auth_cookie(redirect, raw_session_token)
    redirect.delete_cookie(key=SSO_STATE_COOKIE_NAME, path="/")
    return redirect


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
    intent_value = (payload.intent or "login").strip().lower()
    if intent_value not in {"login", "register"}:
        raise HTTPException(status_code=400, detail="Invalid Google auth intent")

    provider_display_name = (token_info.get("name") or email or "").strip()[:120]
    chosen_display_name = (payload.display_name or "").strip()[:120] if intent_value == "register" else provider_display_name
    if intent_value == "register" and not chosen_display_name:
        raise HTTPException(status_code=400, detail="Display name is required for Google signup")
    if intent_value == "register" and not payload.tos_accepted:
        raise HTTPException(status_code=400, detail="Terms of Service acceptance is required for Google signup")

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
                    SET picture_url = %s, last_login_at = NOW(), email_verified = TRUE
                    WHERE id = %s
                    """,
                    (picture_url, user_id),
                )
            else:
                if intent_value != "register":
                    raise HTTPException(
                        status_code=404,
                        detail="No account found. Please create an account first.",
                    )
                new_user = True
                user_id = uuid.uuid4()
                cur.execute(
                    """
                    INSERT INTO users (id, email, display_name, picture_url, last_login_at)
                    VALUES (%s, %s, %s, %s, NOW())
                    """,
                    (user_id, email, chosen_display_name, picture_url),
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
        try:
            _send_verification_email(email, verification_link, display_name)
        except Exception:
            pass  # Email delivery failure is non-fatal; user can resend from login page

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
    _verify_signed_token(payload.token, _TOKEN_TYPE_VERIFY, "Verification token expired or already used")
    token_hash = _hash_token(payload.token)
    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM email_verification_tokens WHERE token_hash = %s RETURNING user_id",
                (token_hash,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=400, detail="Verification token expired or already used")
            user_id = row["user_id"]
            cur.execute("UPDATE users SET email_verified = TRUE WHERE id = %s", (user_id,))
            _insert_security_event(cur, user_id, "email_verified", {"method": "token"})
        conn.commit()
    return {"status": "ok"}


@app.post("/auth/resend-verification")
def auth_resend_verification(payload: VerificationRequest) -> Any:
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

            user_id = row["id"]

            # Rate limit: max 3 requests per rolling 24 hours.
            # After the 2nd request a 5-minute cooldown applies before the 3rd.
            cur.execute(
                """
                SELECT requested_at FROM email_verification_rate_limit
                WHERE user_id = %s AND requested_at > NOW() - INTERVAL '24 hours'
                ORDER BY requested_at ASC
                """,
                (user_id,),
            )
            recent = cur.fetchall()
            count = len(recent)

            if count >= 3:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Daily limit of 3 verification emails reached. Try again tomorrow."},
                )

            if count >= 2:
                most_recent_ts = recent[-1]["requested_at"]
                seconds_since = (_utc_now() - most_recent_ts).total_seconds()
                cooldown = 300  # 5 minutes
                if seconds_since < cooldown:
                    retry_after = int(cooldown - seconds_since) + 1
                    return JSONResponse(
                        status_code=429,
                        content={
                            "detail": "Please wait before requesting another verification email.",
                            "retry_after": retry_after,
                        },
                        headers={"Retry-After": str(retry_after)},
                    )

            cur.execute(
                "INSERT INTO email_verification_rate_limit (id, user_id) VALUES (%s, %s)",
                (uuid.uuid4(), user_id),
            )
            raw_verification_token, _ = _issue_email_verification_token(cur, user_id)
            verification_link = f"{APP_BASE_URL}/verify.html?token={raw_verification_token}"
            cur.execute("SELECT display_name FROM users WHERE id = %s", (user_id,))
            dn_row = cur.fetchone()
            display_name = dn_row["display_name"] if dn_row else ""
            _insert_security_event(cur, user_id, "email_verification_sent", {"channel": "app_link"})
        conn.commit()

    try:
        _send_verification_email(email, verification_link, display_name)
    except Exception:
        pass  # Non-fatal; token is saved, user can retry
    return {"status": "ok"}


@app.post("/auth/password-reset/request")
def auth_password_reset_request(payload: VerificationRequest) -> dict[str, Any]:
    email = _normalize_email(payload.email)
    _validate_email(email)
    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT u.id, u.display_name
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
            display_name = row["display_name"] or ""
            _insert_security_event(cur, row["id"], "password_reset_requested", {"channel": "app_link"})
        conn.commit()

    try:
        _send_reset_email(email, reset_link, display_name)
    except Exception:
        pass  # Non-fatal; token is saved, client should display the link or prompt retry
    return {"status": "ok"}


@app.post("/auth/password-reset/confirm")
def auth_password_reset_confirm(payload: PasswordResetConfirmRequest) -> dict[str, str]:
    _validate_password_strength(payload.new_password)
    _verify_signed_token(payload.token, _TOKEN_TYPE_RESET, "Reset token expired or already used")
    token_hash = _hash_token(payload.token)

    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM password_reset_tokens WHERE token_hash = %s RETURNING user_id",
                (token_hash,),
            )
            row = cur.fetchone()
            if not row:
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


@app.get("/users/search")
def search_users(
    q: str,
    limit: int = 20,
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> dict[str, Any]:
    user = _require_user(session_token)
    query = (q or "").strip().lower()
    if len(query) < 2:
        return {"users": []}
    safe_limit = max(1, min(limit, 50))
    pattern = f"%{query}%"
    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, email, display_name, picture_url
                FROM users
                WHERE id <> %s
                  AND is_banned = FALSE
                  AND (
                    LOWER(email) LIKE %s
                    OR LOWER(display_name) LIKE %s
                  )
                ORDER BY display_name ASC, email ASC
                LIMIT %s
                """,
                (user["id"], pattern, pattern, safe_limit),
            )
            rows = cur.fetchall()
    return {
        "users": [
            {
                "id": str(row["id"]),
                "email": row["email"],
                "display_name": row["display_name"],
                "picture_url": row["picture_url"],
            }
            for row in rows
        ]
    }


@app.post("/connections/request")
def create_connection_request(
    payload: ConnectionRequestCreateRequest,
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> dict[str, Any]:
    user = _require_user(session_token)
    try:
        requester_id = _to_uuid(user["id"])
        target_id = _to_uuid(payload.target_user_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid user_id") from exc

    if requester_id == target_id:
        raise HTTPException(status_code=400, detail="You cannot connect with yourself")

    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, is_banned FROM users WHERE id = %s", (target_id,))
            target = cur.fetchone()
            if not target:
                raise HTTPException(status_code=404, detail="User not found")
            if target.get("is_banned"):
                raise HTTPException(status_code=400, detail="Cannot connect with banned user")

            if _are_connected(cur, requester_id, target_id):
                return {"status": "ok", "already_connected": True}

            cur.execute(
                """
                SELECT id, requester_user_id, recipient_user_id, status
                FROM connection_requests
                WHERE (
                    requester_user_id = %s AND recipient_user_id = %s
                ) OR (
                    requester_user_id = %s AND recipient_user_id = %s
                )
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (requester_id, target_id, target_id, requester_id),
            )
            existing = cur.fetchone()
            if existing and existing["status"] == "pending":
                return {
                    "status": "ok",
                    "pending": True,
                    "direction": (
                        "outgoing"
                        if str(existing["requester_user_id"]) == str(requester_id)
                        else "incoming"
                    ),
                }

            cur.execute(
                """
                INSERT INTO connection_requests (id, requester_user_id, recipient_user_id, status, responded_at)
                VALUES (%s, %s, %s, 'pending', NULL)
                ON CONFLICT (requester_user_id, recipient_user_id) DO UPDATE
                SET status = 'pending',
                    responded_at = NULL,
                    created_at = NOW()
                """,
                (uuid.uuid4(), requester_id, target_id),
            )
        conn.commit()
    return {"status": "ok", "pending": True}


@app.get("/connections/requests")
def list_connection_requests(
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> dict[str, Any]:
    user = _require_user(session_token)
    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT cr.requester_user_id, u.display_name, u.email, u.picture_url, cr.created_at
                FROM connection_requests cr
                JOIN users u ON u.id = cr.requester_user_id
                WHERE cr.recipient_user_id = %s
                  AND cr.status = 'pending'
                ORDER BY cr.created_at DESC
                LIMIT 100
                """,
                (user["id"],),
            )
            incoming_rows = cur.fetchall()

            cur.execute(
                """
                SELECT cr.recipient_user_id, u.display_name, u.email, u.picture_url, cr.created_at
                FROM connection_requests cr
                JOIN users u ON u.id = cr.recipient_user_id
                WHERE cr.requester_user_id = %s
                  AND cr.status = 'pending'
                ORDER BY cr.created_at DESC
                LIMIT 100
                """,
                (user["id"],),
            )
            outgoing_rows = cur.fetchall()

    return {
        "incoming": [
            {
                "user_id": str(row["requester_user_id"]),
                "display_name": row["display_name"],
                "email": row["email"],
                "picture_url": row["picture_url"],
                "created_at": row["created_at"].isoformat(),
            }
            for row in incoming_rows
        ],
        "outgoing": [
            {
                "user_id": str(row["recipient_user_id"]),
                "display_name": row["display_name"],
                "email": row["email"],
                "picture_url": row["picture_url"],
                "created_at": row["created_at"].isoformat(),
            }
            for row in outgoing_rows
        ],
    }


@app.post("/connections/requests/accept")
def accept_connection_request(
    payload: ConnectionRequestActionRequest,
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> dict[str, Any]:
    user = _require_user(session_token)
    try:
        recipient_id = _to_uuid(user["id"])
        requester_id = _to_uuid(payload.requester_user_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid user_id") from exc

    if recipient_id == requester_id:
        raise HTTPException(status_code=400, detail="Invalid requester")

    low_id, high_id = _connection_pair(recipient_id, requester_id)
    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id
                FROM connection_requests
                WHERE requester_user_id = %s
                  AND recipient_user_id = %s
                  AND status = 'pending'
                """,
                (requester_id, recipient_id),
            )
            pending = cur.fetchone()
            if not pending:
                raise HTTPException(status_code=404, detail="Pending request not found")

            cur.execute(
                """
                UPDATE connection_requests
                SET status = 'accepted', responded_at = NOW()
                WHERE requester_user_id = %s
                  AND recipient_user_id = %s
                  AND status = 'pending'
                """,
                (requester_id, recipient_id),
            )
            cur.execute(
                """
                INSERT INTO connections (user_low_id, user_high_id)
                VALUES (%s, %s)
                ON CONFLICT (user_low_id, user_high_id) DO NOTHING
                """,
                (low_id, high_id),
            )
        conn.commit()
    return {"status": "ok", "connected": True}


@app.post("/connections/requests/decline")
def decline_connection_request(
    payload: ConnectionRequestActionRequest,
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> dict[str, Any]:
    user = _require_user(session_token)
    try:
        recipient_id = _to_uuid(user["id"])
        requester_id = _to_uuid(payload.requester_user_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid user_id") from exc

    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE connection_requests
                SET status = 'declined', responded_at = NOW()
                WHERE requester_user_id = %s
                  AND recipient_user_id = %s
                  AND status = 'pending'
                """,
                (requester_id, recipient_id),
            )
        conn.commit()
    return {"status": "ok"}


@app.get("/connections")
def list_connections(
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> dict[str, Any]:
    user = _require_user(session_token)
    user_id = _to_uuid(user["id"])
    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    CASE
                        WHEN c.user_low_id = %s THEN c.user_high_id
                        ELSE c.user_low_id
                    END AS connection_user_id,
                    c.created_at
                FROM connections c
                WHERE c.user_low_id = %s OR c.user_high_id = %s
                ORDER BY c.created_at DESC
                """,
                (user_id, user_id, user_id),
            )
            raw_connections = cur.fetchall()
            connection_ids = [row["connection_user_id"] for row in raw_connections]
            if not connection_ids:
                return {"connections": []}

            cur.execute(
                """
                SELECT id, display_name, email, picture_url, is_banned
                FROM users
                WHERE id = ANY(%s)
                """,
                (connection_ids,),
            )
            profile_rows = cur.fetchall()

    profile_map = {str(row["id"]): row for row in profile_rows if not row.get("is_banned")}
    return {
        "connections": [
            {
                "user_id": str(row["connection_user_id"]),
                "display_name": profile_map[str(row["connection_user_id"])]["display_name"],
                "email": profile_map[str(row["connection_user_id"])]["email"],
                "picture_url": profile_map[str(row["connection_user_id"])]["picture_url"],
                "connected_at": row["created_at"].isoformat(),
            }
            for row in raw_connections
            if str(row["connection_user_id"]) in profile_map
        ]
    }


@app.get("/connections/messages/{other_user_id}")
def list_connection_messages(
    other_user_id: str,
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> dict[str, Any]:
    user = _require_user(session_token)
    try:
        user_id = _to_uuid(user["id"])
        peer_id = _to_uuid(other_user_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid user_id") from exc

    with _db() as conn:
        with conn.cursor() as cur:
            if not _are_connected(cur, user_id, peer_id):
                raise HTTPException(status_code=403, detail="You can only message accepted connections")
            cur.execute(
                """
                SELECT id, sender_user_id, recipient_user_id, content, created_at
                FROM direct_messages
                WHERE (
                    sender_user_id = %s AND recipient_user_id = %s
                ) OR (
                    sender_user_id = %s AND recipient_user_id = %s
                )
                ORDER BY created_at DESC
                LIMIT 200
                """,
                (user_id, peer_id, peer_id, user_id),
            )
            rows = cur.fetchall()

    rows.reverse()
    return {
        "messages": [
            {
                "id": row["id"],
                "sender_user_id": str(row["sender_user_id"]),
                "recipient_user_id": str(row["recipient_user_id"]),
                "content": row["content"],
                "created_at": row["created_at"].isoformat(),
            }
            for row in rows
        ]
    }


@app.post("/connections/messages")
def create_connection_message(
    payload: ConnectionMessageCreateRequest,
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> dict[str, Any]:
    user = _require_user(session_token)
    try:
        sender_id = _to_uuid(user["id"])
        recipient_id = _to_uuid(payload.recipient_user_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid user_id") from exc

    if sender_id == recipient_id:
        raise HTTPException(status_code=400, detail="Cannot send message to yourself")

    with _db() as conn:
        with conn.cursor() as cur:
            if not _are_connected(cur, sender_id, recipient_id):
                raise HTTPException(status_code=403, detail="You can only message accepted connections")
            cur.execute(
                """
                INSERT INTO direct_messages (sender_user_id, recipient_user_id, content)
                VALUES (%s, %s, %s)
                RETURNING id, sender_user_id, recipient_user_id, content, created_at
                """,
                (sender_id, recipient_id, payload.content.strip()),
            )
            row = cur.fetchone()
        conn.commit()

    return {
        "id": row["id"],
        "sender_user_id": str(row["sender_user_id"]),
        "recipient_user_id": str(row["recipient_user_id"]),
        "content": row["content"],
        "created_at": row["created_at"].isoformat(),
    }


@app.post("/groups")
def create_group(
    payload: GroupCreateRequest,
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> dict[str, Any]:
    user = _require_user(session_token)
    creator_id = _to_uuid(user["id"])
    group_name = payload.name.strip()
    if len(group_name) < 2:
        raise HTTPException(status_code=400, detail="Group name is too short")

    group_id = uuid.uuid4()
    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO chat_groups (id, name, created_by_user_id)
                VALUES (%s, %s, %s)
                """,
                (group_id, group_name, creator_id),
            )
            cur.execute(
                """
                INSERT INTO group_members (group_id, user_id)
                VALUES (%s, %s)
                ON CONFLICT (group_id, user_id) DO NOTHING
                """,
                (group_id, creator_id),
            )
        conn.commit()

    return {
        "status": "ok",
        "group": {
            "id": str(group_id),
            "name": group_name,
        },
    }


@app.get("/groups")
def list_groups(
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> dict[str, Any]:
    user = _require_user(session_token)
    user_id = _to_uuid(user["id"])
    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT g.id, g.name, g.created_by_user_id, g.group_type, g.company_key, g.sso_provider, g.created_at
                FROM group_members gm
                JOIN chat_groups g ON g.id = gm.group_id
                WHERE gm.user_id = %s
                ORDER BY g.created_at DESC
                """,
                (user_id,),
            )
            rows = cur.fetchall()
    return {
        "groups": [
            {
                "id": str(row["id"]),
                "name": row["name"],
                "created_by_user_id": str(row["created_by_user_id"]),
                "group_type": row["group_type"],
                "company_key": row["company_key"],
                "sso_provider": row["sso_provider"],
                "created_at": row["created_at"].isoformat(),
            }
            for row in rows
        ]
    }


@app.delete("/groups/{group_id}/members/me")
def leave_group(
    group_id: str,
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> dict[str, Any]:
    user = _require_user(session_token)
    try:
        user_id = _to_uuid(user["id"])
        safe_group_id = _to_uuid(group_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid id") from exc

    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM group_members
                WHERE group_id = %s AND user_id = %s
                RETURNING group_id
                """,
                (safe_group_id, user_id),
            )
            deleted = cur.fetchone()
            if not deleted:
                raise HTTPException(status_code=404, detail="You are not a member of this group")
        conn.commit()

    return {"status": "ok"}


@app.post("/groups/{group_id}/members")
def add_group_member(
    group_id: str,
    payload: GroupAddMemberRequest,
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> dict[str, Any]:
    user = _require_user(session_token)
    try:
        actor_id = _to_uuid(user["id"])
        safe_group_id = _to_uuid(group_id)
        target_id = _to_uuid(payload.user_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid id") from exc

    if actor_id == target_id:
        raise HTTPException(status_code=400, detail="You are already in the group")

    with _db() as conn:
        with conn.cursor() as cur:
            _require_group_member(cur, safe_group_id, actor_id)

            cur.execute("SELECT id, is_banned FROM users WHERE id = %s", (target_id,))
            target = cur.fetchone()
            if not target:
                raise HTTPException(status_code=404, detail="User not found")
            if target.get("is_banned"):
                raise HTTPException(status_code=400, detail="Cannot add banned user")

            # Group adds are limited to accepted connections.
            if not _are_connected(cur, actor_id, target_id):
                raise HTTPException(status_code=403, detail="You can only add your accepted connections")

            cur.execute(
                """
                INSERT INTO group_members (group_id, user_id)
                VALUES (%s, %s)
                ON CONFLICT (group_id, user_id) DO NOTHING
                """,
                (safe_group_id, target_id),
            )
        conn.commit()

    return {"status": "ok"}


@app.get("/groups/{group_id}/messages")
def list_group_messages(
    group_id: str,
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> dict[str, Any]:
    user = _require_user(session_token)
    try:
        user_id = _to_uuid(user["id"])
        safe_group_id = _to_uuid(group_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid id") from exc

    with _db() as conn:
        with conn.cursor() as cur:
            _require_group_member(cur, safe_group_id, user_id)
            cur.execute(
                """
                SELECT gm.id, gm.sender_user_id, u.display_name, gm.content, gm.created_at
                FROM group_messages gm
                JOIN users u ON u.id = gm.sender_user_id
                WHERE gm.group_id = %s
                ORDER BY gm.created_at DESC
                LIMIT 200
                """,
                (safe_group_id,),
            )
            rows = cur.fetchall()

    rows.reverse()
    return {
        "messages": [
            {
                "id": row["id"],
                "sender_user_id": str(row["sender_user_id"]),
                "sender_display_name": row["display_name"],
                "content": row["content"],
                "created_at": row["created_at"].isoformat(),
            }
            for row in rows
        ]
    }


@app.post("/groups/{group_id}/messages")
def create_group_message(
    group_id: str,
    payload: GroupMessageCreateRequest,
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> dict[str, Any]:
    user = _require_user(session_token)
    try:
        sender_id = _to_uuid(user["id"])
        safe_group_id = _to_uuid(group_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid id") from exc

    with _db() as conn:
        with conn.cursor() as cur:
            _require_group_member(cur, safe_group_id, sender_id)
            cur.execute(
                """
                INSERT INTO group_messages (group_id, sender_user_id, content)
                VALUES (%s, %s, %s)
                RETURNING id, sender_user_id, content, created_at
                """,
                (safe_group_id, sender_id, payload.content.strip()),
            )
            row = cur.fetchone()
        conn.commit()

    return {
        "id": row["id"],
        "sender_user_id": str(row["sender_user_id"]),
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
