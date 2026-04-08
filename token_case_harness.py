#!/usr/bin/env python3
"""
Token case generator + validator (single-file harness).

What it does:
1) Prompts for number of tokens to generate.
2) Splits tokens as evenly as possible across 6 categories.
3) Saves all generated token cases + expected outcomes to a text file (JSONL).
4) Loads app validation logic from api/main.py.
5) Validates every token and compares actual vs expected.
6) Prints summary like "599 of 600 correct".
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.util
import json
import os
import secrets
import struct
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parent
API_MAIN = ROOT / "api" / "main.py"
OUTPUT_FILE = ROOT / "token_cases.txt"


@dataclass
class TokenCase:
    id: int
    category: str
    endpoint: str  # verify | reset
    token: str
    expected_status: int
    reason: str


def _b64u_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _sign(secret: str, nonce: str, token_type: str, expiry_ts: int) -> str:
    msg = f"{nonce}|{token_type}|{expiry_ts}".encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest()
    return _b64u_no_pad(sig)


def _make_signed_token(secret: str, token_type: str, expiry_ts: int) -> str:
    nonce = secrets.token_urlsafe(24)
    exp_b64 = _b64u_no_pad(struct.pack(">I", expiry_ts & 0xFFFFFFFF))
    sig_b64 = _sign(secret, nonce, token_type, expiry_ts)
    return f"{nonce}.{token_type}.{exp_b64}.{sig_b64}"


def _make_bad_sig_token(secret: str, token_type: str, expiry_ts: int) -> str:
    # Sign with different secret to force signature mismatch.
    wrong_secret = secret[::-1] + "x"
    nonce = secrets.token_urlsafe(24)
    exp_b64 = _b64u_no_pad(struct.pack(">I", expiry_ts & 0xFFFFFFFF))
    sig_b64 = _sign(wrong_secret, nonce, token_type, expiry_ts)
    return f"{nonce}.{token_type}.{exp_b64}.{sig_b64}"


def _make_malformed_token() -> str:
    choices = [
        "onepart",
        "a.b.c",
        "....",
        "nonce.v.@@@.sig",
        f"{secrets.token_urlsafe(8)}..{secrets.token_urlsafe(8)}.{secrets.token_urlsafe(8)}",
    ]
    return secrets.choice(choices)


def _chunk_counts(total: int, buckets: int) -> list[int]:
    base = total // buckets
    rem = total % buckets
    return [base + (1 if i < rem else 0) for i in range(buckets)]


def _build_cases(total: int, token_secret: str) -> list[TokenCase]:
    now = int(time.time())
    counts = _chunk_counts(total, 6)
    cases: list[TokenCase] = []
    cid = 1

    def add_many(n: int, fn: Callable[[], TokenCase]) -> None:
        nonlocal cid
        for _ in range(n):
            c = fn()
            c.id = cid
            cid += 1
            cases.append(c)

    # 1) valid_verify -> expected 200
    add_many(
        counts[0],
        lambda: TokenCase(
            id=0,
            category="valid_verify",
            endpoint="verify",
            token=_make_signed_token(token_secret, "v", now + secrets.randbelow(3600) + 60),
            expected_status=200,
            reason="Valid signature, type=v, future expiry",
        ),
    )

    # 2) valid_reset -> expected 200
    add_many(
        counts[1],
        lambda: TokenCase(
            id=0,
            category="valid_reset",
            endpoint="reset",
            token=_make_signed_token(token_secret, "r", now + secrets.randbelow(3600) + 60),
            expected_status=200,
            reason="Valid signature, type=r, future expiry",
        ),
    )

    # 3) expired -> expected 400
    add_many(
        counts[2],
        lambda: TokenCase(
            id=0,
            category="expired",
            endpoint="verify" if secrets.randbelow(2) == 0 else "reset",
            token=(
                _make_signed_token(token_secret, "v", now - secrets.randbelow(3600) - 60)
                if secrets.randbelow(2) == 0
                else _make_signed_token(token_secret, "r", now - secrets.randbelow(3600) - 60)
            ),
            expected_status=400,
            reason="Signed expiry in the past",
        ),
    )

    # 4) wrong_type -> expected 400
    def wrong_type_case() -> TokenCase:
        endpoint = "verify" if secrets.randbelow(2) == 0 else "reset"
        token_type = "r" if endpoint == "verify" else "v"
        return TokenCase(
            id=0,
            category="wrong_type",
            endpoint=endpoint,
            token=_make_signed_token(token_secret, token_type, now + secrets.randbelow(3600) + 60),
            expected_status=400,
            reason="Token type does not match endpoint",
        )

    add_many(counts[3], wrong_type_case)

    # 5) bad_signature -> expected 400
    def bad_sig_case() -> TokenCase:
        endpoint = "verify" if secrets.randbelow(2) == 0 else "reset"
        token_type = "v" if endpoint == "verify" else "r"
        return TokenCase(
            id=0,
            category="bad_signature",
            endpoint=endpoint,
            token=_make_bad_sig_token(token_secret, token_type, now + secrets.randbelow(3600) + 60),
            expected_status=400,
            reason="HMAC signature mismatch",
        )

    add_many(counts[4], bad_sig_case)

    # 6) malformed -> expected 400
    add_many(
        counts[5],
        lambda: TokenCase(
            id=0,
            category="malformed",
            endpoint="verify" if secrets.randbelow(2) == 0 else "reset",
            token=_make_malformed_token(),
            expected_status=400,
            reason="Invalid token format or parse failure",
        ),
    )

    secrets.SystemRandom().shuffle(cases)
    # Keep ids sequential after shuffle for readability.
    for i, c in enumerate(cases, start=1):
        c.id = i
    return cases


def _write_cases(cases: list[TokenCase], out_path: Path) -> None:
    with out_path.open("w", encoding="utf-8") as f:
        for c in cases:
            f.write(json.dumps(asdict(c), separators=(",", ":")) + "\n")


def _read_cases(out_path: Path) -> list[TokenCase]:
    loaded: list[TokenCase] = []
    with out_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            loaded.append(TokenCase(**json.loads(line)))
    return loaded


def _load_app_module(token_secret: str):
    # Ensure import-time security checks in api/main.py pass.
    os.environ.setdefault("TOKEN_SECRET", token_secret)
    os.environ.setdefault("COOKIE_SECURE", "false")
    os.environ.setdefault("WEB_ORIGIN", "http://localhost:3000")

    spec = importlib.util.spec_from_file_location("appmain", str(API_MAIN))
    if spec is None or spec.loader is None:
        raise RuntimeError("Failed to load api/main.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _validate_cases(cases: list[TokenCase], app_mod) -> tuple[int, int, dict[str, dict[str, int]]]:
    correct = 0
    total = len(cases)
    by_category: dict[str, dict[str, int]] = {}

    for c in cases:
        got = 500
        try:
            if c.endpoint == "verify":
                app_mod._verify_signed_token(c.token, app_mod._TOKEN_TYPE_VERIFY, "expired")
            else:
                app_mod._verify_signed_token(c.token, app_mod._TOKEN_TYPE_RESET, "expired")
            got = 200
        except Exception as exc:
            got = getattr(exc, "status_code", 500)

        ok = got == c.expected_status
        if ok:
            correct += 1

        bucket = by_category.setdefault(c.category, {"total": 0, "correct": 0, "incorrect": 0})
        bucket["total"] += 1
        if ok:
            bucket["correct"] += 1
        else:
            bucket["incorrect"] += 1

    return correct, total, by_category


def main() -> None:
    raw = input("How many tokens do you want to generate? ").strip()
    if not raw.isdigit() or int(raw) <= 0:
        raise SystemExit("Please enter a positive integer.")

    total = int(raw)
    token_secret = secrets.token_urlsafe(48)

    cases = _build_cases(total, token_secret)
    _write_cases(cases, OUTPUT_FILE)
    print(f"Saved {len(cases)} token cases to: {OUTPUT_FILE}")

    loaded_cases = _read_cases(OUTPUT_FILE)
    app_mod = _load_app_module(token_secret)
    correct, total_loaded, by_category = _validate_cases(loaded_cases, app_mod)

    print("\nPer-category results:")
    for name in sorted(by_category):
        row = by_category[name]
        print(
            f"- {name}: {row['correct']} of {row['total']} correct"
        )

    print("\nOverall:")
    print(f"{correct} of {total_loaded} correct")
    accuracy = (correct / total_loaded) * 100.0 if total_loaded else 0.0
    print(f"Accuracy: {accuracy:.2f}%")


if __name__ == "__main__":
    main()
