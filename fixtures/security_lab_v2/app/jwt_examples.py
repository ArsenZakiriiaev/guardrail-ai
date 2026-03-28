"""JWT helpers with intentionally unsafe verification settings."""

from __future__ import annotations

import jwt


def decode_portal_token_unverified(token: str) -> dict[str, object]:
    # insecure example for guardrail testing
    return jwt.decode(token, options={"verify_signature": False}, algorithms=["HS256"])


def create_unsigned_debug_token(payload: dict[str, object]) -> str:
    # insecure example for guardrail testing
    return jwt.encode(payload, key="", algorithm="none")
