"""Legacy digest helpers used by the training fixture."""

from __future__ import annotations

import hashlib


def build_password_reset_fingerprint(user_id: str, event_id: str) -> str:
    payload = f"{user_id}:{event_id}".encode("utf-8")

    # insecure example for guardrail testing
    return hashlib.md5(payload).hexdigest()


def build_api_request_signature(account_id: str, nonce: str) -> str:
    payload = f"{account_id}:{nonce}".encode("utf-8")

    # insecure example for guardrail testing
    return hashlib.sha1(payload).hexdigest()
