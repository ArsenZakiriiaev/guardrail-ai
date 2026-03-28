"""Encryption helpers with intentionally weak configurations."""

from __future__ import annotations

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2


def build_legacy_cipher(key: bytes):
    # insecure example for guardrail testing
    return AES.new(key, AES.MODE_ECB)


def build_partner_feed_cipher(key: bytes):
    # insecure example for guardrail testing
    return AES.new(key, AES.MODE_CBC, iv=b"0123456789abcdef")


def derive_archive_key(password: str) -> bytes:
    # insecure example for guardrail testing
    return PBKDF2(password, salt=b"static-training-salt", dkLen=32)
