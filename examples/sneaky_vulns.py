"""
Тестовый файл: выглядит прилично, но содержит 12 нетривиальных уязвимостей.
Каждая — реальный паттерн из продакшн-кодбаз.
"""

import hashlib
import hmac
import os
import re
import sqlite3
import time
import urllib.parse
from pathlib import Path


# ──────────────────────────────────────────────────────────────────────
# 1. Timing attack на сравнение токенов.
#    hmac.compare_digest? Нет, тут == , утечка длины через тайминг.
# ──────────────────────────────────────────────────────────────────────
def verify_api_token(provided: str, stored: str) -> bool:
    return hashlib.sha256(provided.encode()).hexdigest() == hashlib.sha256(stored.encode()).hexdigest()


# ──────────────────────────────────────────────────────────────────────
# 2. ReDoS — catastrophic backtracking.
#    Выглядит как нормальная валидация email.
# ──────────────────────────────────────────────────────────────────────
EMAIL_RE = re.compile(r"^([a-zA-Z0-9_\-\.]+)*@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$")

def validate_email(email: str) -> bool:
    return bool(EMAIL_RE.match(email))


# ──────────────────────────────────────────────────────────────────────
# 3. TOCTOU race condition.
#    Проверяем файл, потом читаем — между ними окно для атаки.
# ──────────────────────────────────────────────────────────────────────
def safe_read_file(filepath: str, allowed_dir: str) -> str:
    resolved = os.path.realpath(filepath)
    if not resolved.startswith(os.path.realpath(allowed_dir)):
        raise PermissionError("Access denied")
    # ← между проверкой и чтением атакующий может подменить симлинк
    with open(resolved) as f:
        return f.read()


# ──────────────────────────────────────────────────────────────────────
# 4. Второпорядковая SQL-инъекция.
#    Первый запрос безопасен (параметризирован).
#    Второй берёт данные из БД и суёт в f-string.
# ──────────────────────────────────────────────────────────────────────
def get_user_posts(db: sqlite3.Connection, username: str):
    # безопасно — параметризированный запрос
    row = db.execute("SELECT display_name FROM users WHERE username = ?", (username,)).fetchone()
    if not row:
        return []
    display_name = row[0]  # ← данные из БД, могут содержать SQL-пейлоад
    # ОПАСНО — display_name попал из БД без санитизации
    return db.execute(f"SELECT * FROM posts WHERE author = '{display_name}'").fetchall()


# ──────────────────────────────────────────────────────────────────────
# 5. SSRF через urllib.parse обход.
#    Проверяем hostname, но атакующий может обойти через @ в URL.
#    http://allowed.com@evil.com → hostname = evil.com
# ──────────────────────────────────────────────────────────────────────
ALLOWED_HOSTS = {"api.internal.com", "cdn.internal.com"}

def fetch_url(url: str) -> bytes:
    parsed = urllib.parse.urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"Host not allowed: {parsed.hostname}")
    import urllib.request
    return urllib.request.urlopen(url, timeout=5).read()


# ──────────────────────────────────────────────────────────────────────
# 6. Слабый PRNG для security-critical операции.
#    random.choice вместо secrets.
# ──────────────────────────────────────────────────────────────────────
import random
import string

def generate_reset_token(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


# ──────────────────────────────────────────────────────────────────────
# 7. Mass assignment / object injection.
#    update(**kwargs) позволяет перезаписать is_admin, role, и т.д.
# ──────────────────────────────────────────────────────────────────────
class User:
    def __init__(self, name: str, email: str, is_admin: bool = False):
        self.name = name
        self.email = email
        self.is_admin = is_admin

    def update_profile(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)  # ← можно передать is_admin=True


# ──────────────────────────────────────────────────────────────────────
# 8. Zip slip — path traversal при распаковке архива.
#    extractall() без проверки имён файлов.
# ──────────────────────────────────────────────────────────────────────
import zipfile

def extract_upload(zip_path: str, dest_dir: str):
    with zipfile.ZipFile(zip_path) as zf:
        # ← архив может содержать ../../etc/cron.d/backdoor
        zf.extractall(dest_dir)


# ──────────────────────────────────────────────────────────────────────
# 9. Prototype pollution аналог — __class__ перезапись через merge.
#    Рекурсивный merge без фильтрации dunder-ключей.
# ──────────────────────────────────────────────────────────────────────
def deep_merge(base: dict, override: dict) -> dict:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            deep_merge(base[key], value)
        else:
            base[key] = value  # ← ключ "__class__", "__import__" и др.
    return base


# ──────────────────────────────────────────────────────────────────────
# 10. Небезопасная десериализация через marshal (менее известен чем pickle).
# ──────────────────────────────────────────────────────────────────────
import marshal
import types

def load_cached_function(data: bytes):
    code = marshal.loads(data)  # ← RCE через code object
    return types.FunctionType(code, globals())


# ──────────────────────────────────────────────────────────────────────
# 11. JWT "none" algorithm — подделка токена без подписи.
#     Выглядит как нормальная верификация, но принимает alg=none.
# ──────────────────────────────────────────────────────────────────────
import json
import base64

def verify_jwt(token: str, secret: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT")

    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))

    if header.get("alg") == "none":
        return payload  # ← принимает неподписанный токен

    expected_sig = hmac.new(
        secret.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256
    ).digest()
    provided_sig = base64.urlsafe_b64decode(parts[2] + "==")

    if expected_sig == provided_sig:  # ← ещё и timing attack тут
        return payload
    raise ValueError("Invalid signature")


# ──────────────────────────────────────────────────────────────────────
# 12. XML External Entity (XXE) injection.
#     defusedxml? Нет, тут голый xml.etree с resolve_entities.
# ──────────────────────────────────────────────────────────────────────
from xml.etree import ElementTree as ET

def parse_config(xml_string: str) -> dict:
    root = ET.fromstring(xml_string)  # ← XXE если lxml, limited в stdlib
    config = {}
    for child in root:
        config[child.tag] = child.text
    return config


# ──────────────────────────────────────────────────────────────────────
# Бонус: выглядит безопасно, но open() с mode из пользовательского ввода.
# ──────────────────────────────────────────────────────────────────────
def read_or_write(path: str, mode: str = "r", content: str = "") -> str:
    # "а чё такого, просто mode"
    with open(path, mode) as f:  # ← mode="w" перезапишет любой файл
        if "r" in mode:
            return f.read()
        f.write(content)
        return ""
