"""Safe alternatives for the insecure training scenarios."""

from __future__ import annotations

import ast
import hashlib
import json
import secrets
import sqlite3
import subprocess
import tempfile
from pathlib import Path

import yaml


class SafeDemoService:
    """Run a few local-only safe examples for comparison."""

    def run_demo(self) -> dict[str, object]:
        return {
            "expression": safe_parse_literal("{'threshold': 3, 'enabled': True}"),
            "process": safe_run_echo("security lab ready"),
            "yaml": safe_yaml_parse("team: platform\nlevel: training\n"),
            "tempfile": str(safe_tempfile_path("reports")),
            "digest": safe_hash_user_event("user-42", "evt-100"),
            "token": safe_issue_reset_token(),
            "db_row_count": safe_lookup_user("ava@example.local"),
            "serialization": safe_json_deserialize(b'{\"mode\": \"safe\", \"count\": 1}'),
        }


def safe_parse_literal(raw_value: str) -> object:
    return ast.literal_eval(raw_value)


def safe_run_echo(message: str) -> str:
    completed = subprocess.run(
        ["echo", message],
        check=True,
        text=True,
        capture_output=True,
    )
    return completed.stdout.strip()


def safe_json_deserialize(blob: bytes) -> object:
    return json.loads(blob.decode("utf-8"))


def safe_yaml_parse(raw_text: str) -> object:
    return yaml.safe_load(raw_text)


def safe_tempfile_path(prefix: str) -> Path:
    handle = tempfile.NamedTemporaryFile(prefix=f"{prefix}-", suffix=".json", delete=False)
    path = Path(handle.name)
    handle.close()
    return path


def safe_hash_user_event(user_id: str, event_id: str) -> str:
    payload = f"{user_id}:{event_id}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def safe_issue_reset_token() -> str:
    return secrets.token_urlsafe(24)


def safe_lookup_user(email: str) -> int:
    connection = sqlite3.connect(":memory:")
    cursor = connection.cursor()
    cursor.execute(
        """
        CREATE TABLE users (
            user_id INTEGER PRIMARY KEY,
            email TEXT NOT NULL
        )
        """
    )
    cursor.executemany(
        "INSERT INTO users (user_id, email) VALUES (?, ?)",
        [
            (1, "ava@example.local"),
            (2, "miles@example.local"),
        ],
    )
    result = cursor.execute("SELECT user_id FROM users WHERE email = ?", (email,))
    rows = result.fetchall()
    connection.close()
    return len(rows)
