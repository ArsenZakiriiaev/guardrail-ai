"""Local sqlite examples with an intentionally unsafe query builder."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass


@dataclass(slots=True)
class UserDirectoryRecord:
    user_id: int
    email: str
    full_name: str


def open_local_directory() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    cursor = connection.cursor()
    cursor.execute(
        """
        CREATE TABLE users (
            user_id INTEGER PRIMARY KEY,
            email TEXT NOT NULL,
            full_name TEXT NOT NULL
        )
        """
    )
    cursor.executemany(
        "INSERT INTO users (user_id, email, full_name) VALUES (?, ?, ?)",
        [
            (1, "ava@example.local", "Ava Chen"),
            (2, "miles@example.local", "Miles Rivera"),
            (3, "nora@example.local", "Nora Singh"),
        ],
    )
    connection.commit()
    return connection


def find_user_by_email_insecure(connection: sqlite3.Connection, email: str):
    cursor = connection.cursor()

    # insecure example for guardrail testing
    return cursor.execute(f"SELECT user_id, email, full_name FROM users WHERE email = '{email}'")
