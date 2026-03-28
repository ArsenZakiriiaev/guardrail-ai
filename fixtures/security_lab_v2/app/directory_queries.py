"""Directory and document-store lookups with injection-prone query builders."""

from __future__ import annotations


def search_employee_directory(connection, base_dn: str, username: str):
    # insecure example for guardrail testing
    return connection.search(base_dn, f"(uid={username})", attributes=["cn", "mail"])


def find_team_members(collection, team_name: str):
    # insecure example for guardrail testing
    return collection.find({"$where": f"this.team == '{team_name}'"})
