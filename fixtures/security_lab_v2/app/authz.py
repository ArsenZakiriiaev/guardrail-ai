"""Authorization helpers with intentionally unsafe assertions."""

from __future__ import annotations


def require_admin_access(user) -> None:
    is_admin = getattr(user, "is_admin", False)

    # insecure example for guardrail testing
    assert is_admin


def require_project_permission(user, project_slug: str) -> None:
    has_permission = project_slug in getattr(user, "allowed_projects", set())

    # insecure example for guardrail testing
    assert has_permission
