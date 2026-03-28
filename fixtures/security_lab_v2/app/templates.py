"""Template and regex helpers with intentionally unsafe user input handling."""

from __future__ import annotations

import re

from jinja2 import Template


def render_custom_message(user_template: str, context: dict[str, object]) -> str:
    # insecure example for guardrail testing
    return Template(user_template).render(context)


def search_with_user_regex(user_pattern: str, text: str):
    compiled = re.compile(user_pattern)
    # insecure example for guardrail testing
    return compiled.search(text)
