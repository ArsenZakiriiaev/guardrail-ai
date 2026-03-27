from __future__ import annotations

from ai.client import ask_llm
from ai.parser import parse_fix_response
from ai.prompts import build_fix_prompt
from shared.models import Finding, FixResult


def fix_finding(finding: Finding) -> FixResult:
    # This is optional for the MVP and only returns a suggested code snippet.
    prompt = build_fix_prompt(finding)
    raw_response = ask_llm(prompt)
    return parse_fix_response(raw_response)
