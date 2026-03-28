from __future__ import annotations

from ai.client import ask_llm
from ai.parser import parse_explain_response
from ai.prompts import build_explain_prompt
from shared.models import ExplanationResult, Finding


def explain_finding(finding: Finding, *, api_key: str | None = None) -> ExplanationResult:
    # Build a strict JSON prompt, ask the model, and always return a valid result.
    prompt = build_explain_prompt(finding)
    raw_response = ask_llm(prompt, api_key=api_key)
    return parse_explain_response(raw_response)
