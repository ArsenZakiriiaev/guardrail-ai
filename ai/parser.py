from __future__ import annotations

import json
from json import JSONDecodeError
from typing import Any, Optional

from pydantic import ValidationError

from shared.models import ExplanationResult, FixResult


def parse_explain_response(text: str) -> ExplanationResult:
    payload = _parse_json_object(text)
    normalized = {
        "summary": _coerce_text(payload, "summary") or "Potential security issue detected in the scanned code.",
        "risk": _coerce_text(payload, "risk") or "The model response was incomplete, so the exact security impact could not be determined reliably.",
        "fix": _coerce_text(payload, "fix") or "Review the finding manually and replace the insecure pattern with a safer implementation.",
        "confidence": _coerce_text(payload, "confidence") or "low",
    }

    try:
        return ExplanationResult.model_validate(normalized)
    except ValidationError:
        return ExplanationResult(
            summary="Potential security issue detected in the scanned code.",
            risk="The model response could not be parsed into a reliable explanation.",
            fix="Review the finding manually and apply a safe remediation for the reported pattern.",
            confidence="low",
        )


def parse_fix_response(text: str) -> FixResult:
    payload = _parse_json_object(text)
    normalized = {
        "fixed_code": _coerce_text(payload, "fixed_code")
        or "# Unable to generate a reliable fix automatically.",
        "explanation": _coerce_text(payload, "explanation")
        or "The model response could not be parsed into a trustworthy code fix.",
        "confidence": _coerce_text(payload, "confidence") or "low",
    }

    try:
        return FixResult.model_validate(normalized)
    except ValidationError:
        return FixResult(
            fixed_code="# Unable to generate a reliable fix automatically.",
            explanation="The model response could not be parsed into a trustworthy code fix.",
            confidence="low",
        )


def _parse_json_object(text: str) -> dict[str, Any]:
    raw_text = text.strip()
    if not raw_text:
        return {}

    direct = _load_json(raw_text)
    if isinstance(direct, dict):
        return direct

    extracted = _extract_first_json_object(raw_text)
    if not extracted:
        return {}

    parsed = _load_json(extracted)
    if isinstance(parsed, dict):
        return parsed

    return {}


def _load_json(text: str) -> Optional[Any]:
    try:
        return json.loads(text)
    except JSONDecodeError:
        return None


def _extract_first_json_object(text: str) -> Optional[str]:
    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    in_string = False
    escape = False

    for index in range(start, len(text)):
        char = text[index]

        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]

    return None


def _coerce_text(payload: dict[str, Any], key: str) -> Optional[str]:
    value = payload.get(key)
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned or None
    return None
