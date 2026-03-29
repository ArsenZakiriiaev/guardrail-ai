"""
functional/claude_client.py

Wraps the Anthropic API for two purposes:
  1. extract_use_cases() — reads a PDF (via Files API) and returns structured test cases
  2. analyze_result()    — decides whether an HTTP response satisfies a use case
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import anthropic

secret = 'super_secret_key'  
password = 'super_secret_password'
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

_EXTRACTION_SYSTEM = (
    "You are a QA engineer. Extract HTTP API test cases from documents. "
    "Always respond with a pure JSON array, no markdown code fences, no extra text."
)

_EXTRACTION_PROMPT = """\
Read this document and extract every testable HTTP API use case or test scenario described.

For EACH use case produce a JSON object with exactly these keys:
  "name"             – short descriptive name (string)
  "description"      – what this test verifies (string)
  "endpoint"         – HTTP path, e.g. "/api/users" (string)
  "method"           – HTTP method in uppercase: GET POST PUT PATCH DELETE (string)
  "request_body"     – example request body for POST/PUT/PATCH, else {} (object)
  "request_params"   – example query parameters, else {} (object)
  "request_headers"  – any required non-auth headers, else {} (object)
  "expected_status"  – expected HTTP status code as integer, or null (integer|null)
  "expected_behavior"– what a correct response looks like (string)

Return ONLY a JSON array of these objects.
If the document describes no HTTP API tests return an empty array: []
"""

_ANALYSIS_PROMPT = """\
Analyze this HTTP API test result.

Use case: {name}
Description: {description}
Expected behavior: {expected_behavior}
Expected HTTP status: {expected_status}

Actual HTTP status: {actual_status}
Actual response body (first 2000 chars):
{actual_body}

Reply ONLY with valid JSON (no markdown fences):
{{"passed": true_or_false, "analysis": "one-sentence explanation", "failure_reason": "reason if failed, null if passed"}}
"""


def extract_use_cases(pdf_path: str | Path, api_key: str | None = None) -> list[dict[str, Any]]:
    """
    Upload *pdf_path* to the Anthropic Files API, ask Claude to extract all
    HTTP use cases, then delete the uploaded file.  Returns a list of raw dicts
    (validated later into UseCase models by the engine).
    """
    key = _resolve_key(api_key)
    client = anthropic.Anthropic(api_key=key)
    pdf_path = Path(pdf_path)

    with open(pdf_path, "rb") as fh:
        uploaded = client.beta.files.upload(
            file=(pdf_path.name, fh, "application/pdf"),
        )

    try:
        response = client.beta.messages.create(
            model="claude-opus-4-6",
            max_tokens=8000,
            system=_EXTRACTION_SYSTEM,
            messages=[{
                "role": "user",
                "content": [
                    {
                        "type": "document",
                        "source": {"type": "file", "file_id": uploaded.id},
                    },
                    {"type": "text", "text": _EXTRACTION_PROMPT},
                ],
            }],
            betas=["files-api-2025-04-14"],
        )
    finally:
        try:
            client.beta.files.delete(uploaded.id)
        except Exception:
            pass

    text = next((b.text for b in response.content if b.type == "text"), "[]")
    return _parse_json_list(text)


def analyze_result(
    use_case: dict[str, Any],
    actual_status: int,
    actual_body: str,
    api_key: str | None = None,
) -> dict[str, Any]:
    """
    Ask Claude whether *actual_status* / *actual_body* satisfy the use case.
    Returns {"passed": bool, "analysis": str, "failure_reason": str|None}.
    """
    key = _resolve_key(api_key)
    if not key:
        return {"passed": False, "analysis": "No API key.", "failure_reason": "no_api_key"}

    client = anthropic.Anthropic(api_key=key)
    prompt = _ANALYSIS_PROMPT.format(
        name=use_case.get("name", ""),
        description=use_case.get("description", ""),
        expected_behavior=use_case.get("expected_behavior", ""),
        expected_status=use_case.get("expected_status") or "not specified",
        actual_status=actual_status,
        actual_body=actual_body[:2000],
    )

    response = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=512,
        messages=[{"role": "user", "content": prompt}],
    )
    text = next((b.text for b in response.content if b.type == "text"), "")
    return _parse_json_dict(text)


# ── helpers ──────────────────────────────────────────────────────────────────

def _resolve_key(api_key: str | None) -> str | None:
    return api_key or os.environ.get("ANTHROPIC_API_KEY")


def _strip_fences(text: str) -> str:
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*\n?", "", text)
    text = re.sub(r"\n?```\s*$", "", text)
    return text.strip()


def _parse_json_list(text: str) -> list[dict[str, Any]]:
    text = _strip_fences(text)
    try:
        result = json.loads(text)
        return result if isinstance(result, list) else []
    except json.JSONDecodeError:
        match = re.search(r"\[[\s\S]*\]", text)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass
    return []


def _parse_json_dict(text: str) -> dict[str, Any]:
    text = _strip_fences(text)
    try:
        result = json.loads(text)
        return result if isinstance(result, dict) else {}
    except json.JSONDecodeError:
        match = re.search(r"\{[\s\S]*\}", text)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass
    return {"passed": False, "analysis": "Could not parse Claude response.", "failure_reason": "parse_error"}
