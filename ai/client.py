from __future__ import annotations

import json
import os
from typing import Any


DEFAULT_OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_OLLAMA_MODEL = "llama3:8b"
DEFAULT_TIMEOUT_SECONDS = 30


def ask_llm(prompt: str) -> str:
    mode = os.getenv("GUARDRAIL_LLM_MODE", "mock").strip().lower()

    if mode == "ollama":
        return _ask_ollama_or_mock(prompt)

    return _build_mock_response(prompt)


def _ask_ollama_or_mock(prompt: str) -> str:
    try:
        import requests
    except ImportError:
        return _build_mock_response(prompt)

    url = os.getenv("GUARDRAIL_OLLAMA_URL", DEFAULT_OLLAMA_URL)
    model = os.getenv("GUARDRAIL_OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL)
    timeout = _read_timeout_seconds()

    try:
        response = requests.post(
            url,
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=timeout,
        )
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException:
        return _build_mock_response(prompt)
    except ValueError:
        return _build_mock_response(prompt)

    generated_text = payload.get("response")
    if isinstance(generated_text, str) and generated_text.strip():
        return generated_text

    return _build_mock_response(prompt)


def _read_timeout_seconds() -> float:
    raw_value = os.getenv("GUARDRAIL_LLM_TIMEOUT", str(DEFAULT_TIMEOUT_SECONDS))
    try:
        return float(raw_value)
    except ValueError:
        return float(DEFAULT_TIMEOUT_SECONDS)


def _build_mock_response(prompt: str) -> str:
    if '"fixed_code"' in prompt:
        return json.dumps(_mock_fix_payload(prompt))

    return json.dumps(_mock_explain_payload(prompt))


def _mock_explain_payload(prompt: str) -> dict[str, Any]:
    lower_prompt = prompt.lower()

    if "aws" in lower_prompt or "akia" in lower_prompt or "secret" in lower_prompt:
        return {
            "summary": "Hardcoded cloud credentials were found in source code.",
            "risk": "If the repository is leaked or shared, attackers may use the credentials to access cloud resources and data.",
            "fix": "Remove the secret from code, rotate it, and load the replacement from environment variables or a secret manager.",
            "confidence": "high",
        }

    if "eval(" in lower_prompt:
        return {
            "summary": "Unsafe dynamic code execution was detected.",
            "risk": "If untrusted input reaches eval, an attacker may execute arbitrary code inside the application process.",
            "fix": "Avoid eval for untrusted data and replace it with a safe parser or explicit allowlisted logic.",
            "confidence": "high",
        }

    return {
        "summary": "A potential security issue was found in the code.",
        "risk": "If this pattern is reachable by an attacker, it may expose sensitive data or unsafe behavior.",
        "fix": "Review the code path and replace the insecure pattern with a safer alternative appropriate for this finding.",
        "confidence": "medium",
    }


def _mock_fix_payload(prompt: str) -> dict[str, Any]:
    lower_prompt = prompt.lower()

    if "aws" in lower_prompt or "akia" in lower_prompt or "secret" in lower_prompt:
        return {
            "fixed_code": "import os\n\nAWS_KEY = os.getenv(\"AWS_KEY\")",
            "explanation": "The hardcoded credential was replaced with an environment variable lookup.",
            "confidence": "high",
        }

    if "eval(" in lower_prompt:
        return {
            "fixed_code": "import ast\n\nresult = ast.literal_eval(user_input)",
            "explanation": "The direct eval call was replaced with a safer parser for literal input.",
            "confidence": "medium",
        }

    return {
        "fixed_code": "# Replace the insecure snippet with a safer implementation for this finding.",
        "explanation": "A generic safe replacement was returned because the mock client had limited context.",
        "confidence": "low",
    }
