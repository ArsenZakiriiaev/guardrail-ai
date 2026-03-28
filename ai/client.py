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
        return _ask_ollama(prompt)

    return _build_mock_response(prompt)


def _ask_ollama(prompt: str) -> str:
    try:
        import requests
    except ImportError as exc:
        raise RuntimeError("Ollama mode requires the 'requests' package to be installed.") from exc

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
    except requests.RequestException as exc:
        raise RuntimeError(f"Ollama request failed for {url}: {exc}") from exc
    except ValueError as exc:
        raise RuntimeError("Ollama returned invalid JSON.") from exc

    generated_text = payload.get("response")
    if isinstance(generated_text, str) and generated_text.strip():
        return generated_text

    raise RuntimeError("Ollama returned an empty response body.")


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

    if "eval(" in lower_prompt:
        return {
            "summary": "Unsafe dynamic code execution was detected.",
            "risk": "If untrusted input reaches eval, an attacker may execute arbitrary code inside the application process.",
            "fix": "Avoid eval for untrusted data and replace it with a safe parser or explicit allowlisted logic.",
            "confidence": "high",
        }

    if "password" in lower_prompt or "passwd" in lower_prompt or "db_password" in lower_prompt:
        return {
            "summary": "A hardcoded password was found in the source code.",
            "risk": "If this value is committed or leaked, attackers may reuse it to access the application or connected systems.",
            "fix": "Remove the password from source code, rotate it if it is real, and load the replacement from environment variables or a secret manager.",
            "confidence": "high",
        }

    if _looks_like_aws_secret(lower_prompt):
        return {
            "summary": "Hardcoded cloud credentials were found in source code.",
            "risk": "If the repository is leaked or shared, attackers may use the credentials to access cloud resources and data.",
            "fix": "Remove the secret from code, rotate it, and load the replacement from environment variables or a secret manager.",
            "confidence": "high",
        }

    if "shell=true" in lower_prompt or "subprocess." in lower_prompt:
        return {
            "summary": "A subprocess call with shell=True was detected.",
            "risk": "If untrusted input reaches this command string, an attacker may trigger command injection and execute arbitrary shell commands.",
            "fix": "Avoid shell=True when possible, pass arguments as a list, and validate or allowlist any user-controlled command data.",
            "confidence": "high",
        }

    if "pickle.load" in lower_prompt or "pickle.loads" in lower_prompt:
        return {
            "summary": "Unsafe pickle deserialization was detected.",
            "risk": "Loading pickle data from an untrusted source can execute attacker-controlled code during deserialization.",
            "fix": "Do not deserialize untrusted pickle data. Prefer safer formats such as JSON and only load pickle from fully trusted sources.",
            "confidence": "high",
        }

    if "fullloader" in lower_prompt:
        return {
            "summary": "yaml.FullLoader usage was detected.",
            "risk": "FullLoader accepts a broader set of YAML constructs than safe_load and can still be risky when parsing untrusted input.",
            "fix": "Prefer yaml.safe_load or SafeLoader when the input is not fully trusted and only basic YAML types are required.",
            "confidence": "high",
        }

    if "yaml.load" in lower_prompt:
        return {
            "summary": "Unsafe yaml.load() usage was detected.",
            "risk": "yaml.load can construct unsafe Python objects from attacker-controlled YAML and may lead to code execution or unexpected object creation.",
            "fix": "Replace yaml.load with yaml.safe_load or use a SafeLoader explicitly when only standard YAML types are needed.",
            "confidence": "high",
        }

    if "tempfile.mktemp" in lower_prompt or "mktemp()" in lower_prompt:
        return {
            "summary": "Insecure temporary file creation was detected.",
            "risk": "tempfile.mktemp can introduce race conditions where an attacker creates the path before the application uses it.",
            "fix": "Use tempfile.NamedTemporaryFile, TemporaryDirectory, or mkstemp instead of mktemp.",
            "confidence": "high",
        }

    if "os.system" in lower_prompt:
        return {
            "summary": "An os.system() call was detected.",
            "risk": "If attacker-controlled input reaches this shell command, it can trigger command injection and arbitrary command execution.",
            "fix": "Avoid os.system when possible. Prefer subprocess with argument lists and strict validation or allowlisting for user input.",
            "confidence": "high",
        }

    if "hashlib.md5" in lower_prompt or "rule_id: hashlib-md5" in lower_prompt:
        return {
            "summary": "Use of hashlib.md5() was detected.",
            "risk": "MD5 is collision-prone and should not be used for security-sensitive hashing such as integrity checks, password storage, or signatures.",
            "fix": "Use a stronger hash such as SHA-256 or a dedicated password hashing function like bcrypt, scrypt, or Argon2 depending on the use case.",
            "confidence": "high",
        }

    if "hashlib.sha1" in lower_prompt or "rule_id: hashlib-sha1" in lower_prompt:
        return {
            "summary": "Use of hashlib.sha1() was detected.",
            "risk": "SHA-1 is considered broken for many security-sensitive uses because collision attacks are practical.",
            "fix": "Replace SHA-1 with SHA-256 or another modern primitive appropriate for the security requirement.",
            "confidence": "high",
        }

    if "insecure-random-token" in lower_prompt or (
        "random." in lower_prompt and "token" in lower_prompt
    ):
        return {
            "summary": "A security-sensitive token was generated with the random module.",
            "risk": "The random module is predictable and can allow attackers to guess tokens, reset links, or session identifiers.",
            "fix": "Use the secrets module, such as secrets.token_urlsafe or secrets.choice, for security-sensitive token generation.",
            "confidence": "high",
        }

    if "rule_id: sql-execute-fstring" in lower_prompt or "execute(f" in lower_prompt:
        return {
            "summary": "A SQL query built with an f-string was detected.",
            "risk": "Interpolating values directly into SQL can enable SQL injection when attacker-controlled data reaches the query.",
            "fix": "Use parameterized queries and pass user data as bound parameters instead of string interpolation.",
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

    if "eval(" in lower_prompt:
        return {
            "fixed_code": "import ast\n\nresult = ast.literal_eval(user_input)",
            "explanation": "The direct eval call was replaced with a safer parser for literal input.",
            "confidence": "medium",
        }

    if "password" in lower_prompt or "passwd" in lower_prompt or "db_password" in lower_prompt:
        return {
            "fixed_code": "import os\n\nDB_PASSWORD = os.getenv(\"DB_PASSWORD\")",
            "explanation": "The hardcoded password was replaced with an environment variable lookup.",
            "confidence": "high",
        }

    if _looks_like_aws_secret(lower_prompt):
        return {
            "fixed_code": "import os\n\nAWS_KEY = os.getenv(\"AWS_KEY\")",
            "explanation": "The hardcoded credential was replaced with an environment variable lookup.",
            "confidence": "high",
        }

    return {
        "fixed_code": "# Replace the insecure snippet with a safer implementation for this finding.",
        "explanation": "A generic safe replacement was returned because the mock client had limited context.",
        "confidence": "low",
    }


def _looks_like_aws_secret(lower_prompt: str) -> bool:
    aws_markers = (
        "akia",
        "aws_key",
        "aws access key",
        "possible aws access key",
        "rule_id: aws-key",
    )
    return any(marker in lower_prompt for marker in aws_markers)
