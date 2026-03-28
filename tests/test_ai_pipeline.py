from __future__ import annotations

import pytest
import requests

from ai.client import ask_llm
from ai.explain import explain_finding
from ai.fix import fix_finding
from ai.parser import parse_explain_response
from ai.prompts import build_explain_prompt
from shared.models import Finding, Severity


def test_parse_explain_response_extracts_json_with_noise() -> None:
    response = 'noise {"summary":"s","risk":"r","fix":"f","confidence":"HIGH"} tail'
    parsed = parse_explain_response(response)

    assert parsed.summary == "s"
    assert parsed.risk == "r"
    assert parsed.fix == "f"
    assert parsed.confidence == "high"


def test_explain_finding_eval_uses_eval_specific_mock_response(monkeypatch) -> None:
    monkeypatch.setenv("GUARDRAIL_LLM_MODE", "mock")
    finding = Finding(
        rule_id="eval-use",
        type="code",
        severity=Severity.HIGH,
        message="Use of eval() on user-controlled input",
        file="app.py",
        line=8,
        snippet="result = eval(user_input)",
    )

    result = explain_finding(finding)

    assert "eval" in result.summary.lower() or "dynamic code" in result.summary.lower()
    assert "attacker" in result.risk.lower() or "arbitrary code" in result.risk.lower()
    assert "eval" in result.fix.lower() or "parser" in result.fix.lower()


def test_fix_finding_password_returns_env_var_fix(monkeypatch) -> None:
    monkeypatch.setenv("GUARDRAIL_LLM_MODE", "mock")
    finding = Finding(
        rule_id="hardcoded-password",
        type="credential",
        severity=Severity.HIGH,
        message="Hardcoded password found in source code",
        file="config.py",
        line=4,
        snippet='DB_PASSWORD = "super-secret-password"',
    )

    result = fix_finding(finding)

    assert "os.getenv" in result.fixed_code
    assert "password" in result.explanation.lower()


def test_explain_finding_subprocess_shell_true_uses_specific_mock_response(
    monkeypatch,
) -> None:
    monkeypatch.setenv("GUARDRAIL_LLM_MODE", "mock")
    finding = Finding(
        rule_id="subprocess-shell-true",
        type="code",
        severity=Severity.HIGH,
        message="Use of subprocess with shell=True can enable command injection",
        file="worker.py",
        line=10,
        snippet="subprocess.run(command, shell=True)",
    )

    result = explain_finding(finding)

    assert "shell=true" in result.summary.lower() or "subprocess" in result.summary.lower()
    assert "command injection" in result.risk.lower()
    assert "shell=true" in result.fix.lower() or "allowlist" in result.fix.lower()


def test_explain_finding_sql_fstring_uses_specific_mock_response(monkeypatch) -> None:
    monkeypatch.setenv("GUARDRAIL_LLM_MODE", "mock")
    finding = Finding(
        rule_id="sql-execute-fstring",
        type="code",
        severity=Severity.HIGH,
        message="SQL built with f-strings can enable SQL injection",
        file="db.py",
        line=12,
        snippet='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
    )

    result = explain_finding(finding)

    assert "sql" in result.summary.lower()
    assert "sql injection" in result.risk.lower()
    assert "parameterized" in result.fix.lower()


def test_explain_finding_insecure_random_token_uses_specific_mock_response(
    monkeypatch,
) -> None:
    monkeypatch.setenv("GUARDRAIL_LLM_MODE", "mock")
    finding = Finding(
        rule_id="insecure-random-token",
        type="code",
        severity=Severity.HIGH,
        message="random module is not cryptographically secure for token generation",
        file="auth.py",
        line=9,
        snippet="Sensitive value redacted.",
    )

    result = explain_finding(finding)

    assert "token" in result.summary.lower()
    assert "guess" in result.risk.lower() or "predictable" in result.risk.lower()
    assert "secrets" in result.fix.lower()


def test_build_explain_prompt_redacts_secret_values() -> None:
    finding = Finding(
        rule_id="aws-key",
        type="secret",
        severity=Severity.HIGH,
        message="Possible AWS access key hardcoded in source",
        file="app.py",
        line=12,
        snippet='AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
    )

    prompt = build_explain_prompt(finding)

    assert "AKIAIOSFODNN7EXAMPLE" not in prompt
    assert 'AWS_KEY = "<redacted>"' in prompt


def test_ask_llm_ollama_raises_on_request_failure(monkeypatch) -> None:
    monkeypatch.setenv("GUARDRAIL_LLM_MODE", "ollama")

    def raise_request_exception(*args, **kwargs):
        raise requests.RequestException("boom")

    monkeypatch.setattr(requests, "post", raise_request_exception)

    with pytest.raises(RuntimeError, match="Ollama request failed"):
        ask_llm("hello")
