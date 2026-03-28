from __future__ import annotations

import pytest
import requests

from ai.client import ask_llm
from ai.explain import explain_finding
from ai.fix import fix_finding
from ai.parser import parse_explain_response
from ai.prompts import build_explain_prompt
from ai.second_pass import run_claude_second_pass
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


def test_ask_llm_prefers_anthropic_when_api_key_is_provided(monkeypatch) -> None:
    monkeypatch.delenv("GUARDRAIL_LLM_MODE", raising=False)
    monkeypatch.setattr("ai.client._ask_anthropic", lambda prompt, api_key=None: '{"summary":"live"}')

    result = ask_llm("hello", api_key="test-key")

    assert result == '{"summary":"live"}'


def test_run_claude_second_pass_collects_reviews(monkeypatch) -> None:
    finding = Finding(
        rule_id="eval-use",
        type="code",
        severity=Severity.HIGH,
        message="Use of eval() on user-controlled input",
        file="app.py",
        line=8,
        snippet="result = eval(user_input)",
    )

    def fake_explain(finding_arg, *, api_key=None, model=None, independent=False):
        assert api_key == "test-key"
        assert finding_arg.rule_id == "eval-use"
        assert independent is True
        return parse_explain_response('{"summary":"s","risk":"r","fix":"f","confidence":"high"}')

    monkeypatch.setattr("ai.second_pass.explain_finding_with_claude", fake_explain)

    reviews, metadata = run_claude_second_pass([finding], api_key="test-key")

    assert metadata == {"requested": True, "completed": 1, "failed": 0}
    review = reviews[(finding.file, finding.line, finding.rule_id)]
    assert review.summary == "s"
    assert review.risk == "r"
    assert review.fix == "f"
