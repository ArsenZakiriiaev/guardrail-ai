from __future__ import annotations

from scanner.parser import parse_findings
from shared.models import Severity
from shared.redaction import SENSITIVE_SNIPPET_PLACEHOLDER


def test_parse_findings_maps_semgrep_payload_to_finding() -> None:
    semgrep_output = {
        "results": [
            {
                "path": "app.py",
                "start": {"line": 12},
                "check_id": "aws-key",
                "extra": {
                    "message": "Possible AWS access key hardcoded in source",
                    "severity": "CRITICAL",
                    "lines": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
                    "metadata": {"type": "secret"},
                },
            }
        ]
    }

    findings = parse_findings(semgrep_output)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "aws-key"
    assert finding.type == "secret"
    assert finding.severity == Severity.CRITICAL
    assert finding.file == "app.py"
    assert finding.line == 12
    assert finding.snippet == 'AWS_KEY = "<redacted>"'
    assert "AKIA" not in finding.snippet


def test_parse_findings_keeps_sensitive_snippet_redacted_when_semgrep_hides_lines(
    tmp_path,
) -> None:
    source_file = tmp_path / "demo.py"
    source_file.write_text('DB_PASSWORD = "super-secret-password"\n', encoding="utf-8")

    semgrep_output = {
        "results": [
            {
                "path": str(source_file),
                "start": {"line": 1},
                "check_id": "hardcoded-password",
                "extra": {
                    "message": "Hardcoded password found in source code",
                    "severity": "ERROR",
                    "lines": "requires login",
                    "metadata": {"type": "credential"},
                },
            }
        ]
    }

    findings = parse_findings(semgrep_output)

    assert len(findings) == 1
    assert findings[0].snippet == SENSITIVE_SNIPPET_PLACEHOLDER
    assert "super-secret-password" not in findings[0].snippet


def test_parse_findings_reads_source_line_for_non_sensitive_findings(tmp_path) -> None:
    source_file = tmp_path / "demo.py"
    source_file.write_text("result = eval(user_input)\n", encoding="utf-8")

    semgrep_output = {
        "results": [
            {
                "path": str(source_file),
                "start": {"line": 1},
                "check_id": "eval-use",
                "extra": {
                    "message": "Use of eval() on potentially untrusted input",
                    "severity": "ERROR",
                    "lines": "requires login",
                    "metadata": {"type": "code"},
                },
            }
        ]
    }

    findings = parse_findings(semgrep_output)

    assert len(findings) == 1
    assert findings[0].snippet == "result = eval(user_input)"


def test_parse_findings_dedupes_identical_findings() -> None:
    semgrep_output = {
        "results": [
            {
                "path": "app.py",
                "start": {"line": 10},
                "check_id": "eval-use",
                "extra": {
                    "message": "Use of eval() on potentially untrusted input",
                    "severity": "ERROR",
                    "lines": "result = eval(user_input)",
                    "metadata": {"type": "code"},
                },
            },
            {
                "path": "app.py",
                "start": {"line": 10},
                "check_id": "eval-use",
                "extra": {
                    "message": "Use of eval() on potentially untrusted input",
                    "severity": "ERROR",
                    "lines": "result = eval(user_input)",
                    "metadata": {"type": "code"},
                },
            },
        ]
    }

    findings = parse_findings(semgrep_output)

    assert len(findings) == 1
