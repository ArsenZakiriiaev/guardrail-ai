from __future__ import annotations

import json

from typer.testing import CliRunner

import cli.main as cli_main


runner = CliRunner()


def test_scan_json_outputs_clean_json(monkeypatch, tmp_path) -> None:
    target = tmp_path / "demo.py"
    target.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")

    semgrep_output = {
        "results": [
            {
                "path": str(target),
                "start": {"line": 1},
                "check_id": "aws-key",
                "extra": {
                    "message": "Possible AWS access key hardcoded in source",
                    "severity": "ERROR",
                    "lines": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
                    "metadata": {"type": "secret"},
                },
            }
        ]
    }

    monkeypatch.setattr(cli_main, "run_semgrep", lambda path: semgrep_output)

    result = runner.invoke(cli_main.app, ["scan", str(target), "--json", "--no-ai"])

    assert result.exit_code == 1
    assert "Scanning:" not in result.stdout
    assert "AKIAIOSFODNN7EXAMPLE" not in result.stdout

    payload = json.loads(result.stdout)
    assert payload[0]["snippet"] == 'AWS_KEY = "<redacted>"'


def test_scan_json_outputs_empty_array_when_clean(monkeypatch, tmp_path) -> None:
    target = tmp_path / "clean.py"
    target.write_text("print('ok')\n", encoding="utf-8")

    monkeypatch.setattr(cli_main, "run_semgrep", lambda path: {"results": []})

    result = runner.invoke(cli_main.app, ["scan", str(target), "--json", "--no-ai"])

    assert result.exit_code == 0
    assert result.stdout.strip() == "[]"
    assert json.loads(result.stdout) == []


def test_analyze_json_outputs_summary_and_findings(monkeypatch, tmp_path) -> None:
    target = tmp_path / "demo.py"
    target.write_text("result = eval(user_input)\n", encoding="utf-8")

    semgrep_output = {
        "results": [
            {
                "path": str(target),
                "start": {"line": 1},
                "check_id": "eval-use",
                "extra": {
                    "message": "Use of eval() on potentially untrusted input",
                    "severity": "ERROR",
                    "lines": "result = eval(user_input)",
                    "metadata": {"type": "code"},
                },
            }
        ]
    }

    monkeypatch.setattr(cli_main, "run_semgrep", lambda path: semgrep_output)

    result = runner.invoke(cli_main.app, ["analyze", str(target), "--json", "--no-ai"])

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["summary"]["target"] == str(target)
    assert payload["summary"]["deep_mode"] is False
    assert payload["summary"]["ai_enriched"] is False
    assert payload["summary"]["total_findings"] == 1
    assert payload["summary"]["files_affected"] == 1
    assert payload["summary"]["rules_triggered"] == 1
    assert payload["summary"]["severity_counts"] == {"high": 1}
    assert payload["findings"][0]["rule_id"] == "eval-use"


def test_analyze_deep_json_includes_code_context(monkeypatch, tmp_path) -> None:
    target = tmp_path / "demo.py"
    target.write_text(
        "\n".join(
            [
                "import subprocess",
                "",
                "def run(command: str) -> None:",
                "    subprocess.run(command, shell=True)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    semgrep_output = {
        "results": [
            {
                "path": str(target),
                "start": {"line": 4},
                "check_id": "subprocess-shell-true",
                "extra": {
                    "message": "Use of subprocess with shell=True can enable command injection",
                    "severity": "ERROR",
                    "lines": "subprocess.run(command, shell=True)",
                    "metadata": {"type": "code"},
                },
            }
        ]
    }

    monkeypatch.setattr(cli_main, "run_semgrep", lambda path: semgrep_output)

    result = runner.invoke(
        cli_main.app,
        ["analyze", str(target), "--json", "--no-ai", "--deep", "--context-lines", "1"],
    )

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["summary"]["deep_mode"] is True
    assert "context" in payload["findings"][0]
    assert "3: def run(command: str) -> None:" in payload["findings"][0]["context"]
    assert "4:     subprocess.run(command, shell=True)" in payload["findings"][0]["context"]
