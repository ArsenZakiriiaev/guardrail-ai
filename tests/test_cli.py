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
