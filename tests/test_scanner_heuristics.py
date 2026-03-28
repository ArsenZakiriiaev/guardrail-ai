from __future__ import annotations

from scanner.parser import parse_findings
from scanner.semgrep_runner import run_semgrep


def test_heuristics_detect_second_order_sqli_and_querybuilder_sink(tmp_path) -> None:
    source_file = tmp_path / "demo.py"
    source_file.write_text(
        "\n".join(
            [
                "from flask import Flask, request",
                "",
                "app = Flask(__name__)",
                "",
                "class SavedFilter:",
                "    def __init__(self, expression: str):",
                "        self.expression = expression",
                "",
                "class QueryBuilder:",
                "    def __init__(self):",
                "        self.filters = []",
                "",
                "    def where(self, clause: str):",
                "        self.filters.append(clause)",
                "",
                "    def build(self) -> str:",
                '        return f"SELECT * FROM users WHERE {" AND ".join(self.filters)}"',
                "",
                '@app.post("/filters")',
                "def save_filter():",
                "    payload = request.get_json() or {}",
                "    expression = payload.get('expression', '')",
                "    saved = SavedFilter(expression=expression)",
                "    db.add(saved)",
                "    db.commit()",
                "    return {'ok': True}",
                "",
                '@app.get("/filters/run")',
                "def run_saved_filter():",
                "    saved = db.query(SavedFilter).first()",
                '    return db.execute(f"SELECT count(*) AS {saved.expression} FROM users")',
                "",
                '@app.get("/builder")',
                "def run_builder():",
                "    payload = request.args.get('filter', '')",
                "    builder = QueryBuilder()",
                "    builder.where(payload)",
                "    return db.execute(builder.build())",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    raw = run_semgrep(str(source_file))
    findings = parse_findings(raw)
    rule_ids = {finding.rule_id for finding in findings}

    assert "rules.second-order-sqli" in rule_ids
    assert "rules.querybuilder-sqli" in rule_ids
