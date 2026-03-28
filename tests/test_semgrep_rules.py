from __future__ import annotations

from scanner.parser import parse_findings
from scanner.semgrep_runner import run_semgrep
from shared.redaction import SENSITIVE_SNIPPET_PLACEHOLDER


def test_run_semgrep_detects_additional_python_security_patterns(tmp_path) -> None:
    source_file = tmp_path / "vulnerable.py"
    source_file.write_text(
        "\n".join(
            [
                "import hashlib",
                "import os",
                "import pickle",
                "import random",
                "import subprocess",
                "import tempfile",
                "import yaml",
                "",
                "def run_command(command: str) -> None:",
                "    subprocess.run(command, shell=True)",
                "",
                "def load_payload(blob: bytes) -> object:",
                "    return pickle.loads(blob)",
                "",
                "def parse_document(text: str) -> object:",
                "    return yaml.load(text)",
                "",
                "def parse_document_full_loader(text: str) -> object:",
                "    return yaml.load(text, Loader=yaml.FullLoader)",
                "",
                "def create_name() -> str:",
                "    return tempfile.mktemp()",
                "",
                "def run_system(command: str) -> int:",
                "    return os.system(command)",
                "",
                "def md5_digest(data: bytes) -> str:",
                "    return hashlib.md5(data).hexdigest()",
                "",
                "def sha1_digest(data: bytes) -> str:",
                "    return hashlib.sha1(data).hexdigest()",
                "",
                "def issue_session_token() -> str:",
                '    session_token = "".join(random.choice("abcdef0123456789") for _ in range(16))',
                "    return session_token",
                "",
                "def fetch_user(cursor, user_id: str):",
                '    return cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    raw = run_semgrep(str(source_file))
    findings = parse_findings(raw)

    rule_ids = {finding.rule_id for finding in findings}

    assert "rules.subprocess-shell-true" in rule_ids
    assert "rules.pickle-loads" in rule_ids
    assert "rules.unsafe-yaml-load" in rule_ids
    assert "rules.yaml-full-loader" in rule_ids
    assert "rules.tempfile-mktemp" in rule_ids
    assert "rules.os-system" in rule_ids
    assert "rules.hashlib-md5" in rule_ids
    assert "rules.hashlib-sha1" in rule_ids
    assert "rules.insecure-random-token" in rule_ids
    assert "rules.sql-execute-fstring" in rule_ids

    snippets = {finding.rule_id: finding.snippet for finding in findings}
    assert snippets["rules.subprocess-shell-true"] == "subprocess.run(command, shell=True)"
    assert snippets["rules.pickle-loads"] == "return pickle.loads(blob)"
    assert snippets["rules.unsafe-yaml-load"] == "return yaml.load(text)"
    assert (
        snippets["rules.yaml-full-loader"]
        == "return yaml.load(text, Loader=yaml.FullLoader)"
    )
    assert snippets["rules.tempfile-mktemp"] == "return tempfile.mktemp()"
    assert snippets["rules.os-system"] == "return os.system(command)"
    assert snippets["rules.hashlib-md5"] == "return hashlib.md5(data).hexdigest()"
    assert snippets["rules.hashlib-sha1"] == "return hashlib.sha1(data).hexdigest()"
    assert snippets["rules.insecure-random-token"] == SENSITIVE_SNIPPET_PLACEHOLDER
    assert (
        snippets["rules.sql-execute-fstring"]
        == 'return cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
    )


def test_run_semgrep_does_not_flag_safe_yaml_loader(tmp_path) -> None:
    source_file = tmp_path / "safe_yaml.py"
    source_file.write_text(
        "\n".join(
            [
                "import yaml",
                "",
                "def parse_document(text: str) -> object:",
                "    return yaml.load(text, Loader=yaml.SafeLoader)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    raw = run_semgrep(str(source_file))
    findings = parse_findings(raw)

    rule_ids = {finding.rule_id for finding in findings}
    assert "rules.unsafe-yaml-load" not in rule_ids
    assert "rules.yaml-full-loader" not in rule_ids


def test_run_semgrep_does_not_flag_safe_alternatives_for_new_rules(tmp_path) -> None:
    source_file = tmp_path / "safe_patterns.py"
    source_file.write_text(
        "\n".join(
            [
                "import hashlib",
                "import random",
                "import yaml",
                "",
                "def safe_hash(data: bytes) -> str:",
                "    return hashlib.sha256(data).hexdigest()",
                "",
                "def retry_count() -> int:",
                "    retry_count = random.randint(1, 5)",
                "    return retry_count",
                "",
                "def fetch_user(cursor, user_id: str):",
                '    return cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
                "",
                "def parse_document(text: str) -> object:",
                "    return yaml.load(text, Loader=yaml.SafeLoader)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    raw = run_semgrep(str(source_file))
    findings = parse_findings(raw)

    rule_ids = {finding.rule_id for finding in findings}
    assert "rules.hashlib-md5" not in rule_ids
    assert "rules.hashlib-sha1" not in rule_ids
    assert "rules.insecure-random-token" not in rule_ids
    assert "rules.sql-execute-fstring" not in rule_ids
    assert "rules.unsafe-yaml-load" not in rule_ids
    assert "rules.yaml-full-loader" not in rule_ids
