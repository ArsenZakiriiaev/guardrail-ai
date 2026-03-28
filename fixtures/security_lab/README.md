# Security Lab Fixture

`fixtures/security_lab/` is a small local-only Python mini-project for GuardRail rule validation.
It intentionally contains insecure patterns for static analysis and matching safe equivalents for comparison.

The insecure code is educational:

- It does not make network calls.
- `main.py` only runs safe demo flows by default.
- Dangerous APIs remain in source so Semgrep can match them, but the project does not depend on executing those paths.

## Layout

```text
fixtures/security_lab/
├── README.md
├── main.py
├── requirements.txt
└── app/
    ├── __init__.py
    ├── config.py
    ├── crypto_utils.py
    ├── database.py
    ├── expression_engine.py
    ├── process_runner.py
    ├── safe_examples.py
    ├── serialization.py
    ├── tempfiles.py
    ├── tokens.py
    └── yaml_handlers.py
```

## How To Run GuardRail

From the repository root you can use the installed CLI:

```bash
guardrail scan fixtures/security_lab
guardrail analyze fixtures/security_lab
guardrail check fixtures/security_lab
```

If you are using the repository virtualenv directly, the equivalent commands are:

```bash
.venv/bin/guardrail scan fixtures/security_lab
.venv/bin/guardrail analyze fixtures/security_lab
.venv/bin/guardrail check fixtures/security_lab
```

If you want to run the mini-project entry point itself, install the local fixture dependency first:

```bash
python3 -m pip install -r fixtures/security_lab/requirements.txt
python3 fixtures/security_lab/main.py
```

## Expected Findings

Expected findings by file:

- `app/config.py`
  - `rules.aws-key`
  - `rules.hardcoded-password`
- `app/expression_engine.py`
  - `rules.eval-use`
- `app/process_runner.py`
  - `rules.subprocess-shell-true`
  - `rules.os-system`
- `app/serialization.py`
  - `rules.pickle-loads` for `pickle.load(...)`
  - `rules.pickle-loads` for `pickle.loads(...)`
- `app/yaml_handlers.py`
  - `rules.unsafe-yaml-load`
  - `rules.yaml-full-loader`
- `app/tempfiles.py`
  - `rules.tempfile-mktemp`
- `app/crypto_utils.py`
  - `rules.hashlib-md5`
  - `rules.hashlib-sha1`
- `app/tokens.py`
  - `rules.insecure-random-token`
- `app/database.py`
  - `rules.sql-execute-fstring`

`app/safe_examples.py` is intended to stay clean and act as a side-by-side reference.

## Scenario Map

- `app/config.py` simulates an internal service settings module with intentionally hardcoded secrets.
- `app/expression_engine.py` shows a reporting helper that evaluates user-provided formulas.
- `app/process_runner.py` models maintenance helpers that would be risky if enabled.
- `app/serialization.py` demonstrates unsafe deserialization from bytes and file-like objects.
- `app/yaml_handlers.py` contrasts generic `yaml.load(...)` and `yaml.FullLoader`.
- `app/tempfiles.py` shows insecure temporary filename generation.
- `app/crypto_utils.py` shows legacy digest helpers used for security-sensitive identifiers.
- `app/tokens.py` uses `random` for password reset token generation.
- `app/database.py` uses `sqlite3` with an f-string SQL query.
- `app/safe_examples.py` shows safer replacements for the same jobs.

## Notes

- `yaml.load(text)` without an explicit loader is kept as-is because the rule matches that exact pattern. With modern `PyYAML` it may raise at runtime, so it is not exercised by `main.py`.
- `pickle` examples are local-only and use in-memory/file-like data in the code shape; they are present for static analysis coverage, not as runnable business logic.
