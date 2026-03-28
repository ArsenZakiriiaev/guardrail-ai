# Security Lab V2 Fixture

`fixtures/security_lab_v2/` expands the original training fixture with additional patterns that GuardRail should detect.

The examples are intentionally insecure for static analysis testing only:

- no network calls are executed by default
- `main.py` does not import the insecure modules
- the unsafe APIs stay in source code so Semgrep can detect them

## Layout

```text
fixtures/security_lab_v2/
├── README.md
├── main.py
├── requirements.txt
└── app/
    ├── __init__.py
    ├── archives.py
    ├── authz.py
    ├── crypto_configs.py
    ├── deserialization.py
    ├── directory_queries.py
    ├── file_access.py
    ├── jwt_examples.py
    ├── process_variants.py
    ├── safe_examples.py
    ├── secrets_store.py
    ├── templates.py
    ├── web_endpoints.py
    └── xml_processing.py
```

## Commands

```bash
guardrail scan fixtures/security_lab_v2
guardrail analyze fixtures/security_lab_v2
guardrail check fixtures/security_lab_v2
```

Virtualenv form:

```bash
.venv/bin/guardrail scan fixtures/security_lab_v2
.venv/bin/guardrail analyze fixtures/security_lab_v2
.venv/bin/guardrail check fixtures/security_lab_v2
```

## Expected Findings

Current verified scan result:

- `32` findings total
- `31` unique rule IDs
- `12` affected Python files

- `app/file_access.py`
  - `rules.path-traversal-open-fstring`
  - `rules.predictable-tempfile-path`
  - `rules.chmod-777`
- `app/archives.py`
  - `rules.zipfile-extractall`
  - `rules.tarfile-extractall`
- `app/xml_processing.py`
  - `rules.xxe-lxml-parser`
- `app/web_endpoints.py`
  - `rules.requests-ssrf`
  - `rules.requests-verify-false`
  - `rules.open-redirect`
  - `rules.header-response-splitting`
  - `rules.insecure-cors-wildcard`
  - `rules.flask-debug-true`
- `app/jwt_examples.py`
  - `rules.jwt-verify-disabled`
  - `rules.jwt-alg-none`
- `app/secrets_store.py`
  - `rules.hardcoded-api-token`
  - `rules.github-token`
  - `rules.slack-token`
  - `rules.private-key`
- `app/deserialization.py`
  - `rules.marshal-loads`
  - `rules.dill-loads`
  - `rules.jsonpickle-decode`
- `app/crypto_configs.py`
  - `rules.aes-ecb-mode`
  - `rules.static-iv`
  - `rules.static-salt`
- `app/directory_queries.py`
  - `rules.ldap-filter-fstring`
  - `rules.nosql-where-fstring`
- `app/templates.py`
  - `rules.jinja2-template-user-input`
  - `rules.regex-user-input`
- `app/authz.py`
  - `rules.assert-auth-check` twice
- `app/process_variants.py`
  - `rules.subprocess-shell-true`
  - `rules.os-popen`

`app/safe_examples.py` is intended to remain clean for comparison.

## Notes

- Some imports reference optional packages such as `requests`, `PyJWT`, `Jinja2`, `lxml`, `dill`, `jsonpickle`, `pycryptodome`, and `Flask`. They are present for realism, not because the fixture needs to run those code paths.
- The `requests-ssrf` rule is intentionally simple and matches outbound request calls that use URL-like variables directly. It is not a full allowlist-aware network policy engine.
