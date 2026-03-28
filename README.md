# GuardRail AI

GuardRail AI is a minimal DevSecOps copilot for developers.

It scans Python code with Semgrep, normalizes findings into a shared model, optionally enriches them with AI-generated security explanations, and can run an isolated HTTP pentest against a temporary Dockerized app built from source.

## What works on `main`

- Semgrep-based scanning for:
  - hardcoded AWS access keys
  - hardcoded passwords
  - `eval(...)` usage
  - `subprocess(..., shell=True)` usage
  - `pickle.load(...)` and `pickle.loads(...)`
  - unsafe `yaml.load(...)`
  - `yaml.load(..., Loader=yaml.FullLoader)`
  - `tempfile.mktemp()` usage
  - `os.system(...)` usage
  - `hashlib.md5(...)` and `hashlib.sha1(...)`
  - token generation with `random`
  - SQL queries executed through f-strings
- Containerized HTTP pentest for Python web apps
  - Dockerized target app with no external network access
  - endpoint discovery from source code for FastAPI, Flask, and basic Django routes
  - SAST-guided attack planning for SQL injection, command injection, and SSRF
  - response audits for security headers, CORS, and cookie flags
  - JSON output, CLI summary, and standalone HTML report
- Shared `Finding` contract
- AI explanation pipeline with `mock` and `ollama`
- CLI output in table or JSON format
- Web UI for code scanning and pentest runs
- Local smoke tests and lightweight unit tests

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e .[dev]
```

## Run AI smoke tests

```bash
GUARDRAIL_LLM_MODE=mock .venv/bin/python test_explain.py
GUARDRAIL_LLM_MODE=mock .venv/bin/python test_eval_case.py
GUARDRAIL_LLM_MODE=mock .venv/bin/python test_password_case.py
```

## Run scanner and CLI

Show the installed CLI version:

```bash
.venv/bin/guardrail version
```

Scan the demo file with AI explanations:

```bash
GUARDRAIL_LLM_MODE=mock .venv/bin/guardrail scan examples/vulnerable_demo.py
```

Scan and print JSON:

```bash
GUARDRAIL_LLM_MODE=mock .venv/bin/guardrail scan examples/vulnerable_demo.py --json
```

Quick check mode for hooks or CI:

```bash
.venv/bin/guardrail check examples/vulnerable_demo.py
```

Run isolated pentest against the demo web app:

```bash
.venv/bin/guardrail pentest examples/vulnerable_demo.py --html-report .guardrail/pentest-report.html
```

Pentest with AI explanations:

```bash
GUARDRAIL_LLM_MODE=mock .venv/bin/guardrail pentest examples/vulnerable_demo.py --ai
```

Raw JSON for CI/CD:

```bash
.venv/bin/guardrail pentest examples/vulnerable_demo.py --json
```

Use an auth header:

```bash
.venv/bin/guardrail pentest ./myproject --auth-header "Authorization: Bearer demo-token"
```

Notes for pentest v1:

- Supports Python web targets with explicit FastAPI, Flask, or basic Django routes.
- Runs attacks only against the container it builds from your source code.
- Requires Docker on the local machine.
- Uses `--network none`, rate limiting, and a hard timeout for containment.

## Use Ollama

Start Ollama separately, then run:

```bash
GUARDRAIL_LLM_MODE=ollama GUARDRAIL_OLLAMA_MODEL=llama3:8b .venv/bin/guardrail scan examples/vulnerable_demo.py
```

## Run unit tests

```bash
.venv/bin/python -m pytest
```
