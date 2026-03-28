# GuardRail AI

GuardRail AI is a minimal DevSecOps copilot for developers.

It scans Python code with Semgrep, normalizes findings into a shared model, and optionally enriches them with AI-generated security explanations.

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
- Shared `Finding` contract
- AI explanation pipeline with `mock` and `ollama`
- CLI output in table or JSON format
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

## Use Ollama

Start Ollama separately, then run:

```bash
GUARDRAIL_LLM_MODE=ollama GUARDRAIL_OLLAMA_MODEL=llama3:8b .venv/bin/guardrail scan examples/vulnerable_demo.py
```

## Run unit tests

```bash
.venv/bin/python -m pytest
```
