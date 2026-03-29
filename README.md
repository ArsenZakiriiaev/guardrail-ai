# Guardrail AI

Guardrail AI is a local-first security workflow for Python applications. It combines static scanning, policy evaluation, isolated HTTP pentesting, functional testing from a PDF spec, a web UI, and optional AI-assisted analysis in one toolchain.

The current primary development line is the `fix` branch. This README describes the code as it exists there.

## What It Does

Guardrail AI currently supports four main workflows:

1. `scan`
   Runs Semgrep-based static analysis, normalizes findings, applies policy rules, and can attach AI explanations plus an optional second AI review pass.
2. `pentest`
   Builds and runs a temporary local target from source inside Docker, discovers endpoints, and executes constrained HTTP pentest probes against that isolated app.
3. `pentest-url`
   Audits a live HTTP(S) URL with passive checks and optional allowlisted active probes.
4. `functional`
   Reads a PDF specification, extracts use cases, executes each use case against a running app, and grades the responses.

On top of that, the project also includes:

- a FastAPI web UI
- a local pentest runner for browser-to-local Docker workflows
- git hooks
- policy configuration
- audit logs
- a file watcher / daemon mode

## High-Level Architecture

### Static Analysis

- [`scanner/semgrep_runner.py`](/home/sonny/guardrail-ai/scanner/semgrep_runner.py) runs Semgrep.
- [`scanner/parser.py`](/home/sonny/guardrail-ai/scanner/parser.py) normalizes raw Semgrep results into shared finding objects.
- [`policy/engine.py`](/home/sonny/guardrail-ai/policy/engine.py) decides which findings are blocked, warned, or ignored.
- [`ai/orchestrator.py`](/home/sonny/guardrail-ai/ai/orchestrator.py) can enrich findings with explanations.
- [`ai/second_pass.py`](/home/sonny/guardrail-ai/ai/second_pass.py) adds an optional second AI review pass.

### Pentest Engine

- [`pentest/endpoint_parser.py`](/home/sonny/guardrail-ai/pentest/endpoint_parser.py) discovers Flask, FastAPI, and basic Django-style routes from source.
- [`pentest/runtime.py`](/home/sonny/guardrail-ai/pentest/runtime.py) builds and runs the target in Docker.
- [`pentest/engine.py`](/home/sonny/guardrail-ai/pentest/engine.py) performs the isolated code pentest.
- [`pentest/url_engine.py`](/home/sonny/guardrail-ai/pentest/url_engine.py) performs live URL pentests.
- [`pentest/reporting.py`](/home/sonny/guardrail-ai/pentest/reporting.py) renders standalone HTML reports.

### Functional Testing

- [`functional/claude_client.py`](/home/sonny/guardrail-ai/functional/claude_client.py) extracts use cases from a PDF and grades results.
- [`functional/runner.py`](/home/sonny/guardrail-ai/functional/runner.py) executes the actual HTTP requests.
- [`functional/engine.py`](/home/sonny/guardrail-ai/functional/engine.py) orchestrates the full run and builds the report.
- [`functional/reporter.py`](/home/sonny/guardrail-ai/functional/reporter.py) renders a standalone HTML report.

### Web UI

- [`web/app.py`](/home/sonny/guardrail-ai/web/app.py) exposes the FastAPI backend.
- [`web/static/index.html`](/home/sonny/guardrail-ai/web/static/index.html) contains the single-page frontend for scan, pentest, URL pentest, and functional testing.

## Current Feature Set

### `scan`

`guardrail scan` is the code-first SAST workflow.

It currently provides:

- Semgrep-backed scanning for Python security issues and secrets
- a normalized finding model shared with the rest of the system
- snippet sanitization / redaction before output
- policy-based blocking, warning, and ignore behavior
- table output for humans
- JSON output for CI
- optional AI explanations
- optional second AI review pass with `--claude-api-key`

Typical rules in the shipped ruleset include:

- hardcoded secrets and credentials
- `eval(...)`
- unsafe shell execution
- unsafe deserialization
- weak crypto choices
- SQL built through unsafe interpolation

### `pentest`

`guardrail pentest` is the isolated application pentest mode. It is meant for code you control locally.

It currently provides:

- source-based endpoint discovery
- containerized execution in Docker
- attack planning from discovered routes and SAST hints
- checks for SQL injection, second-order SQL injection, reflected XSS, SSTI, path traversal, open redirect, command injection, SSRF, security headers, cookies, and CORS issues
- deduped findings
- sorted findings by importance
- standalone HTML reports
- request logging for the executed probes

AI in pentest mode is not used as a source-code reviewer. In the current `fix` branch it is used as a constrained pentest planner that proposes additional HTTP probes for discovered endpoints. The engine executes the requests itself and only reports confirmed deltas.

### `pentest-url`

`guardrail pentest-url` is the live target workflow for an existing HTTP(S) application.

It supports:

- passive checks for any reachable HTTP(S) URL
- optional active checks when the host is explicitly allowlisted
- optional auth headers
- optional AI explanations
- JSON and HTML reporting

### `functional`

`guardrail functional` runs use cases from a PDF spec against a live app.

It works in three phases:

1. extract use cases from the PDF
2. execute the described HTTP flows against the provided base URL
3. judge each result against the expected behavior

This mode is intended for requirements-driven verification, not exploit discovery.

## Requirements

Minimum runtime requirements:

- Python 3.11+
- Docker for `pentest`
- network access for Anthropic-backed functional testing and AI-assisted flows

Notes:

- `scan` works without Docker.
- `pentest-url` works without Docker.
- `functional` requires a PDF input and an Anthropic API key.
- `pentest` requires working access to the local Docker daemon.

## Installation

Clone the repo and install it into a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

Verify the CLI:

```bash
guardrail version
```

If you do not activate the virtual environment, run commands through the local binary instead:

```bash
.venv/bin/guardrail version
```

## Quick Start

### Scan a File

```bash
.venv/bin/guardrail scan examples/vulnerable_demo.py
```

JSON output:

```bash
.venv/bin/guardrail scan examples/vulnerable_demo.py --json
```

Quick pass/fail mode for CI:

```bash
.venv/bin/guardrail check examples/vulnerable_demo.py
```

Strict real-time monitoring (every save/create/update is checked immediately):

```bash
.venv/bin/guardrail watch . --strict
```

Brain tracking mode (risk scoring, escalation on repeated risky edits, periodic summaries):

```bash
.venv/bin/guardrail watch . --strict --brain --summary-interval 10
```

Strict daemon mode with desktop notifications on clean saves too:

```bash
.venv/bin/guardrail start . --strict --notify-clean
```

Full background brain tracker:

```bash
.venv/bin/guardrail start . --strict --brain --notify-clean --summary-interval 10
```

### Run an Isolated Pentest from Source

```bash
.venv/bin/guardrail pentest examples/vulnerable_demo.py
```

With AI explanations and HTML report:

```bash
.venv/bin/guardrail pentest examples/vulnerable_demo.py --ai --html-report .guardrail/pentest-report.html
```

### Audit a Live URL

Passive checks:

```bash
.venv/bin/guardrail pentest-url https://example.com --json
```

Allowlisted active checks:

```bash
.venv/bin/guardrail pentest-url https://app.example.com \
  --active \
  --allow-host app.example.com \
  --html-report .guardrail/url-report.html
```

### Run Functional Tests from a PDF Spec

```bash
.venv/bin/guardrail functional \
  --spec requirements.pdf \
  --url http://127.0.0.1:8000
```

With explicit API key and HTML report:

```bash
.venv/bin/guardrail functional \
  --spec requirements.pdf \
  --url http://127.0.0.1:8000 \
  --api-key "$ANTHROPIC_API_KEY" \
  --html-report .guardrail/functional-report.html
```

## AI Modes

There are two different AI usage patterns in this repository.

### AI for `scan`

`scan` can run:

- regular AI explanations
- an optional second AI review pass with `--claude-api-key`

This is useful when you want extra explanation depth or an independent AI opinion attached to already-detected findings.

### AI for `pentest`

In the current `fix` branch, AI is used as a pentest planner, not as a file reviewer. The pentest engine discovers endpoints first, then asks AI for additional constrained HTTP probes against the discovered target. The engine executes those probes itself and validates the resulting response deltas.

### AI for `functional`

`functional` uses Anthropic-backed extraction and analysis:

- extract structured use cases from a PDF
- judge whether the real response satisfies the use case

You can pass the key explicitly:

```bash
--api-key "$ANTHROPIC_API_KEY"
```

Or rely on the environment variable:

```bash
export ANTHROPIC_API_KEY=...
```

## Web UI

Run the local web UI:

```bash
source .venv/bin/activate
uvicorn web.app:app --host 127.0.0.1 --port 8000 --reload
```

Then open:

```text
http://127.0.0.1:8000
```

The UI currently supports:

- code scan from pasted files
- scan from zip upload
- source pentest from pasted files
- source pentest from zip upload
- live URL pentest
- functional testing from PDF

## Pentest Runner

The pentest runner exists for cases where the web UI is remote but Docker is only available on your local machine.

Start it locally:

```bash
.venv/bin/guardrail pentest-runner --host 127.0.0.1 --port 8001
```

With explicit CORS origin:

```bash
.venv/bin/guardrail pentest-runner \
  --host 127.0.0.1 \
  --port 8001 \
  --allow-origin https://your-app.up.railway.app
```

With a runner token:

```bash
.venv/bin/guardrail pentest-runner \
  --host 127.0.0.1 \
  --port 8001 \
  --allow-origin https://your-app.up.railway.app \
  --runner-token YOUR_TOKEN
```

Optional allowlist for active URL pentests via the runner:

```bash
.venv/bin/guardrail pentest-runner \
  --allow-active-host app.example.com \
  --allow-active-host *.example.com
```

Health check:

```bash
curl http://127.0.0.1:8001/api/health
```

Expected response:

```json
{"status":"ok","service":"pentest-runner"}
```

## Functional Testing Details

Functional testing is backend-side HTTP execution. The browser does not execute the test cases directly.

That means:

- if you open the hosted UI on Railway and enter `http://127.0.0.1:8000`, the backend will try to connect to its own localhost, not yours
- if you want to test your own local app through a hosted UI, you need a public tunnel
- if both the UI backend and the target app are local on the same machine, `http://127.0.0.1:8000` is correct

The functional pipeline is implemented in [`functional/engine.py`](/home/sonny/guardrail-ai/functional/engine.py).

It does the following:

1. uploads the PDF spec and extracts structured use cases
2. coerces those use cases into the internal `UseCase` model
3. executes each use case as a real HTTP request
4. grades each response against the expected behavior
5. returns a `FunctionalTestReport`

The report includes:

- total use cases
- passed
- failed
- errors
- per-use-case analysis
- optional standalone HTML report

## Watcher, Protect, and Daemon Commands

Watch the current directory for changes:

```bash
.venv/bin/guardrail watch
```

Set up policy, install hooks, run an initial scan, then watch:

```bash
.venv/bin/guardrail protect
```

Start daemon mode:

```bash
.venv/bin/guardrail start
```

Stop daemon mode:

```bash
.venv/bin/guardrail stop
```

Show watcher, hooks, and policy status:

```bash
.venv/bin/guardrail status
```

## Hooks

Install git hooks:

```bash
.venv/bin/guardrail hooks install
```

Remove git hooks:

```bash
.venv/bin/guardrail hooks uninstall
```

Show hook status:

```bash
.venv/bin/guardrail hooks status
```

## Policy

Create a local policy file:

```bash
.venv/bin/guardrail policy init
```

Show the active policy:

```bash
.venv/bin/guardrail policy show
```

Default rules live in:

- [`policy/default.yml`](/home/sonny/guardrail-ai/policy/default.yml)
- [`rules/python-security.yml`](/home/sonny/guardrail-ai/rules/python-security.yml)
- [`rules/secrets.yml`](/home/sonny/guardrail-ai/rules/secrets.yml)
- [`rules/advanced.yml`](/home/sonny/guardrail-ai/rules/advanced.yml)
- [`rules/eval.yml`](/home/sonny/guardrail-ai/rules/eval.yml)

## Audit Log

Show recent audit entries:

```bash
.venv/bin/guardrail audit
```

Limit the output:

```bash
.venv/bin/guardrail audit --limit 50
```

Filter by event type:

```bash
.venv/bin/guardrail audit --event pentest_cli
```

## Development

Run the full test suite:

```bash
.venv/bin/python -m pytest
```

Run a narrower subset:

```bash
.venv/bin/python -m pytest tests/test_cli.py tests/test_pentest_engine.py tests/test_pentest_url.py
```

Compile-check edited modules:

```bash
python -m py_compile cli/main.py pentest/engine.py functional/engine.py web/app.py
```

## Limitations and Scope

This is not a general remote exploitation framework. It is a constrained developer security workflow.

Current practical limits:

- `pentest` only works on local code it can build and run in Docker
- `pentest-url` active checks require explicit allowlisting
- `functional` quality depends heavily on the PDF quality and how concrete the use cases are
- `functional` is HTTP-based, not a browser automation framework
- hosted UI plus local target requires either a local UI instance or a public tunnel
- Docker permissions must be fixed at the OS level if your user cannot access `/var/run/docker.sock`

## Common Troubleshooting

### `guardrail: command not found`

Use the virtualenv binary or activate the environment:

```bash
source .venv/bin/activate
guardrail version
```

Or:

```bash
.venv/bin/guardrail version
```

### `Spec file not found: requirements.pdf`

The file path is wrong or the PDF does not exist in the current working directory. Use an absolute path if needed.

### `Connection refused` in `functional`

Usually one of these:

- the target app is not running
- you used `localhost` but only `127.0.0.1` is reachable in your environment
- the UI backend is remote and cannot access your machine's localhost

### Docker permission denied

Your user likely does not have access to the Docker socket. A common permanent fix is:

```bash
sudo usermod -aG docker $USER
```

Then log out and log back in.

## Repository Layout

```text
ai/           AI explanation, parsing, fixes, second-pass logic
audit/        audit logging
cli/          Typer CLI entrypoint
functional/   PDF-driven functional test engine
hooks/        git hook installation and status
pentest/      endpoint discovery, runtime, pentest engines, reporting
policy/       policy loading and evaluation
rules/        Semgrep and policy rule files
scanner/      Semgrep execution and finding normalization
shared/       common models and redaction helpers
watcher/      file watcher and daemon mode
web/          FastAPI backend and frontend UI
examples/     demo vulnerable targets
tests/        pytest suite
```

## Version

Current packaged version: `0.3.0`
