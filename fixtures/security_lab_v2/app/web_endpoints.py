"""Web-style handlers with intentionally insecure patterns."""

from __future__ import annotations

from flask import Flask, Response, redirect
import requests


app = Flask(__name__)


def fetch_remote_preview(user_url: str) -> str:
    # insecure example for guardrail testing
    response = requests.get(user_url, timeout=3)
    return response.text


def call_internal_status(api_url: str) -> int:
    # insecure example for guardrail testing
    response = requests.get(api_url, verify=False, timeout=3)
    return response.status_code


def continue_after_login(next_url: str):
    # insecure example for guardrail testing
    return redirect(next_url)


def build_debug_response(username: str) -> Response:
    response = Response("ok", mimetype="text/plain")

    # insecure example for guardrail testing
    response.headers["X-Trace"] = f"user={username}\r\nX-Admin: true"

    # insecure example for guardrail testing
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


def start_debug_server() -> None:
    # insecure example for guardrail testing
    app.run(debug=True, use_reloader=False)
