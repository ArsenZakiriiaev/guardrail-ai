"""
functional/runner.py

Sends a single HTTP request for a UseCase against a live base URL and
returns the status code + response body.
"""
from __future__ import annotations

import time
from urllib.parse import urljoin

import requests

from functional.models import UseCase


class HttpResult:
    __slots__ = ("status_code", "body", "elapsed_ms", "error")

    def __init__(
        self,
        status_code: int = 0,
        body: str = "",
        elapsed_ms: float = 0.0,
        error: str | None = None,
    ) -> None:
        self.status_code = status_code
        self.body = body
        self.elapsed_ms = elapsed_ms
        self.error = error


def execute(
    use_case: UseCase,
    base_url: str,
    *,
    auth_headers: dict[str, str] | None = None,
    timeout_seconds: float = 10.0,
) -> HttpResult:
    """
    Build an HTTP request from *use_case* and send it to *base_url*.
    Redirects are followed but the final status code is returned as-is.
    """
    url = _build_url(base_url, use_case.endpoint)
    headers = {**(auth_headers or {}), **use_case.request_headers}
    started = time.perf_counter()

    try:
        response = requests.request(
            method=use_case.method,
            url=url,
            headers=headers,
            params=use_case.request_params or None,
            json=use_case.request_body or None,
            timeout=timeout_seconds,
            allow_redirects=True,
        )
        elapsed = round((time.perf_counter() - started) * 1000, 1)
        return HttpResult(
            status_code=response.status_code,
            body=response.text,
            elapsed_ms=elapsed,
        )
    except requests.RequestException as exc:
        elapsed = round((time.perf_counter() - started) * 1000, 1)
        return HttpResult(elapsed_ms=elapsed, error=str(exc))


def _build_url(base: str, endpoint: str) -> str:
    """Join base URL with endpoint path, ensuring no double slashes."""
    base = base.rstrip("/")
    endpoint = endpoint if endpoint.startswith("/") else f"/{endpoint}"
    return base + endpoint
