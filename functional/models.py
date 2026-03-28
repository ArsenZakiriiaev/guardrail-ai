from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator


class UseCase(BaseModel):
    name: str = ""
    description: str = ""
    endpoint: str = "/"
    method: str = "GET"
    request_body: dict[str, Any] = Field(default_factory=dict)
    request_params: dict[str, str] = Field(default_factory=dict)
    request_headers: dict[str, str] = Field(default_factory=dict)
    expected_status: int | None = None
    expected_behavior: str = ""

    @field_validator("method")
    @classmethod
    def normalize_method(cls, v: str) -> str:
        return v.upper()

    @field_validator("endpoint")
    @classmethod
    def normalize_endpoint(cls, v: str) -> str:
        return v if v.startswith("/") else f"/{v}"


class FunctionalTestResult(BaseModel):
    use_case: UseCase
    passed: bool = False
    status: str = "error"  # "pass" | "fail" | "error"
    actual_status_code: int | None = None
    actual_response_body: str = ""
    analysis: str = ""
    failure_reason: str | None = None


class FunctionalTestReport(BaseModel):
    pdf_path: str
    target: str
    total: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    use_cases: list[UseCase] = Field(default_factory=list)
    results: list[FunctionalTestResult] = Field(default_factory=list)
    html_report_path: str | None = None
