from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Finding(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="ignore")

    rule_id: str = Field(..., min_length=1)
    type: str = Field(..., min_length=1)
    severity: str = Field(..., min_length=1)
    message: str = Field(..., min_length=1)
    file: str = Field(..., min_length=1)
    line: int = Field(..., ge=1)
    snippet: str

    @field_validator("type", "severity")
    @classmethod
    def normalize_lowercase(cls, value: str) -> str:
        return value.lower()


class ExplanationResult(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="ignore")

    summary: str = Field(..., min_length=1)
    risk: str = Field(..., min_length=1)
    fix: str = Field(..., min_length=1)
    confidence: Optional[str] = None

    @field_validator("confidence")
    @classmethod
    def normalize_confidence(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None

        normalized = value.lower()
        if normalized not in {"low", "medium", "high"}:
            return "low"
        return normalized


class FixResult(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="ignore")

    fixed_code: str = Field(..., min_length=1)
    explanation: str = Field(..., min_length=1)
    confidence: Optional[str] = None

    @field_validator("confidence")
    @classmethod
    def normalize_confidence(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None

        normalized = value.lower()
        if normalized not in {"low", "medium", "high"}:
            return "low"
        return normalized
