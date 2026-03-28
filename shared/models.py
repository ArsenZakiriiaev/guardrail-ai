from __future__ import annotations

from enum import StrEnum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="ignore")

    rule_id: str = Field(..., min_length=1)
    type: str = Field(..., min_length=1)
    severity: Severity
    message: str = Field(..., min_length=1)
    file: str = Field(..., min_length=1)
    line: int = Field(..., ge=1)
    snippet: str = ""

    @field_validator("type")
    @classmethod
    def normalize_type(cls, value: str) -> str:
        return value.lower()

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, value: Severity | str) -> Severity | str:
        if isinstance(value, str):
            return value.lower()
        return value

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")


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

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")


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

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")


class EnrichedFinding(Finding):
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

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")
