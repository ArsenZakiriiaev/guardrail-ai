"""
shared/models.py — общий формат данных между Dev 1 и Dev 2.
Точка синхронизации: оба девелопера используют эти классы.
"""

from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """
    Сырой результат от Semgrep (создаёт Dev 2).
    Dev 1 принимает список Finding и обогащает их через AI.
    """
    file: str
    line: int
    rule_id: str
    message: str
    snippet: str
    severity: Severity = Severity.MEDIUM


@dataclass
class EnrichedFinding:
    """
    Финальный результат после AI-обогащения (создаёт Dev 1).
    CLI Dev 2 выводит этот объект пользователю.
    """
    file: str
    line: int
    rule_id: str
    message: str
    snippet: str
    severity: Severity

    # Заполняет Dev 1
    explanation: Optional[str] = None
    fix_available: bool = False
    fixed_code: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "rule_id": self.rule_id,
            "message": self.message,
            "snippet": self.snippet,
            "severity": self.severity.value,
            "explanation": self.explanation,
            "fix_available": self.fix_available,
            "fixed_code": self.fixed_code,
        }
