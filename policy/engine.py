"""
policy/engine.py — движок политик.
Загружает .guardrail.yml из проекта, определяет какие
находки блокировать, а какие — только предупреждать.
"""

from __future__ import annotations

import importlib.resources
from pathlib import Path
from typing import Optional

import yaml

from shared.models import Finding, Severity


DEFAULT_POLICY_FILE = "default.yml"


def _load_default_policy() -> dict:
    policy_dir = Path(__file__).parent
    default_path = policy_dir / DEFAULT_POLICY_FILE
    if default_path.exists():
        return yaml.safe_load(default_path.read_text()) or {}
    return {}


def load_policy(project_root: str | Path | None = None) -> dict:
    """
    Загружает политику из .guardrail.yml в корне проекта.
    Если файла нет — возвращает дефолтную политику.
    """
    if project_root:
        custom = Path(project_root) / ".guardrail.yml"
        if custom.exists():
            loaded = yaml.safe_load(custom.read_text()) or {}
            merged = _load_default_policy()
            merged.update(loaded)
            return merged

    return _load_default_policy()


def init_policy(project_root: str | Path) -> Path:
    """
    Создаёт .guardrail.yml в проекте с дефолтными настройками.
    Возвращает путь до созданного файла.
    """
    default = _load_default_policy()
    target = Path(project_root) / ".guardrail.yml"
    if target.exists():
        return target

    content = yaml.dump(default, default_flow_style=False, allow_unicode=True, sort_keys=False)

    header = (
        "# Guardrail-AI Policy Configuration\n"
        "# Edit this file to customize security policies for your project.\n"
        "#\n"
        "# block_severity: findings at this level or above will BLOCK commits/pushes\n"
        "# warn_severity: findings at this level or above will generate warnings\n"
        "# ignored_rules: list of rule_ids to skip\n"
        "# watched_extensions: file types to monitor in watch mode\n"
        "#\n\n"
    )
    target.write_text(header + content)
    return target


class PolicyDecision:
    """Результат оценки политики для одной находки."""

    __slots__ = ("action", "reason")

    BLOCK = "block"
    WARN = "warn"
    IGNORE = "ignore"

    def __init__(self, action: str, reason: str = ""):
        self.action = action
        self.reason = reason

    def __repr__(self) -> str:
        return f"PolicyDecision({self.action!r}, {self.reason!r})"


_SEVERITY_ORDER = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


def evaluate_finding(finding: Finding, policy: dict) -> PolicyDecision:
    """
    Оценивает одну находку по политике.
    Возвращает PolicyDecision: block / warn / ignore.
    """
    ignored_rules: list[str] = policy.get("ignored_rules", [])
    if finding.rule_id in ignored_rules:
        return PolicyDecision(PolicyDecision.IGNORE, f"Rule {finding.rule_id} is in ignored list")

    block_sev_str = policy.get("block_severity", "high")
    warn_sev_str = policy.get("warn_severity", "medium")

    try:
        block_threshold = _SEVERITY_ORDER[Severity(block_sev_str)]
    except (ValueError, KeyError):
        block_threshold = _SEVERITY_ORDER[Severity.HIGH]

    try:
        warn_threshold = _SEVERITY_ORDER[Severity(warn_sev_str)]
    except (ValueError, KeyError):
        warn_threshold = _SEVERITY_ORDER[Severity.MEDIUM]

    finding_level = _SEVERITY_ORDER.get(finding.severity, 1)

    if finding_level >= block_threshold:
        return PolicyDecision(
            PolicyDecision.BLOCK,
            f"Severity {finding.severity.value} >= block threshold ({block_sev_str})",
        )

    if finding_level >= warn_threshold:
        return PolicyDecision(
            PolicyDecision.WARN,
            f"Severity {finding.severity.value} >= warn threshold ({warn_sev_str})",
        )

    return PolicyDecision(PolicyDecision.IGNORE, "Below warning threshold")


def evaluate_findings(findings: list[Finding], policy: dict) -> dict[str, list]:
    """
    Оценивает список находок по политике.
    Возвращает dict: {blocked: [...], warned: [...], ignored: [...]}.
    """
    result: dict[str, list] = {"blocked": [], "warned": [], "ignored": []}

    for f in findings:
        decision = evaluate_finding(f, policy)
        if decision.action == PolicyDecision.BLOCK:
            result["blocked"].append((f, decision))
        elif decision.action == PolicyDecision.WARN:
            result["warned"].append((f, decision))
        else:
            result["ignored"].append((f, decision))

    return result
