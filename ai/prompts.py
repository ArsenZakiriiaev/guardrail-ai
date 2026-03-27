from __future__ import annotations

from shared.models import Finding


def build_explain_prompt(finding: Finding) -> str:
    return f"""You are GuardRail AI, a security assistant for developers.

Analyze the security finding below and return ONLY valid JSON.

Output rules:
- Return exactly one JSON object.
- Do not use markdown.
- Do not use code fences.
- Do not add any text before or after the JSON.
- Use this exact schema:
  {{
    "summary": "short plain-language summary",
    "risk": "real security risk and impact",
    "fix": "one practical safe remediation",
    "confidence": "low|medium|high"
  }}
- Keep summary short and clear.
- Keep risk concrete and realistic.
- Keep fix practical for a developer.
- Do not repeat or expose full secret values from the snippet.

Finding metadata:
- rule_id: {finding.rule_id}
- type: {finding.type}
- severity: {finding.severity}
- message: {finding.message}
- file: {finding.file}
- line: {finding.line}

Code snippet:
{finding.snippet}
"""


def build_fix_prompt(finding: Finding) -> str:
    return f"""You are GuardRail AI, a secure coding assistant for developers.

Generate a minimal safe code fix for the finding below and return ONLY valid JSON.

Output rules:
- Return exactly one JSON object.
- Do not use markdown.
- Do not use code fences.
- Do not add any text before or after the JSON.
- Use this exact schema:
  {{
    "fixed_code": "updated code snippet only",
    "explanation": "brief explanation of the change",
    "confidence": "low|medium|high"
  }}
- Preserve existing behavior as much as possible.
- Prefer the smallest safe fix for the shown snippet.
- Do not invent unrelated refactors.
- Do not expose full secret values from the snippet.

Finding metadata:
- rule_id: {finding.rule_id}
- type: {finding.type}
- severity: {finding.severity}
- message: {finding.message}
- file: {finding.file}
- line: {finding.line}

Code snippet:
{finding.snippet}
"""
