from __future__ import annotations

import os

from ai.parser import parse_explain_response
from ai.prompts import build_explain_prompt
from shared.models import ExplanationResult, Finding
from shared.redaction import sanitize_snippet


DEFAULT_CLAUDE_MODEL = "claude-opus-4-6"
DEFAULT_MAX_TOKENS = 512
_DEFAULT_SYSTEM_PROMPT = "You are a senior application security engineer. Return only valid JSON."


def ask_claude(
    prompt: str,
    *,
    api_key: str | None = None,
    model: str | None = None,
    system: str | None = None,
    max_tokens: int = DEFAULT_MAX_TOKENS,
) -> str:
    key = (api_key or os.getenv("ANTHROPIC_API_KEY", "")).strip()
    if not key:
        raise ValueError("Claude requires ANTHROPIC_API_KEY or --claude-api-key.")

    try:
        import anthropic
    except ImportError as exc:
        raise RuntimeError("Claude requires the 'anthropic' package.") from exc

    client = anthropic.Anthropic(api_key=key)
    response = client.messages.create(
        model=(model or os.getenv("GUARDRAIL_CLAUDE_MODEL") or DEFAULT_CLAUDE_MODEL).strip(),
        max_tokens=max_tokens,
        system=(system or _DEFAULT_SYSTEM_PROMPT),
        messages=[{"role": "user", "content": prompt}],
    )
    return next((block.text for block in response.content if getattr(block, "type", "") == "text"), "")


def explain_finding_with_claude(
    finding: Finding,
    *,
    api_key: str | None = None,
    model: str | None = None,
    independent: bool = False,
) -> ExplanationResult:
    raw_response = ask_claude(
        _build_independent_review_prompt(finding) if independent else build_explain_prompt(finding),
        api_key=api_key,
        model=model,
    )
    return parse_explain_response(raw_response)


def _build_independent_review_prompt(finding: Finding) -> str:
    snippet = sanitize_snippet(finding.snippet, finding.type, finding.rule_id)

    return f"""You are performing an independent second-pass review of a security finding.

Return ONLY valid JSON using this schema:
{{
  "summary": "short specific summary",
  "risk": "concrete exploitability and impact",
  "fix": "practical remediation specific to this case",
  "confidence": "low|medium|high"
}}

Requirements:
- Tailor the response to this exact finding, code snippet, file, and line.
- Do not use generic filler like "potential security issue" unless the evidence is truly weak.
- If the signal looks weak or could be a false positive, say why in the risk field, but still explain what should be checked.
- Keep each field concise, but specific.

Finding metadata:
- rule_id: {finding.rule_id}
- type: {finding.type}
- severity: {finding.severity}
- message: {finding.message}
- file: {finding.file}
- line: {finding.line}

Code snippet:
{snippet}
"""
