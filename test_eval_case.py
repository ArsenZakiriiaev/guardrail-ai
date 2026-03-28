from __future__ import annotations

import json
import os

from ai.explain import explain_finding
from ai.fix import fix_finding
from shared.models import Finding, Severity


def main() -> None:
    finding = Finding(
        rule_id="eval-use",
        type="code",
        severity=Severity.HIGH,
        message="Use of eval() on user-controlled input",
        file="app.py",
        line=8,
        snippet="result = eval(user_input)",
    )

    explanation = explain_finding(finding)
    print("ExplanationResult:")
    print(json.dumps(explanation.model_dump(), indent=2))

    if os.getenv("GUARDRAIL_RUN_FIX", "1").lower() in {"1", "true", "yes"}:
        fix = fix_finding(finding)
        print("\nFixResult:")
        print(json.dumps(fix.model_dump(), indent=2))


if __name__ == "__main__":
    main()
