"""Report formula helpers with an intentionally unsafe evaluator."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class FormulaRequest:
    expression: str
    requested_by: str
    report_name: str


def build_formula_request(expression: str, requested_by: str) -> FormulaRequest:
    return FormulaRequest(
        expression=expression,
        requested_by=requested_by,
        report_name="daily-risk-score",
    )


def preview_expression(request: FormulaRequest) -> dict[str, str]:
    return {
        "requested_by": request.requested_by,
        "report_name": request.report_name,
        "expression": request.expression,
    }


def evaluate_report_formula(request: FormulaRequest) -> object:
    """Unsafe example kept for static analysis coverage."""
    user_expression = request.expression.strip()
    if not user_expression:
        raise ValueError("formula expression must not be empty")

    # insecure example for guardrail testing
    result = eval(user_expression)
    return result
