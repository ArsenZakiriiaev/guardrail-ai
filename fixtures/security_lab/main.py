"""Entry point for the GuardRail security fixture project."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def build_lab_manifest() -> dict[str, object]:
    base_dir = Path(__file__).resolve().parent
    return {
        "project": "security_lab",
        "base_dir": str(base_dir),
        "mode": "safe_demo_only",
        "insecure_modules": [
            "app.config",
            "app.expression_engine",
            "app.process_runner",
            "app.serialization",
            "app.yaml_handlers",
            "app.tempfiles",
            "app.crypto_utils",
            "app.tokens",
            "app.database",
        ],
    }


def main() -> int:
    manifest = build_lab_manifest()

    print("Security Lab Fixture")
    print(json.dumps(manifest, indent=2))
    print()

    try:
        from app.safe_examples import SafeDemoService
    except ModuleNotFoundError as exc:
        print(
            "Safe demo dependencies are missing. "
            "Install fixtures/security_lab/requirements.txt before running main.py.",
            file=sys.stderr,
        )
        print(f"Missing module: {exc.name}", file=sys.stderr)
        return 1

    service = SafeDemoService()
    safe_report = service.run_demo()
    print("Safe demo output")
    print(json.dumps(safe_report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
