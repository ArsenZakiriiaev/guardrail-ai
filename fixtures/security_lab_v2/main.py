"""Entry point for the extended GuardRail fixture project."""

from __future__ import annotations

import json
from pathlib import Path


def build_manifest() -> dict[str, object]:
    base_dir = Path(__file__).resolve().parent
    return {
        "project": "security_lab_v2",
        "base_dir": str(base_dir),
        "entrypoint_behavior": "manifest-only",
        "modules": [
            "app.file_access",
            "app.archives",
            "app.xml_processing",
            "app.web_endpoints",
            "app.jwt_examples",
            "app.secrets_store",
            "app.deserialization",
            "app.crypto_configs",
            "app.directory_queries",
            "app.templates",
            "app.authz",
            "app.process_variants",
        ],
    }


def main() -> int:
    print("Security Lab V2 Fixture")
    print(json.dumps(build_manifest(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
