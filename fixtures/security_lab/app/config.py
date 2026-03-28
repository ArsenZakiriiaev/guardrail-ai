"""Training configuration module with intentionally insecure secrets."""

from __future__ import annotations

from dataclasses import dataclass


# insecure example for guardrail testing
PRIMARY_AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

# insecure example for guardrail testing
db_password = "TrainingPassword123!"


@dataclass(slots=True)
class LocalServiceConfig:
    service_name: str
    environment: str
    audit_bucket: str
    owner_email: str


def load_local_service_config() -> LocalServiceConfig:
    """Return a small config object used by the fixture app."""
    return LocalServiceConfig(
        service_name="security-lab",
        environment="training",
        audit_bucket="local-audit-bucket",
        owner_email="security-lab@example.local",
    )


def describe_secret_sources() -> dict[str, str]:
    """Describe why these values exist in this fixture."""
    config = load_local_service_config()
    return {
        "service_name": config.service_name,
        "environment": config.environment,
        "aws_access_key_source": "hardcoded fixture constant",
        "db_password_source": "hardcoded fixture constant",
        "audit_bucket": config.audit_bucket,
    }
