"""Hardcoded secrets used only for detection coverage."""

from __future__ import annotations


# insecure example for guardrail testing
api_token = "internal-training-token-0001"

# insecure example for guardrail testing
GITHUB_PERSONAL_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"

# insecure example for guardrail testing
SLACK_BOT_TOKEN = "xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx"

# insecure example for guardrail testing
PRIVATE_KEY_PEM = """
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDqtrainingfixture
4B8x7mM3QmZtN0Q7sW4A1e9j9m1L6h3nG9g4q8k6A7u2p5v8x3d4f5g6h7j8k9l0m1n
vFixtureOnlyDoNotUseInProductionOrForRealSecrets1234567890abcdefghijkl
-----END PRIVATE KEY-----
"""


def describe_secret_inventory() -> dict[str, str]:
    return {
        "api_token_owner": "training fixture",
        "github_token_owner": "training fixture",
        "slack_token_owner": "training fixture",
        "private_key_owner": "training fixture",
    }
