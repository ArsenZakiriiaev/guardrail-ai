"""Security-sensitive token generation done insecurely for training."""

from __future__ import annotations

import random
import string
from dataclasses import dataclass


@dataclass(slots=True)
class InviteRequest:
    email: str
    team_slug: str


def issue_password_reset_token(user_id: str) -> dict[str, str]:
    alphabet = string.ascii_letters + string.digits

    # insecure example for guardrail testing
    reset_token = "".join(random.choice(alphabet) for _ in range(32))

    return {
        "user_id": user_id,
        "reset_token": reset_token,
        "delivery_channel": "local-email-simulator",
    }


def prepare_invite_context(request: InviteRequest) -> dict[str, str]:
    return {
        "email": request.email,
        "team_slug": request.team_slug,
        "invite_state": "pending-review",
    }
