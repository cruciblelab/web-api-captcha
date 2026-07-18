"""Self-hosted arithmetic captcha -- renders "7 + 4 = ?" as a distorted
PNG (see `webapi_captcha.rendering`) and checks the typed numeric
answer against what's stored server-side. Needs the
`discord-webapi[captcha]` extra (Pillow).
"""

from __future__ import annotations

import random
import secrets
from datetime import UTC, datetime, timedelta

from webapi_captcha._shared import verify_pending_challenge
from webapi_captcha.base import CaptchaStore
from webapi_captcha.models import CaptchaChallenge, PendingCaptcha
from webapi_captcha.rendering import render_captcha_image

_OPERATORS = ("+", "-", "*")


class MathCaptchaProvider:
    """`CaptchaProvider` that asks the user to solve a small arithmetic
    problem shown in a distorted image. Addition/subtraction use 1-20
    (subtraction never goes negative); multiplication is kept to single
    digits (1-9) specifically -- 1-20 x 1-20 can produce a problem like
    "16 x 19", which is not the trivial-for-a-human arithmetic this is
    supposed to be, just a different kind of hard captcha."""

    kind = "math"

    def __init__(
        self,
        store: CaptchaStore,
        *,
        ttl: timedelta = timedelta(minutes=10),
        max_attempts: int = 5,
    ) -> None:
        self.store = store
        self.ttl = ttl
        self.max_attempts = max_attempts

    async def issue(self) -> CaptchaChallenge:
        operator = random.choice(_OPERATORS)
        if operator == "*":
            a = random.randint(1, 9)
            b = random.randint(1, 9)
        else:
            a = random.randint(1, 20)
            b = random.randint(1, 20)
        if operator == "-" and b > a:
            a, b = b, a  # keep subtraction non-negative -- less confusing
        answer = {"+": a + b, "-": a - b, "*": a * b}[operator]
        prompt_text = f"{a} {operator} {b} = ?"

        challenge_id = secrets.token_urlsafe(16)
        now = datetime.now(UTC)
        await self.store.create(
            PendingCaptcha(
                challenge_id=challenge_id,
                kind=self.kind,
                answer=str(answer),
                created_at=now,
                expires_at=now + self.ttl,
            )
        )
        return CaptchaChallenge(
            challenge_id=challenge_id,
            kind=self.kind,
            prompt="Solve the problem shown in the image.",
            image_data_uri=render_captcha_image(prompt_text),
            expires_at=now + self.ttl,
        )

    async def verify(self, challenge_id: str, response: str) -> bool:
        return await verify_pending_challenge(
            self.store, challenge_id, response, max_attempts=self.max_attempts
        )
