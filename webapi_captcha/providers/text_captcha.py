"""Self-hosted classic captcha -- renders a random alphanumeric string as
a distorted PNG (see `webapi_captcha.rendering`) and checks the
typed string against what's stored server-side. Needs the
`discord-webapi[captcha]` extra (Pillow).
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

from webapi_captcha._shared import verify_pending_challenge
from webapi_captcha.base import CaptchaStore
from webapi_captcha.models import CaptchaChallenge, PendingCaptcha
from webapi_captcha.rendering import render_captcha_image

# Excludes visually-ambiguous characters (0/O, 1/I/l) -- a human squinting
# at a distorted image shouldn't have to guess which one it is.
_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


class TextCaptchaProvider:
    """`CaptchaProvider` that asks the user to read a random distorted
    string back -- the classic visual captcha, distinct from
    `MathCaptchaProvider`'s arithmetic question."""

    kind = "text"

    def __init__(
        self,
        store: CaptchaStore,
        *,
        length: int = 6,
        ttl: timedelta = timedelta(minutes=10),
        max_attempts: int = 5,
    ) -> None:
        self.store = store
        self.length = length
        self.ttl = ttl
        self.max_attempts = max_attempts

    async def issue(self) -> CaptchaChallenge:
        text = "".join(secrets.choice(_ALPHABET) for _ in range(self.length))
        challenge_id = secrets.token_urlsafe(16)
        now = datetime.now(UTC)
        await self.store.create(
            PendingCaptcha(
                challenge_id=challenge_id,
                kind=self.kind,
                answer=text,
                created_at=now,
                expires_at=now + self.ttl,
            )
        )
        return CaptchaChallenge(
            challenge_id=challenge_id,
            kind=self.kind,
            prompt="Type the characters shown in the image.",
            image_data_uri=render_captcha_image(text),
            expires_at=now + self.ttl,
        )

    async def verify(self, challenge_id: str, response: str) -> bool:
        return await verify_pending_challenge(
            self.store,
            challenge_id,
            response,
            max_attempts=self.max_attempts,
            normalize=lambda r: r.strip().upper(),
        )
