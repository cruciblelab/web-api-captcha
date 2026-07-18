from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class CaptchaChallenge(BaseModel):
    """What a `CaptchaProvider.issue()` hands back for the frontend to
    render. Different provider families use different fields:

    - **Image providers** (Math/Text) set `image_data_uri` (a
      `data:image/png;base64,...` URI, ready for an `<img src="...">`).
    - **Third-party widgets** (reCAPTCHA/hCaptcha) set `site_key` -- their
      own JS embed does the rendering.
    - **Parameterized providers** (proof-of-work, path-trace) set `params`
      -- a structured, provider-defined bag the frontend reads to run the
      challenge itself (the PoW prefix/difficulty, the line to trace, ...).
      This is also the extension point for your own provider: put whatever
      your JS needs in `params`.
    """

    challenge_id: str
    kind: str
    prompt: str
    image_data_uri: str | None = None
    site_key: str | None = None
    params: dict[str, Any] = {}
    expires_at: datetime | None = None


class PendingCaptcha(BaseModel):
    """A self-hosted provider's own record of "challenge_id X's correct
    answer is Y" -- internal to `CaptchaStore`, never sent to the
    frontend. Not used by third-party providers at all (Google/hCaptcha
    hold their own challenge state, this library never sees it)."""

    challenge_id: str
    kind: str
    answer: str
    attempts: int = 0
    created_at: datetime
    expires_at: datetime


class VerificationRequest(BaseModel):
    """One bot-gated verification -- e.g. "prove you're human before
    joining this giveaway." Created by `CaptchaGate.create_verification()`,
    resolved (and `verified` flipped to `True`) when its checks all pass.
    `purpose`/`metadata` are entirely yours -- the gate never interprets
    them, it just carries them through to the `captcha_verified` Transport
    event so your bot-side handler knows what to do next (e.g.
    `purpose="giveaway_entry"`, `metadata={"giveaway_id": "..."}`).

    `challenge` is `None` for verifications that don't use a captcha at all
    (account-only or click-only gates -- see `CaptchaGate`), since there's
    no image to render or answer to store in those modes.
    """

    token: str
    user_id: int
    guild_id: int | None = None
    purpose: str
    metadata: dict[str, Any] = {}
    challenge: CaptchaChallenge | None = None
    verified: bool = False
    created_at: datetime
    expires_at: datetime
