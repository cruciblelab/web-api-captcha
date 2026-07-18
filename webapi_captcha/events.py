from typing import Any

from pydantic import BaseModel

EVENT_TYPE_CAPTCHA_VERIFIED = "captcha_verified"


class CaptchaVerified(BaseModel):
    """Transport event payload published by `CaptchaGate.verify()` the
    moment a bot-gated verification link is solved -- the bot process
    subscribes (`CaptchaGate.on_verified(...)`) to react (e.g. DM the user
    "you're in!") the instant it fires, works whether the bot and the web
    process handling the verification are the same process or not.

    `schema_version` lets a bot process and a web process running
    different discord-webapi versions (independent deploys, see
    `RedisTransport`) stay forward/backward tolerant instead of one
    choking on the other's shape.
    """

    schema_version: int = 1
    token: str
    user_id: int
    guild_id: int | None
    purpose: str
    metadata: dict[str, Any] = {}
    # Which checks the verification actually passed (e.g. ["captcha",
    # "account"]) -- lets a bot-side handler react to *how strongly* the
    # user was verified, not just that they were. Empty for a click-only
    # gate (possession of the link was the only proof).
    checks_passed: list[str] = []
