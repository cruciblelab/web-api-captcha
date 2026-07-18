"""Protocol definitions for the captcha subsystem. Write your own
`CaptchaProvider` (wrapping any third-party service or captcha library,
not just the two we ship) or your own `CaptchaStore`/`VerificationStore`
by implementing these -- no inheritance needed, same "bring your own
Store" pattern as everywhere else in this library.
"""

from __future__ import annotations

from typing import Protocol

from webapi_captcha.models import CaptchaChallenge, PendingCaptcha, VerificationRequest


class CaptchaProvider(Protocol):
    """A pluggable captcha backend. Two shapes fit this one Protocol:

    - **Self-hosted** (`MathCaptchaProvider`/`TextCaptchaProvider`):
      `issue()` generates a challenge image server-side and remembers the
      correct answer in its own `CaptchaStore`; `verify()` checks the
      typed answer against that.
    - **Third-party widget** (`ReCaptchaProvider`/`HCaptchaProvider`):
      `issue()` just returns your `site_key` for the frontend widget to
      render itself (no image, no locally-stored answer -- the provider
      holds that); `verify()` posts the widget's response token to the
      provider's own verify API.

    Bring your own: wrap any other captcha service or library by
    implementing just these two methods -- nothing else in this package
    (the dashboard router, `CaptchaGate`) needs to know which kind of
    provider it's talking to.
    """

    kind: str

    async def issue(self) -> CaptchaChallenge: ...

    async def verify(self, challenge_id: str, response: str) -> bool: ...


class CaptchaStore(Protocol):
    """Persistence for a self-hosted provider's (Math/Text) pending
    challenges. **Not** used by third-party providers -- reCAPTCHA/
    hCaptcha hold their own challenge state, this library never sees it.
    """

    async def create(self, pending: PendingCaptcha) -> None: ...

    async def get(self, challenge_id: str) -> PendingCaptcha | None: ...

    async def increment_attempts(self, challenge_id: str) -> int: ...

    async def delete(self, challenge_id: str) -> None: ...


class VerificationStore(Protocol):
    """Persistence for `CaptchaGate`'s one-time bot-gated verification
    links."""

    async def create(self, request: VerificationRequest) -> None: ...

    async def get(self, token: str) -> VerificationRequest | None: ...

    async def mark_verified(self, token: str) -> None: ...

    async def delete(self, token: str) -> None: ...
