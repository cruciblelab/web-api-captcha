"""`FallbackCaptchaProvider` -- composes several `CaptchaProvider`s into
one, trying each in order until one's `issue()` actually succeeds.

This is about resilience against a *provider* outage, not a captcha
solve: reCAPTCHA/hCaptcha/Turnstile's own shipped `issue()` never makes a
network call (their "challenge" is just their static `site_key` -- the
provider's own JS widget does the real network round-trip later, when
the visitor interacts with it), so for those specifically there's
nothing for this class to protect against at `issue()` time. What this
*does* protect against, honestly: a self-hosted provider whose
`CaptchaStore` write fails (a database blip), or -- the main case -- your
own custom `CaptchaProvider` wrapping a paid service whose `issue()`
really does call out over the network and really can time out or 5xx.
Bring the providers in the order you want tried; this just gives you a
clean way to degrade to the next one instead of surfacing an error page.

A verification, once issued, can only ever be checked by the *same*
provider that issued it -- a human solved *that* provider's specific
challenge, so there's no meaningful "try a different provider" step at
`verify()` time. `challenge_id`s from this class are prefixed with which
child provider issued them so `verify()` always routes back to the right
one, and this class's `verify()` never re-tries a different provider
itself.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

from webapi_captcha.base import CaptchaProvider
from webapi_captcha.models import CaptchaChallenge

logger = logging.getLogger("webapi_captcha")

_SEPARATOR = ":"


class FallbackCaptchaProvider:
    """`kind` is this composite's own identity (for whatever key you
    register it under in `app.state.webapi_captcha_providers` --
    same as any other provider); the `CaptchaChallenge` `issue()` actually
    returns carries the *real* kind of whichever child provider handled
    it, so the bundled widget (and your own frontend) renders it exactly
    as if that child had been used directly -- this class is invisible
    past the moment of choosing which child to use.
    """

    kind = "fallback"

    def __init__(self, providers: Sequence[CaptchaProvider]) -> None:
        if not providers:
            raise ValueError("FallbackCaptchaProvider needs at least one provider")
        self.providers = list(providers)

    async def issue(self) -> CaptchaChallenge:
        last_exc: Exception | None = None
        for index, provider in enumerate(self.providers):
            try:
                challenge = await provider.issue()
            except Exception as exc:  # noqa: BLE001 -- deliberately broad: any
                # custom provider's issue() failure should fall through to
                # the next one, not just a pre-guessed subset of exception
                # types.
                logger.warning(
                    "FallbackCaptchaProvider: provider %d (%s) failed to issue a "
                    "challenge, trying the next one",
                    index,
                    getattr(provider, "kind", type(provider).__name__),
                    exc_info=True,
                )
                last_exc = exc
                continue
            return challenge.model_copy(
                update={"challenge_id": f"{index}{_SEPARATOR}{challenge.challenge_id}"}
            )
        assert last_exc is not None  # guaranteed: providers is non-empty (checked in __init__)
        raise last_exc

    async def verify(self, challenge_id: str, response: str) -> bool:
        index_str, _, child_challenge_id = challenge_id.partition(_SEPARATOR)
        try:
            index = int(index_str)
            provider = self.providers[index]
        except (ValueError, IndexError):
            # Malformed or out-of-range prefix -- not a challenge_id this
            # instance (in its current configuration) ever issued. Fail
            # closed rather than guessing which child to ask.
            return False
        return await provider.verify(child_challenge_id, response)
