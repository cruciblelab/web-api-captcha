"""`CaptchaGate` -- ties a *verification* to a specific
user/purpose so the rest of your app can gate on it, with the actual
verifying happening on the web.

It's called a *captcha* gate because solving a captcha is its default
layer, but it's really a general verification gate: you stack whichever
checks (`webapi_captcha.checks`) you want, and it requires all of
them to pass. Think of it as building a cake rather than picking one of
two dishes -- our captcha layer, our account-identity layer, and any of
your own layers, used whole, mixed, or not at all:

- **captcha only** (default): `require_captcha=True`. A human solves an
  image. Proves "a human," not "which account."
- **account only**: `require_captcha=False, require_account=True`. The
  user just has to be signed in (via whatever `current_user_id_resolver`
  your app wired into `build_captcha_router()`) *as the exact account the
  link was issued for*. No image. This is the trust anchor a bare captcha
  can't give -- a forwarded link solved by someone else fails.
- **both ("safety mode")**: `require_captcha=True, require_account=True`.
- **click-only**: both False, no extra checks -- possession of the
  one-time secret link is the only proof. Lowest friction; document to
  yourself that it's the weakest.
- **your own layers**: `extra_checks=[...]` -- a `PredicateCheck` wrapping
  your own function, or any object implementing `VerificationCheck` (your
  browser-fingerprint / behavioral / membership-age / anti-fraud policy).
  These run alongside ours.

Concrete scenario this was built for: a Discord giveaway bot's `/join`
command calls `create_verification()`, sends the user the resulting link
however it likes (a DM, an ephemeral reply), and replies "click the link
to verify." The web side serves it (see
`webapi_captcha.api.build_captcha_router()`). The moment every check
passes, `verify()` publishes `captcha_verified` over `Transport` -- the
bot subscribes via `on_verified()` and reacts (e.g. DMs "you're in!")
right then, no polling, whether the bot and web run in the same process
or two separate ones sharing a real message bus instead of
`InProcessTransport`. Nothing here is Discord-specific, though -- swap
"bot command" for any backend action that needs to gate on a human (and
optionally a specific signed-in account) finishing a web-side check.
"""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from webapi_captcha.base import CaptchaProvider, VerificationStore
from webapi_captcha.checks import (
    AccountMatchCheck,
    CaptchaCheck,
    VerificationCheck,
    VerificationContext,
)
from webapi_captcha.events import EVENT_TYPE_CAPTCHA_VERIFIED, CaptchaVerified
from webapi_captcha.models import CaptchaChallenge, VerificationRequest
from webapi_captcha.transport import Event, Transport


class CaptchaGate:
    def __init__(
        self,
        transport: Transport,
        store: VerificationStore,
        provider: CaptchaProvider | None = None,
        *,
        require_captcha: bool = True,
        require_account: bool = False,
        extra_checks: Sequence[VerificationCheck] | None = None,
        ttl: timedelta = timedelta(minutes=15),
    ) -> None:
        if require_captcha and provider is None:
            raise ValueError("require_captcha=True needs a CaptchaProvider (pass provider=...)")
        self.transport = transport
        self.store = store
        self.provider = provider
        self.require_captcha = require_captcha
        self.require_account = require_account
        self.ttl = ttl

        # The captcha check is put LAST on purpose: it *consumes* the
        # one-time answer when it runs, so if a cheaper, side-effect-free
        # check (account, or one of yours) is going to fail, we want it to
        # fail first -- before the captcha answer is spent -- so the user
        # doesn't lose a correctly-solved captcha just because they weren't
        # signed in yet. Verification is all-or-nothing (logical AND), so
        # this ordering doesn't change *whether* it passes, only that a
        # failure doesn't waste the captcha.
        checks: list[VerificationCheck] = []
        if require_account:
            checks.append(AccountMatchCheck())
        checks.extend(extra_checks or [])
        if require_captcha:
            assert provider is not None  # guarded above
            checks.append(CaptchaCheck(provider))
        self.checks = checks
        # Per-token locks around verify()'s check-then-mark-verified
        # sequence -- see that method's docstring for why. Same
        # setdefault-then-pop pattern as `AdaptiveCaptchaGate._token_locks`,
        # verified safe under real concurrency: any task still waiting on
        # a lock already holds its own reference to that Lock object
        # (grabbed via `setdefault` before it could be popped), so
        # popping here only affects the *next* caller for this token.
        self._token_locks: dict[str, asyncio.Lock] = {}

    async def create_verification(
        self,
        *,
        user_id: int,
        guild_id: int | None = None,
        purpose: str,
        metadata: dict[str, Any] | None = None,
    ) -> VerificationRequest:
        """Creates a one-time verification token for `user_id`. Issues a
        captcha challenge from `self.provider` only when `require_captcha`
        (otherwise `challenge` is `None` -- account-only/click-only gates
        have nothing to render). Hand the token (or a URL built from it,
        e.g. `f"https://yoursite.com/verify/{request.token}"`) to the user
        however you like -- DM, ephemeral reply, a button.
        """
        challenge = None
        if self.require_captcha:
            assert self.provider is not None  # guaranteed by __init__
            challenge = await self.provider.issue()
        now = datetime.now(UTC)
        request = VerificationRequest(
            token=secrets.token_urlsafe(24),
            user_id=user_id,
            guild_id=guild_id,
            purpose=purpose,
            metadata=metadata or {},
            challenge=challenge,
            created_at=now,
            expires_at=now + self.ttl,
        )
        await self.store.create(request)
        return request

    async def get_challenge(self, token: str) -> CaptchaChallenge | None:
        """The captcha image to render, or `None` if the token doesn't
        exist / expired / was already verified, *or* this gate simply has
        no captcha (account-only/click-only). Use `get_info()` when you
        also need to know which non-captcha checks apply."""
        request = await self._get_live(token)
        if request is None or request.verified:
            return None
        return request.challenge

    async def get_info(self, token: str, *, client_ip: str | None = None) -> dict[str, Any] | None:
        """Everything the frontend needs to render the right thing: the
        captcha image (if any), whether the user must be signed in, and
        whether this token is already verified. `None` only when the token
        is truly gone (never existed, or expired) -- an *already verified*
        token is a real, distinct outcome from "gone" (a page reload after
        a successful verification should say "you're already verified", not
        "this link is invalid/expired", which is confusing and was a real
        bug reported from physical testing: the earlier version returned
        `None` for both cases, so the two were indistinguishable to the
        frontend). `client_ip` is accepted (and ignored) purely so
        `build_captcha_router()` can call `get_info()` the same way for
        `CaptchaGate` and `AdaptiveCaptchaGate` alike -- this gate's
        requirement is static, set at construction, so it has no use for
        the connecting IP."""
        request = await self._get_live(token)
        if request is None:
            return None
        if request.verified:
            return {
                "challenge": None,
                "requires_captcha": self.require_captcha,
                "requires_account": self.require_account,
                "verified": True,
            }
        return {
            "challenge": request.challenge,
            "requires_captcha": self.require_captcha,
            "requires_account": self.require_account,
            "verified": False,
        }

    async def verify(
        self,
        token: str,
        response: str | None = None,
        *,
        authenticated_user_id: int | None = None,
        signals: dict[str, Any] | None = None,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> CheckResult:
        """Runs every configured check; the verification passes only if
        they *all* pass. `response` is the captcha answer (ignored by a
        gate with no `CaptchaCheck`); `authenticated_user_id` is the
        currently-signed-in user's id (the web layer resolves this via
        `current_user_id_resolver` -- `AccountMatchCheck` needs it);
        `signals` is passed straight to your own checks; `client_ip` is the
        server's own observation of the connecting IP (unlike `signals`,
        not client-forgeable) -- see `VerificationContext.client_ip` for
        why this exists (writing your own IP-reputation check).
        `user_agent` is the same kind of server-observed value, the
        request's own `User-Agent` header -- see `VerificationContext.
        user_agent` and `signals.reject_headless_user_agent`.

        Idempotent: verifying an already-verified token returns success
        without re-running the checks (a page refresh re-posting the same
        form doesn't re-consume a one-time captcha answer). On success,
        marks it verified and publishes `captcha_verified`.

        The check-then-mark-verified sequence runs under this token's
        lock: two concurrent `verify()` calls for the same token (a
        double-click, a client retry, nothing server-side prevented it)
        used to both observe `verified=False`, both pass their checks,
        and both publish `captcha_verified` -- contradicting the
        "idempotent" claim above (a duplicate DM/credit for a bot-side
        `on_verified()` handler).
        """
        request = await self._get_live(token)
        if request is None:
            return CheckResult(verified=False, failed_check=None, detail="link expired or unknown")
        if request.verified:
            return CheckResult(verified=True, passed=[c.name for c in self.checks])

        lock = self._token_locks.setdefault(token, asyncio.Lock())
        try:
            async with lock:
                # Re-read: a concurrent verify() may have already
                # completed while we waited for the lock.
                request = await self._get_live(token)
                if request is None:
                    return CheckResult(
                        verified=False, failed_check=None, detail="link expired or unknown"
                    )
                if request.verified:
                    return CheckResult(verified=True, passed=[c.name for c in self.checks])

                ctx = VerificationContext(
                    request=request,
                    authenticated_user_id=authenticated_user_id,
                    captcha_response=response,
                    signals=signals or {},
                    client_ip=client_ip,
                    user_agent=user_agent,
                )
                passed: list[str] = []
                for check in self.checks:
                    outcome = await check.run(ctx)
                    if not outcome.passed:
                        return CheckResult(
                            verified=False, failed_check=check.name, detail=outcome.detail
                        )
                    passed.append(check.name)

                await self.store.mark_verified(token)
                await self.transport.publish(
                    Event(
                        type=EVENT_TYPE_CAPTCHA_VERIFIED,
                        payload=CaptchaVerified(
                            token=token,
                            user_id=request.user_id,
                            guild_id=request.guild_id,
                            purpose=request.purpose,
                            metadata=request.metadata,
                            checks_passed=passed,
                        ).model_dump(),
                    )
                )
                return CheckResult(verified=True, passed=passed)
        finally:
            self._token_locks.pop(token, None)

    def on_verified(
        self,
        handler: Callable[[CaptchaVerified], Awaitable[None]],
        *,
        purpose: str | None = None,
    ) -> None:
        """Convenience wrapper around `transport.subscribe` so bot-side
        code doesn't need to know the event type string or unwrap the
        payload itself -- `handler` receives an already-parsed
        `CaptchaVerified` (including `checks_passed`).

        **Important if you run more than one `CaptchaGate` on the same
        `Transport`** (a giveaway gate and a separate appeal gate, say):
        `captcha_verified` is one shared event type, published by every
        gate on that transport -- `on_verified()` on any one of them
        receives *all* of their events, not just its own. Pass `purpose=`
        to filter to the one this handler actually cares about (matched
        against `VerificationRequest.purpose`/`CaptchaVerified.purpose`);
        leaving it `None` keeps the old unfiltered behavior, which is only
        safe when this is the only gate on this transport.
        """

        async def _wrapped(event: Event) -> None:
            payload = CaptchaVerified.model_validate(event.payload)
            if purpose is not None and payload.purpose != purpose:
                return
            await handler(payload)

        self.transport.subscribe(EVENT_TYPE_CAPTCHA_VERIFIED, _wrapped)

    async def _get_live(self, token: str) -> VerificationRequest | None:
        request = await self.store.get(token)
        if request is None:
            return None
        if datetime.now(UTC) > request.expires_at:
            await self.store.delete(token)
            return None
        return request


class CheckResult:
    """The outcome of `CaptchaGate.verify()`. Truthy iff `verified` -- so
    `if await gate.verify(...):` still reads naturally -- while also
    carrying which check failed (for a helpful frontend message, e.g.
    "please sign in first") or which checks passed."""

    def __init__(
        self,
        *,
        verified: bool,
        failed_check: str | None = None,
        detail: str | None = None,
        passed: list[str] | None = None,
    ) -> None:
        self.verified = verified
        self.failed_check = failed_check
        self.detail = detail
        self.passed = passed or []

    def __bool__(self) -> bool:
        return self.verified
