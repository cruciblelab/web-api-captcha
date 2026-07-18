"""`AdaptiveCaptchaGate` -- the Cloudflare-"Under Attack Mode" pattern:
check IP reputation first, only escalate to a visible captcha if that
connection looks suspicious; if it doesn't, ask nothing more than the
invisible layer already asks. Once someone clears it, remember that for
a while so a page refresh doesn't ask again -- captcha fatigue is a real
UX cost, not a free safety margin.

This is a distinct class from `CaptchaGate`, not a mode flag on it,
because the decision here is made *dynamically*, the first time a
verification link is actually opened (when the connecting IP is known),
rather than fixed once at construction time -- `CaptchaGate`'s
`require_captcha` is deliberately static, and retrofitting a dynamic
decision into it would have meant either breaking that simplicity for
everyone or growing a pile of conditional branches into an already-
covered, already-tested class. Composing a new small piece next to it
matches every other decision in this module: build another piece rather
than make one piece do everything.

Same "use it or don't" rule as the rest of this package: this is not
wired into anything automatically, it needs no default IP-reputation
source (see `webapi_captcha.reputation` -- bring your own), and
nothing stops you from using Cloudflare Turnstile, your own adaptive
logic, or nothing at all instead.
"""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from pydantic import BaseModel

from webapi_captcha.base import CaptchaProvider, VerificationStore
from webapi_captcha.checks import (
    AccountMatchCheck,
    CaptchaCheck,
    VerificationCheck,
    VerificationContext,
)
from webapi_captcha.events import EVENT_TYPE_CAPTCHA_VERIFIED, CaptchaVerified
from webapi_captcha.gate import CheckResult
from webapi_captcha.models import CaptchaChallenge, VerificationRequest
from webapi_captcha.reputation import IPReputationChecker
from webapi_captcha.transport import Event, Transport


class AdaptiveDecision(BaseModel):
    """The one-time-made, then-persisted answer to "does this
    verification link need a visible captcha" -- kept separate from
    `VerificationRequest` itself (a dedicated store, not a mutation of
    the shared one) so this feature needs no changes to
    `VerificationStore`/`CaptchaGate` at all."""

    requires_captcha: bool
    challenge: CaptchaChallenge | None = None


class AdaptiveDecisionStore(Protocol):
    """Where an `AdaptiveCaptchaGate` remembers the escalation decision
    it made the first time a token's link was opened, so reloading the
    page doesn't re-roll the dice (and doesn't re-charge an IP-reputation
    lookup that might cost money) on every request."""

    async def get(self, token: str) -> AdaptiveDecision | None: ...

    async def set(self, token: str, decision: AdaptiveDecision) -> None: ...

    async def delete(self, token: str) -> None: ...


class MemoryAdaptiveDecisionStore:
    """Dict-backed `AdaptiveDecisionStore`. Zero infrastructure -- the
    default."""

    def __init__(self) -> None:
        self._decisions: dict[str, AdaptiveDecision] = {}

    async def get(self, token: str) -> AdaptiveDecision | None:
        return self._decisions.get(token)

    async def set(self, token: str, decision: AdaptiveDecision) -> None:
        self._decisions[token] = decision

    async def delete(self, token: str) -> None:
        self._decisions.pop(token, None)


class TrustStore(Protocol):
    """"Don't ask again for a while" -- once a `user_id` clears an
    `AdaptiveCaptchaGate` verification, it's marked trusted until `ttl`
    passes, so a repeat visit within that window skips both the
    IP-reputation lookup and any visible captcha entirely. Keyed by
    `user_id` (a real, stable account identity -- see
    `current_user_id_resolver` -- not a client-submitted device signal)
    -- deliberately the same trust anchor `AccountMatchCheck` uses
    elsewhere in this package, not a fingerprint that could be spoofed
    the way `captcha.scoring`'s heuristics can be.

    `ip` is optional and does two independent things depending on which
    call it's passed to: `trust(..., ip=...)` records which IP earned the
    trust; `is_trusted(..., ip=...)` -- only when the *caller* opts into
    IP-binding (`AdaptiveCaptchaGate(bind_trust_to_ip=True)`) -- requires
    that recorded IP to still match, so a session that was cleared from
    one IP doesn't silently carry over to a different one (connect from
    IP A, then IP B -- re-challenge immediately). `ip=None` on either
    call preserves the original, IP-agnostic behavior -- trust follows
    the account everywhere."""

    async def is_trusted(self, user_id: int, *, ip: str | None = None) -> bool: ...

    async def trust(self, user_id: int, *, ttl: timedelta, ip: str | None = None) -> None: ...


class MemoryTrustStore:
    """Dict-backed `TrustStore`. Zero infrastructure -- the default."""

    def __init__(self) -> None:
        self._trusted: dict[int, tuple[datetime, str | None]] = {}

    async def is_trusted(self, user_id: int, *, ip: str | None = None) -> bool:
        entry = self._trusted.get(user_id)
        if entry is None:
            return False
        expires_at, bound_ip = entry
        if datetime.now(UTC) > expires_at:
            del self._trusted[user_id]
            return False
        if ip is not None and bound_ip is not None and bound_ip != ip:
            return False
        return True

    async def trust(self, user_id: int, *, ttl: timedelta, ip: str | None = None) -> None:
        self._trusted[user_id] = (datetime.now(UTC) + ttl, ip)


class AdaptiveCaptchaGate:
    """A `CaptchaGate`-shaped verification gate whose captcha requirement
    is decided dynamically, per verification link, the first time it's
    opened -- based on the connecting IP's reputation, not fixed up
    front. High-level flow, same idea as Cloudflare's "Under Attack
    Mode":

    1. `create_verification()` mints a token with no challenge yet --
       nothing is decided until someone actually opens the link.
    2. The first `get_info()`/`verify()` call for that token checks
       `trust_store` (skip everything if this account was recently
       cleared) and, failing that, asks `reputation.is_suspicious(ip)`.
       Suspicious -> a real captcha challenge is issued from
       `escalation_provider` and required. Not suspicious -> no visible
       captcha at all, only `require_account`/`extra_checks` (typically
       the invisible layer -- PoW + behavior score) apply.
    3. The decision is persisted in `decision_store` so a page reload
       doesn't re-roll it or re-charge a paid reputation lookup.
    4. On success, if `trust_store` is set, the user is marked trusted
       for `trust_ttl` -- their next verification (even a *different*
       token/purpose using the *same* trust_store) skips reputation
       entirely.

    Talks to the exact same bundled widget
    (`webapi_captcha.widget`) and `build_captcha_router()` as
    `CaptchaGate` -- the widget already renders "no captcha" or "here's
    the challenge" based on whatever `get_info()` returns, so nothing
    about the frontend needs to know this gate is adaptive.
    """

    def __init__(
        self,
        transport: Transport,
        store: VerificationStore,
        reputation: IPReputationChecker,
        escalation_provider: CaptchaProvider,
        decision_store: AdaptiveDecisionStore,
        *,
        require_account: bool = False,
        extra_checks: Sequence[VerificationCheck] | None = None,
        trust_store: TrustStore | None = None,
        trust_ttl: timedelta = timedelta(hours=24),
        bind_trust_to_ip: bool = False,
        ttl: timedelta = timedelta(minutes=15),
    ) -> None:
        self.transport = transport
        self.store = store
        self.reputation = reputation
        self.escalation_provider = escalation_provider
        self.decision_store = decision_store
        self.require_account = require_account
        self.extra_checks: list[VerificationCheck] = list(extra_checks or [])
        self.trust_store = trust_store
        self.trust_ttl = trust_ttl
        self.bind_trust_to_ip = bind_trust_to_ip
        self.ttl = ttl
        # Per-token locks -- two concurrent calls for the SAME token (a
        # double page load, a client retry, two open tabs) used to race
        # on both `_resolve_decision` (each could see no decision stored
        # yet and independently `escalation_provider.issue()` a
        # DIFFERENT challenge, so whichever `decision_store.set()` landed
        # last silently discarded the other -- the user who solved the
        # one still shown on their screen would then fail) and on
        # `verify()`'s check-then-mark-verified sequence (both could see
        # `verified=False`, both pass their checks, and both publish
        # `captcha_verified` -- a duplicate DM/credit for a bot-side
        # handler, contradicting this method's own "idempotent" claim).
        # Same setdefault-then-pop pattern as `CaptchaGate._token_locks`,
        # safe under real concurrency: any task still waiting on a lock
        # already holds its own reference to that exact Lock object
        # (grabbed via `setdefault` before it could be popped), so
        # popping here only affects the *next* caller for this token,
        # which gets a fresh lock and re-reads current state regardless.
        self._token_locks: dict[str, asyncio.Lock] = {}

    async def is_currently_trusted(self, user_id: int, *, client_ip: str | None = None) -> bool:
        """Whether `user_id` is trusted *right now*, without minting or
        touching any verification token -- the piece `PageGuard` needs to
        decide "does this visitor even need a fresh verification link" at
        all, before creating one. `False` if there's no `trust_store`
        configured. Honors `bind_trust_to_ip` the same way `_resolve_
        decision` does."""
        if self.trust_store is None:
            return False
        return await self.trust_store.is_trusted(
            user_id, ip=client_ip if self.bind_trust_to_ip else None
        )

    async def create_verification(
        self,
        *,
        user_id: int,
        guild_id: int | None = None,
        purpose: str,
        metadata: dict[str, Any] | None = None,
    ) -> VerificationRequest:
        """Mints a token with no challenge attached yet -- whether one is
        ever needed is decided later, the first time the link is
        actually opened (see `get_info`/`verify`)."""
        now = datetime.now(UTC)
        request = VerificationRequest(
            token=secrets.token_urlsafe(24),
            user_id=user_id,
            guild_id=guild_id,
            purpose=purpose,
            metadata=metadata or {},
            challenge=None,
            created_at=now,
            expires_at=now + self.ttl,
        )
        await self.store.create(request)
        return request

    async def get_info(self, token: str, *, client_ip: str | None = None) -> dict[str, Any] | None:
        """Same shape as `CaptchaGate.get_info()` -- what the frontend
        needs to render the right thing, including the same "already
        verified" vs. "gone" distinction (see that docstring for why: a
        page reload after success must not look like an expired link).
        Making/persisting the escalation decision (if not already made)
        happens here, since this is the first point at which the
        connecting IP is known."""
        request = await self._get_live(token)
        if request is None:
            return None
        if request.verified:
            return {
                "challenge": None,
                "requires_captcha": False,
                "requires_account": self.require_account,
                "verified": True,
            }
        decision = await self._resolve_decision(token, request, client_ip)
        return {
            "challenge": decision.challenge,
            "requires_captcha": decision.requires_captcha,
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
        """Same contract as `CaptchaGate.verify()`. Reuses whatever
        escalation decision `get_info()` already made for this token
        (or makes one now, if the widget's info call was somehow
        skipped) -- the decision, once made, never changes for a given
        token.

        The whole check-then-mark-verified sequence runs under this
        token's lock (see `__init__`'s `_token_locks` comment) -- two
        concurrent `verify()` calls for the same token used to both
        observe `verified=False`, both pass their checks, and both
        publish `captcha_verified`, contradicting the "idempotent" claim
        above."""
        request = await self._get_live(token)
        if request is None:
            return CheckResult(verified=False, failed_check=None, detail="link expired or unknown")
        if request.verified:
            return CheckResult(verified=True, passed=[])

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
                    return CheckResult(verified=True, passed=[])

                decision = await self._resolve_decision_locked(token, request, client_ip)
                # The check that reads ctx.request.challenge (CaptchaCheck)
                # needs it there -- AdaptiveDecision is kept in its own
                # store rather than mutated onto the shared
                # VerificationRequest, so it's attached to this in-memory
                # copy just for this call.
                request.challenge = decision.challenge

                checks: list[VerificationCheck] = []
                if self.require_account:
                    checks.append(AccountMatchCheck())
                checks.extend(self.extra_checks)
                if decision.requires_captcha:
                    checks.append(CaptchaCheck(self.escalation_provider))

                ctx = VerificationContext(
                    request=request,
                    authenticated_user_id=authenticated_user_id,
                    captcha_response=response,
                    signals=signals or {},
                    client_ip=client_ip,
                    user_agent=user_agent,
                )
                passed: list[str] = []
                for check in checks:
                    outcome = await check.run(ctx)
                    if not outcome.passed:
                        return CheckResult(
                            verified=False, failed_check=check.name, detail=outcome.detail
                        )
                    passed.append(check.name)

                await self.store.mark_verified(token)
                await self.decision_store.delete(token)
                if self.trust_store is not None:
                    await self.trust_store.trust(
                        request.user_id,
                        ttl=self.trust_ttl,
                        ip=client_ip if self.bind_trust_to_ip else None,
                    )
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
        """Identical to `CaptchaGate.on_verified` -- including the same
        `purpose=` filter, for the same reason: `captcha_verified` is one
        event type shared by every gate on a `Transport`, adaptive or
        not."""

        async def _wrapped(event: Event) -> None:
            payload = CaptchaVerified.model_validate(event.payload)
            if purpose is not None and payload.purpose != purpose:
                return
            await handler(payload)

        self.transport.subscribe(EVENT_TYPE_CAPTCHA_VERIFIED, _wrapped)

    async def _resolve_decision(
        self, token: str, request: VerificationRequest, client_ip: str | None
    ) -> AdaptiveDecision:
        """Acquires this token's lock itself -- for callers (`get_info`)
        that don't already hold it. `verify()` holds the lock for its
        whole critical section already, so it calls
        `_resolve_decision_locked` directly instead (acquiring the same
        lock twice from the same task would deadlock -- `asyncio.Lock`
        isn't reentrant)."""
        lock = self._token_locks.setdefault(token, asyncio.Lock())
        try:
            async with lock:
                return await self._resolve_decision_locked(token, request, client_ip)
        finally:
            self._token_locks.pop(token, None)

    async def _resolve_decision_locked(
        self, token: str, request: VerificationRequest, client_ip: str | None
    ) -> AdaptiveDecision:
        existing = await self.decision_store.get(token)
        if existing is not None:
            return existing

        trusted = await self.is_currently_trusted(request.user_id, client_ip=client_ip)

        requires_captcha = False
        challenge = None
        if not trusted and client_ip is not None:
            requires_captcha = await self.reputation.is_suspicious(client_ip)
            if requires_captcha:
                challenge = await self.escalation_provider.issue()

        decision = AdaptiveDecision(requires_captcha=requires_captcha, challenge=challenge)
        await self.decision_store.set(token, decision)
        # Re-read rather than trust our own locally-computed `decision`:
        # across web replicas (separate processes, so this class's own
        # in-process lock above can't help), a concurrent caller may have
        # persisted a DIFFERENT decision (a different escalation
        # challenge) microseconds before us -- `SQLAdaptiveDecisionStore.
        # set()` deliberately discards our write rather than overwriting
        # theirs in that case (see its own docstring), so the store is
        # the source of truth here, not this local variable.
        return await self.decision_store.get(token) or decision

    async def _get_live(self, token: str) -> VerificationRequest | None:
        request = await self.store.get(token)
        if request is None:
            return None
        if datetime.now(UTC) > request.expires_at:
            await self.store.delete(token)
            await self.decision_store.delete(token)
            return None
        return request
