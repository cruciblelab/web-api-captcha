"""`PageGuard` -- the "Cloudflare in front of a whole page" primitive,
built on `AdaptiveCaptchaGate`. `AdaptiveCaptchaGate` protects ONE
already-minted verification token (a link handed to a specific user for
a specific purpose); `PageGuard` protects an arbitrary ROUTE -- any page
a visitor navigates to, whether or not they're signed in yet, including
a page that comes *before* your own login even starts (there's no stable
account id to key anything on at that point, which is exactly the gap
this fills).

High-level flow:

1. A visitor is identified per request -- the signed-in account's id if
   there is one, otherwise a random value in an httpOnly cookie (minted
   on first visit).
2. If that visitor is already trusted (`AdaptiveCaptchaGate.trust_store`,
   optionally IP-bound via `bind_trust_to_ip` -- see `adaptive.py`),
   the page loads normally, no captcha shown, nothing checked again.
3. Otherwise the connecting IP's reputation is checked (plus, if
   configured, one extra opt-in signal -- e.g. a missing
   `Accept-Language` header, a real server-side, no-JS-needed heuristic).
   Clean -> the page loads normally, invisibly, exactly as if nothing
   happened. Suspicious -> the visitor is redirected to a fresh
   `AdaptiveCaptchaGate` verification link instead of seeing the page at
   all.

Same "use it or don't" rule as the rest of this package: this is a
small, optional, composable layer. Bring your own `AdaptiveCaptchaGate`
(any `IPReputationChecker`, any `CaptchaProvider`, your own `TrustStore`,
reCAPTCHA/hCaptcha/Turnstile instead of a bundled provider, ...), use
`PageGuard` to sit in front of it, write your own equivalent, or don't
gate pages at all -- nothing here is required to use the rest of
`webapi_captcha`.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from webapi_captcha.adaptive import AdaptiveCaptchaGate
from webapi_captcha.api import CurrentUserIdResolver, _no_current_user
from webapi_captcha.ratelimit import TokenBucketLimiter
from webapi_captcha.risk import RiskLevel
from webapi_captcha.signals import DEFAULT_HEADLESS_UA_PATTERNS

DEFAULT_COOKIE_NAME = "wac_visitor_id"
DEFAULT_COOKIE_MAX_AGE = 60 * 60 * 24 * 365  # 1 year


class PageGuardRedirect(Exception):
    """Raised by `PageGuard.require_human` when a visitor needs to solve
    a captcha before the route they asked for can run. Register a
    handler for it on your `FastAPI` app:

        @app.exception_handler(PageGuardRedirect)
        async def _redirect(request, exc):
            resp = RedirectResponse(exc.location)
            if exc.new_cookie_value is not None:
                resp.set_cookie(exc.cookie_name, exc.new_cookie_value,
                                 httponly=True, samesite="lax", max_age=exc.cookie_max_age)
            return resp

    A plain exception, not a special FastAPI response type, so this
    module needs no knowledge of your app's routing -- and the cookie
    (if a brand new anonymous visitor needed one minted) travels with
    the exception so the redirect response can carry it. Cookies can't
    just be set on an ambient injected `Response` parameter here: FastAPI
    only applies that object's headers/cookies when your endpoint
    *doesn't* return its own `Response` instance, and this module's
    endpoints (and every page in this project's examples) do."""

    def __init__(
        self,
        location: str,
        *,
        new_cookie_value: str | None = None,
        cookie_name: str = DEFAULT_COOKIE_NAME,
        cookie_max_age: int = DEFAULT_COOKIE_MAX_AGE,
    ) -> None:
        self.location = location
        self.new_cookie_value = new_cookie_value
        self.cookie_name = cookie_name
        self.cookie_max_age = cookie_max_age
        super().__init__(f"redirect required -> {location}")


def _pseudo_user_id(raw: str) -> int:
    """A stable, deterministic (NOT a real account id) integer derived
    from an arbitrary string -- lets an anonymous visitor's cookie value
    be used anywhere `AdaptiveCaptchaGate`/`TrustStore` expect a
    `user_id: int`, without loosening those Protocols to `int | str`
    everywhere just for this one case. A collision with a real signed-in
    account's id, or between two different anonymous visitors, is
    astronomically unlikely (64 bits, keyed off a cryptographically
    random cookie) -- and even then only ever affects trust/verification
    records for that one pseudo-identity, never someone else's; if
    `require_account=True` is also configured on the gate,
    `AccountMatchCheck` still requires the *real* signed-in
    account to match, so a pseudo-id can never impersonate one."""
    digest = hashlib.sha256(raw.encode()).digest()
    return int.from_bytes(digest[:8], "big")


class PageGuard:
    """See the module docstring for the overall flow. Construct one per
    `AdaptiveCaptchaGate` you want fronting arbitrary pages (as opposed
    to that gate's normal use, protecting one minted verification link).
    """

    def __init__(
        self,
        gate: AdaptiveCaptchaGate,
        *,
        verify_url: Callable[[str, str], str],
        cookie_name: str = DEFAULT_COOKIE_NAME,
        cookie_max_age: int = DEFAULT_COOKIE_MAX_AGE,
        purpose: str = "page_guard",
        extra_suspicious: Callable[[Request], bool] | None = None,
        default_min_level: RiskLevel = RiskLevel.MINIMAL,
    ) -> None:
        self.gate = gate
        self.verify_url = verify_url
        self.cookie_name = cookie_name
        self.cookie_max_age = cookie_max_age
        self.purpose = purpose
        self.extra_suspicious = extra_suspicious
        self.default_min_level = default_min_level

    async def require_human(
        self,
        request: Request,
        *,
        authenticated_user_id: int | None = None,
        metadata: dict[str, Any] | None = None,
        min_level: RiskLevel | None = None,
        trust_token: str | None = None,
        expected_subject_id: str | None = None,
        required_purpose: str | None = None,
    ) -> str | None:
        """Call at the top of a protected route. Raises `PageGuardRedirect`
        if this visitor needs to solve a captcha before proceeding.
        Otherwise returns normally -- and, if this was a brand new
        anonymous visitor (no cookie yet), returns the raw value your
        route must set as `cookie_name` on whatever response it returns
        (`response.set_cookie(guard.cookie_name, value, httponly=True,
        samesite="lax", max_age=guard.cookie_max_age)`); returns `None`
        when there's nothing new to set (an existing cookie, or a
        signed-in account, which needs no cookie at all).

        `trust_token`: an optional cross-site trust receipt (see
        `webapi_captcha.receipts`/`AdaptiveCaptchaGate.is_currently_
        trusted`) -- this package never reads it from `request` itself;
        extract it from wherever your app keeps it (a header, a cookie,
        your own session) and pass the raw string in. `expected_subject_
        id`/`required_purpose`: passed straight through to `TrustTokenVerifier
        .verify()` -- pass the local visitor id you expect this token to
        belong to (and/or the purpose you expect it to have been issued
        for) to have that binding enforced instead of left entirely to
        you as the caller."""
        client_ip = request.client.host if request.client else None
        new_cookie_value: str | None = None

        if authenticated_user_id is not None:
            visitor_id = authenticated_user_id
        else:
            raw = request.cookies.get(self.cookie_name)
            if raw is None:
                raw = secrets.token_urlsafe(24)
                new_cookie_value = raw
            visitor_id = _pseudo_user_id(raw)

        if await self.gate.is_currently_trusted(
            visitor_id,
            client_ip=client_ip,
            trust_token=trust_token,
            expected_subject_id=expected_subject_id,
            required_purpose=required_purpose,
        ):
            return new_cookie_value

        floor = self.default_min_level
        if min_level is not None:
            floor = max(floor, min_level)
        # Same short-circuit intent as before (skip the sync predicate
        # once escalation is already decided some other way): now
        # generalized from "IP reputation already flagged this" to "the
        # floor from purpose/running-risk/explicit min_level already
        # clears the challenge threshold" -- observably identical for
        # every caller that doesn't combine those with extra_suspicious.
        if floor < self.gate.min_level_for_challenge and self.extra_suspicious is not None:
            if self.extra_suspicious(request):
                floor = max(floor, self.gate.min_level_for_challenge)

        assessment = await self.gate.assess_risk(
            client_ip=client_ip,
            user_id=visitor_id,
            purpose=self.purpose,
            route=request.url.path,
            signals={},
            min_level=floor,
        )
        suspicious = assessment.level >= self.gate.min_level_for_challenge

        if not suspicious:
            return new_cookie_value

        verification = await self.gate.create_verification(
            user_id=visitor_id, purpose=self.purpose, metadata=metadata or {}
        )
        raise PageGuardRedirect(
            self.verify_url(verification.token, str(request.url)),
            new_cookie_value=new_cookie_value,
            cookie_name=self.cookie_name,
            cookie_max_age=self.cookie_max_age,
        )


def missing_accept_language(request: Request) -> bool:
    """An optional `extra_suspicious` predicate: real browsers virtually
    always send a non-empty `Accept-Language` header; a script that
    didn't bother setting one is a mild, honest, zero-JS signal --
    server-side, checkable before the page even renders. Like every
    other heuristic in this package: soft evidence, not a verdict on its
    own (a privacy-focused browser extension or a corporate proxy can
    strip it too) -- combine it with IP reputation, don't rely on it
    alone, which is exactly what `PageGuard` does (this only adds to,
    never replaces, the reputation check)."""
    return not request.headers.get("accept-language")


def suspicious_user_agent(patterns: tuple[str, ...] | None = None) -> Callable[[Request], bool]:
    """Builds an `extra_suspicious` predicate for `PageGuard` matching
    `webapi_captcha.signals.reject_headless_user_agent`'s default
    denylist against the request's own `User-Agent` header -- the same
    server-side, checkable-before-the-page-renders signal as
    `missing_accept_language`, catching a well-known headless-browser/
    automation tool's *default* identity (same honest caveat: trivially
    spoofed by anyone who bothers to set their own `User-Agent`).

    Unlike `missing_accept_language` (already a ready-to-use predicate),
    this is a *factory* -- call it to get the predicate, so you can
    override `patterns` without reaching into
    `webapi_captcha.signals` directly:

        PageGuard(gate, verify_url=..., extra_suspicious=suspicious_user_agent())
    """
    needles = tuple(p.lower() for p in (patterns or DEFAULT_HEADLESS_UA_PATTERNS))

    def _predicate(request: Request) -> bool:
        ua = request.headers.get("user-agent", "").lower()
        return any(needle in ua for needle in needles)

    return _predicate


_DEFAULT_PASSIVE_LIMITER = TokenBucketLimiter(max_calls=6, per_seconds=60.0)


class PassiveSignalBody(BaseModel):
    signals: dict[str, Any] = {}


class PassiveSignalResult(BaseModel):
    level: str  # RiskLevel member name, lowercased -- informational only today


def build_passive_risk_router(
    guard: PageGuard,
    *,
    mount_path: str = "/api/captcha/passive-signal",
    current_user_id_resolver: CurrentUserIdResolver = _no_current_user,
    rate_limiter: TokenBucketLimiter | None = None,
) -> APIRouter:
    """Feeds ongoing, passively-collected signals into a visitor's
    RUNNING risk level (`guard.gate.running_risk_store`) *between* page
    loads -- what `require_human()` consults on every subsequent request
    via `assess_risk()`'s running-risk floor, so a visitor who looked
    clean on their first page view can be escalated on a later one
    without solving anything or waiting for IP reputation itself to
    change. See `webapi_captcha.risk.RunningRiskStore` for why this is
    monotonic (a level can only ever go up within its TTL).

    Mounts nothing meaningful (an empty `APIRouter`) if
    `guard.gate.risk_engine` or `guard.gate.running_risk_store` is
    `None` -- this mechanism is opt-in additive and needs BOTH to mean
    anything: an engine to turn signals into a level, a store to
    remember that level between requests.

    Frontend contract: `POST` here periodically (e.g. every N seconds,
    on scroll milestones, or before unload) with whatever `signals` your
    page has accumulated so far -- the same shape
    `SignalScoreCheck`/the bundled widget already collect. This package
    ships no beacon script of its own yet; wire your own small `POST`,
    or extend `widget.js`'s existing signal collection to also fire here
    on an interval -- that frontend piece is a separate, later addition
    from this server-side contract.
    """
    router = APIRouter(tags=["captcha"])
    limiter = rate_limiter or _DEFAULT_PASSIVE_LIMITER

    if guard.gate.risk_engine is None or guard.gate.running_risk_store is None:
        return router

    @router.post(mount_path)
    async def report_passive_signal(
        body: PassiveSignalBody,
        request: Request,
        authenticated_user_id: int | None = Depends(current_user_id_resolver),
    ) -> PassiveSignalResult:
        client_ip = request.client.host if request.client else "unknown"
        limiter.check(client_ip)

        if authenticated_user_id is not None:
            visitor_id = authenticated_user_id
        else:
            raw = request.cookies.get(guard.cookie_name)
            if raw is None:
                # No cookie yet -- this endpoint never mints one (only
                # require_human() does, on a real page load); nothing to
                # attribute this signal to.
                return PassiveSignalResult(level=RiskLevel.MINIMAL.name.lower())
            visitor_id = _pseudo_user_id(raw)

        assessment = await guard.gate.assess_risk(
            client_ip=request.client.host if request.client else None,
            user_id=visitor_id,
            purpose=guard.purpose,
            signals=body.signals,
        )
        assert guard.gate.running_risk_store is not None  # guarded by the early return above
        new_level = await guard.gate.running_risk_store.bump(
            visitor_id, assessment.level, ttl=guard.gate.running_risk_ttl
        )
        return PassiveSignalResult(level=new_level.name.lower())

    return router
