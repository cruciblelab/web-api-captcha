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

from fastapi import Request

from webapi_captcha.adaptive import AdaptiveCaptchaGate
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
    ) -> None:
        self.gate = gate
        self.verify_url = verify_url
        self.cookie_name = cookie_name
        self.cookie_max_age = cookie_max_age
        self.purpose = purpose
        self.extra_suspicious = extra_suspicious

    async def require_human(
        self,
        request: Request,
        *,
        authenticated_user_id: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str | None:
        """Call at the top of a protected route. Raises `PageGuardRedirect`
        if this visitor needs to solve a captcha before proceeding.
        Otherwise returns normally -- and, if this was a brand new
        anonymous visitor (no cookie yet), returns the raw value your
        route must set as `cookie_name` on whatever response it returns
        (`response.set_cookie(guard.cookie_name, value, httponly=True,
        samesite="lax", max_age=guard.cookie_max_age)`); returns `None`
        when there's nothing new to set (an existing cookie, or a
        signed-in account, which needs no cookie at all)."""
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

        if await self.gate.is_currently_trusted(visitor_id, client_ip=client_ip):
            return new_cookie_value

        suspicious = False
        if client_ip is not None:
            suspicious = await self.gate.reputation.is_suspicious(client_ip)
        if not suspicious and self.extra_suspicious is not None:
            suspicious = self.extra_suspicious(request)

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
