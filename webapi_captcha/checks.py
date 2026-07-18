"""Composable verification *checks* -- the "layers" a `CaptchaGate` stacks
to decide whether a verification passes.

A captcha alone only proves "a human did this," never "*which* account
did this" -- so a link that's been forwarded to someone else still
solves. That's the whole reason `AccountMatchCheck` exists: it ties the
solve to whichever user your own app's login resolves as currently
signed in (see `webapi_captcha.api.build_captcha_router`'s
`current_user_id_resolver`), which is what makes a verification
trustworthy rather than just "someone, somewhere, filled in a captcha."

Every check is one small, independent unit implementing the
`VerificationCheck` Protocol. A gate runs a list of them and requires *all*
to pass (logical AND). Mix ours with your own freely:

- captcha only:      `require_captcha=True`
- account only:      `require_captcha=False, require_account=True`
- both ("safety"):   `require_captcha=True, require_account=True`
- click-only:        both False, no extra checks (possession of the
                     one-time link is itself the proof -- lowest friction)
- your own layers:   `extra_checks=[...]` (a `PredicateCheck`, or any
                     object implementing `VerificationCheck` -- e.g. your
                     own browser-fingerprint / behavioral / "member for N
                     days" logic; this library gives you the hook, you
                     write the policy)
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from webapi_captcha.base import CaptchaProvider
from webapi_captcha.models import VerificationRequest


@dataclass
class VerificationContext:
    """Everything a check gets to look at. `signals` is an arbitrary,
    client-submitted bag (user-agent, a fingerprint token, behavioral
    data, ...) -- untrusted by definition, so a check that reads it is
    responsible for deciding how much to trust it.

    `client_ip` is different: it's the server's own observation of who
    connected (from `Request.client.host`, via `build_captcha_router()`),
    not something the client claims about itself -- as trustworthy as
    your reverse proxy's `X-Forwarded-For` handling, but never
    client-forgeable the way every entry in `signals` is. This is the
    hook for building your own IP-reputation check (a blocklist, a
    third-party lookup, whatever) as a `PredicateCheck`/`VerificationCheck`
    reading `ctx.client_ip` -- the library ships no such check itself (no
    opinion on which reputation source you'd trust), it just makes sure
    the IP is actually available to write one against.

    `user_agent` is the same kind of server-observed value as `client_ip`
    (the request's own `User-Agent` header, via `build_captcha_router()`)
    -- not something the client's JavaScript claims in `signals`, but not
    unspoofable either (any HTTP client sets this header to whatever it
    wants); it's simply a *different, harder-to-coordinate* lie than a
    JS-reported flag, since it's set once per request rather than
    computed by script logic that has to fake an entire browser
    environment. See `signals.reject_headless_user_agent` for the one
    check shipped against it."""

    request: VerificationRequest
    authenticated_user_id: int | None = None
    captcha_response: str | None = None
    signals: dict[str, Any] = field(default_factory=dict)
    client_ip: str | None = None
    user_agent: str | None = None


@dataclass
class CheckOutcome:
    passed: bool
    detail: str | None = None


@runtime_checkable
class VerificationCheck(Protocol):
    """A single verification layer. Implement this (or use `PredicateCheck`
    for a one-off function) to add your own requirement -- the gate treats
    first-party and third-party checks identically."""

    name: str

    async def run(self, ctx: VerificationContext) -> CheckOutcome: ...


class CaptchaCheck:
    """Passes if the submitted `captcha_response` solves the challenge the
    verification was issued with, via the wrapped `CaptchaProvider`."""

    name = "captcha"

    def __init__(self, provider: CaptchaProvider) -> None:
        self.provider = provider

    async def run(self, ctx: VerificationContext) -> CheckOutcome:
        if ctx.request.challenge is None:
            return CheckOutcome(False, "this verification has no captcha challenge")
        if ctx.captcha_response is None:
            return CheckOutcome(False, "no captcha answer was submitted")
        ok = await self.provider.verify(ctx.request.challenge.challenge_id, ctx.captcha_response)
        return CheckOutcome(ok, None if ok else "the captcha answer was wrong")


class AccountMatchCheck:
    """Passes only if the request is authenticated (via whatever
    `current_user_id_resolver` your app wired into
    `build_captcha_router()`) *as the exact user the verification was
    created for*. This is what upgrades a verification from "a human did
    this" to "this specific account did this" -- a forwarded link solved
    by someone else fails here."""

    name = "account"

    async def run(self, ctx: VerificationContext) -> CheckOutcome:
        if ctx.authenticated_user_id is None:
            return CheckOutcome(False, "not signed in")
        if ctx.authenticated_user_id != ctx.request.user_id:
            return CheckOutcome(False, "signed in as a different account")
        return CheckOutcome(True)


class PredicateCheck:
    """Wraps your own async function as a check, so you don't have to write
    a whole class for a one-off rule. `predicate` receives the
    `VerificationContext` and returns either a plain `bool` or a
    `CheckOutcome` (use the latter when you want to attach a reason).

    This is the escape hatch for everything this library deliberately does
    *not* build for you -- browser/mobile fingerprint scoring, behavioral
    signals, "already a guild member for N days," an external anti-fraud
    service, whatever your threshold is. You bring the policy; the gate
    just runs it alongside ours.
    """

    def __init__(
        self,
        name: str,
        predicate: Callable[[VerificationContext], Awaitable[bool | CheckOutcome]],
    ) -> None:
        self.name = name
        self._predicate = predicate

    async def run(self, ctx: VerificationContext) -> CheckOutcome:
        result = await self._predicate(ctx)
        if isinstance(result, CheckOutcome):
            return result
        return CheckOutcome(bool(result))
