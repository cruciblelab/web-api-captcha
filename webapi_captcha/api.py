"""The FastAPI-facing captcha API -- two independent uses:

- **Plain web usage** (`/api/captcha/challenge`, `/api/captcha/verify`):
  protect any point on your own site (a signup form, a comment box, ...)
  with whichever registered provider you name by `kind` -- no signed-in
  user involved at all.
- **Gated verification** (`/api/captcha/gate/{token}`): the other half
  of `webapi_captcha.gate.CaptchaGate` -- serves and resolves a
  token some other part of your app handed a specific user (see that
  module's docstring for the giveaway-bot scenario and the
  account-only / captcha / "safety" / click-only modes).

There's no sensible default *provider* to fall back to (which captcha
backend, whose reCAPTCHA keys?), so mount this yourself once you've
picked and constructed one:

    app.state.webapi_captcha_providers = {"math": math_provider}
    app.state.webapi_captcha_gate = gate  # optional, only if you use CaptchaGate
    app.include_router(build_captcha_router())

The gate's account-check (`require_account=True`) needs to know who's
currently signed in -- this package has no login system of its own (it
doesn't assume Discord, or any particular auth), so pass your own FastAPI
dependency as `current_user_id_resolver=` that resolves to the signed-in
user's stable id (or `None` if nobody's signed in). If you're using this
alongside discord-webapi:

    from discord_webapi.auth.dependencies import get_current_user_optional
    from discord_webapi.auth.models import DiscordUser

    async def resolve_discord_user_id(
        user: DiscordUser | None = Depends(get_current_user_optional),
    ) -> int | None:
        return user.id if user is not None else None

    app.include_router(build_captcha_router(current_user_id_resolver=resolve_discord_user_id))

Captcha-only / click-only gates work without any resolver at all.

**More than one `CaptchaGate` purpose at once** (e.g. a giveaway-entry
gate and a separate "verify before appealing a ban" gate)? Pass `gate=`
explicitly and mount the router once per gate under different prefixes
instead of relying on the single `app.state.webapi_captcha_gate`:

    app.include_router(build_captcha_router(gate=giveaway_gate), prefix="/giveaway")
    app.include_router(build_captcha_router(gate=appeal_gate), prefix="/appeal")

Each mount gets its own `/{prefix}/api/captcha/gate/{token}` pair, fully
independent. Point the bundled widget's `data-api-base` at the matching
prefix (empty string, the default, means unprefixed -- the single-gate
case above). The plain `/challenge`+`/verify` provider endpoints get
duplicated harmlessly under each prefix; mount the router without a
`gate=` (or without a `prefix`) once more if you only want one
unprefixed copy of those for direct site usage.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Protocol

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from webapi_captcha.base import CaptchaProvider
from webapi_captcha.gate import CheckResult
from webapi_captcha.models import CaptchaChallenge
from webapi_captcha.ratelimit import TokenBucketLimiter

_DEFAULT_VERIFY_LIMITER = TokenBucketLimiter(max_calls=20, per_seconds=60.0)
_DEFAULT_CHALLENGE_LIMITER = TokenBucketLimiter(max_calls=20, per_seconds=60.0)
_DEFAULT_GATE_VERIFY_IP_LIMITER = TokenBucketLimiter(max_calls=20, per_seconds=60.0)

# A FastAPI dependency (sync or async, any signature FastAPI can inject --
# Request, cookies, headers, whatever your auth needs) resolving to the
# currently-authenticated user's stable id, or None if nobody's signed in.
CurrentUserIdResolver = Callable[..., Awaitable[int | None] | int | None]


async def _no_current_user() -> int | None:
    """Default `current_user_id_resolver` -- always "not signed in". Fine
    for captcha-only/click-only gates, and for `require_account=True`
    gates you simply don't intend to ever satisfy through this router."""
    return None


class GateLike(Protocol):
    """Structural shape both `CaptchaGate` and `AdaptiveCaptchaGate`
    satisfy -- lets this router work with either without importing
    `AdaptiveCaptchaGate` here (which would otherwise force
    `webapi_captcha.adaptive`'s dependencies onto every consumer
    of this module, even ones who never touch adaptive gates)."""

    async def get_info(
        self, token: str, *, client_ip: str | None = None
    ) -> dict[str, Any] | None: ...

    async def verify(
        self,
        token: str,
        response: str | None = None,
        *,
        authenticated_user_id: int | None = None,
        signals: dict[str, Any] | None = None,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> CheckResult: ...


class CaptchaVerifyRequest(BaseModel):
    kind: str
    challenge_id: str
    response: str


class GateVerifyRequest(BaseModel):
    captcha_response: str | None = None
    # Arbitrary client-submitted signals for your own extra_checks
    # (fingerprint token, behavioral data, ...). Untrusted -- your check
    # decides how much to believe them.
    signals: dict[str, Any] = {}


class CaptchaVerifyResult(BaseModel):
    verified: bool


class GateVerifyResult(BaseModel):
    verified: bool
    # Which check blocked it (e.g. "account" -> the frontend can prompt
    # "please sign in first"; "captcha" -> "wrong answer"). None on
    # success.
    failed_check: str | None = None
    detail: str | None = None


class GateInfo(BaseModel):
    """What the frontend needs to render the right thing for a gate link:
    the captcha image if there is one, whether the visitor has to be
    signed in, and whether this token is already verified
    (a page reload after a successful verification hits this same
    endpoint again -- `verified=True` lets the frontend say "you're
    already verified" instead of treating it as an expired/invalid link,
    which is what the previous version -- with no `verified` field --
    conflated it with)."""

    challenge: CaptchaChallenge | None
    requires_captcha: bool
    requires_account: bool
    verified: bool = False


def _get_providers(request: Request) -> dict[str, CaptchaProvider]:
    providers: dict[str, CaptchaProvider] = getattr(
        request.app.state, "webapi_captcha_providers", {}
    )
    return providers


def _get_provider(request: Request, kind: str) -> CaptchaProvider:
    provider = _get_providers(request).get(kind)
    if provider is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, f"No captcha provider registered for {kind!r}"
        )
    return provider


def _get_gate(request: Request, gate: GateLike | None) -> GateLike:
    resolved = gate or getattr(request.app.state, "webapi_captcha_gate", None)
    if resolved is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "No CaptchaGate configured -- pass gate=... to build_captcha_router() or "
            "set app.state.webapi_captcha_gate",
        )
    return resolved


def build_captcha_router(
    *,
    gate: GateLike | None = None,
    current_user_id_resolver: CurrentUserIdResolver = _no_current_user,
    verify_rate_limiter: TokenBucketLimiter | None = None,
    challenge_rate_limiter: TokenBucketLimiter | None = None,
    gate_verify_ip_rate_limiter: TokenBucketLimiter | None = None,
) -> APIRouter:
    """`gate=None` (the default) reads `app.state.webapi_captcha_gate`
    at request time -- the single-gate case. Pass an explicit `gate=` to
    bind this particular router mount to one gate regardless of app
    state, so you can mount the router more than once (each under its own
    `prefix=`) for more than one gate purpose at once -- see the module
    docstring. Works with either `CaptchaGate` or
    `webapi_captcha.adaptive.AdaptiveCaptchaGate`.

    `current_user_id_resolver`: your own FastAPI dependency resolving to
    the signed-in user's id (or `None`) -- see the module docstring for
    the discord-webapi wiring example. Only matters for
    `require_account=True` gates; ignored otherwise.

    Three independent, all-optional rate limiters, each falling back to
    its own generous default (20 calls/60s) if not given:

    - `challenge_rate_limiter`: per client IP, on `GET /challenge` --
      issuing a self-hosted challenge (Math/Text) writes a fresh
      `CaptchaStore` row every call, with no limiter of any kind before
      this; unbounded issuance is a cheap way to fill that store.
    - `verify_rate_limiter`: per client IP on `POST /verify` (the plain
      provider endpoint), per *token* on `POST /gate/{token}/verify`.
    - `gate_verify_ip_rate_limiter`: per client IP, *additionally* on
      `POST /gate/{token}/verify` -- `verify_rate_limiter`'s per-token
      budget only ever bounds guesses against *one* token; it does
      nothing to stop one IP from attempting many different tokens (each
      gets its own fresh per-token budget). This closes that gap without
      changing the per-token limiter's own behavior.
    """
    limiter = verify_rate_limiter or _DEFAULT_VERIFY_LIMITER
    challenge_limiter = challenge_rate_limiter or _DEFAULT_CHALLENGE_LIMITER
    gate_verify_ip_limiter = gate_verify_ip_rate_limiter or _DEFAULT_GATE_VERIFY_IP_LIMITER
    router = APIRouter(prefix="/api/captcha", tags=["captcha"])

    @router.get("/challenge")
    async def create_challenge(kind: str, request: Request) -> CaptchaChallenge:
        client_host = request.client.host if request.client else "unknown"
        challenge_limiter.check(client_host)
        provider = _get_provider(request, kind)
        return await provider.issue()

    @router.post("/verify")
    async def verify_challenge(body: CaptchaVerifyRequest, request: Request) -> CaptchaVerifyResult:
        # Keyed by client IP, not an authenticated user -- this endpoint is
        # meant to protect pages that don't require login (a public signup
        # form, ...), so there's no user id to key on the way the other
        # dashboard write endpoints do. Each self-hosted provider also
        # independently bounds guesses per challenge_id (see
        # `_shared.verify_pending_challenge`); this is a second,
        # coarser layer against one IP hammering many different challenges.
        client_host = request.client.host if request.client else "unknown"
        limiter.check(client_host)
        provider = _get_provider(request, body.kind)
        ok = await provider.verify(body.challenge_id, body.response)
        return CaptchaVerifyResult(verified=ok)

    @router.get("/gate/{token}")
    async def get_gate_info(token: str, request: Request) -> GateInfo:
        resolved_gate = _get_gate(request, gate)
        info = await resolved_gate.get_info(
            token, client_ip=request.client.host if request.client else None
        )
        if info is None:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND, "This verification link has expired or was already used"
            )
        return GateInfo(**info)

    @router.post("/gate/{token}/verify")
    async def verify_gate(
        token: str,
        body: GateVerifyRequest,
        request: Request,
        user_id: int | None = Depends(current_user_id_resolver),
    ) -> GateVerifyResult:
        limiter.check(token)
        client_host = request.client.host if request.client else "unknown"
        gate_verify_ip_limiter.check(client_host)
        resolved_gate = _get_gate(request, gate)
        result = await resolved_gate.verify(
            token,
            body.captcha_response,
            authenticated_user_id=user_id,
            signals=body.signals,
            client_ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
        return GateVerifyResult(
            verified=result.verified, failed_check=result.failed_check, detail=result.detail
        )

    return router
