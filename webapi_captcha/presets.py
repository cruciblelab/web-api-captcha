"""`build_cloudflare_style_guard()` -- a one-call quickstart wiring
together the exact "Cloudflare in front of your whole site" flow this
package's pieces already support individually: check IP reputation first,
stay invisible when clean, escalate to a real captcha (the line-drawing
`PathTraceProvider` by default) plus behavioral scoring when suspicious,
remember trust for a while, and re-challenge if the connecting IP changes.

This is a *starting point*, not a new abstraction -- every argument is
one of `AdaptiveCaptchaGate`/`PageGuard`'s own constructor parameters
passed straight through, with a sensible default for a zero-config first
run. Swap any single piece (your own `IPReputationChecker`, a
`ReCaptchaProvider`/`TurnstileProvider` instead of `PathTraceProvider`,
a SQL-backed store for any of the four in-memory ones, your own scoring
heuristics) without needing a different function -- this is the "fully
customizable, hybrid" entry point the rest of `webapi_captcha`
already is, just pre-assembled once instead of by hand every time. Skip
this module entirely and construct `AdaptiveCaptchaGate`/`PageGuard`
yourself for full control; nothing else in this package depends on it.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta

from fastapi import Request

from webapi_captcha.adaptive import (
    AdaptiveCaptchaGate,
    AdaptiveDecisionStore,
    MemoryAdaptiveDecisionStore,
    MemoryTrustStore,
    TrustStore,
)
from webapi_captcha.base import CaptchaProvider, VerificationStore
from webapi_captcha.checks import VerificationCheck
from webapi_captcha.memory import MemoryCaptchaStore, MemoryVerificationStore
from webapi_captcha.pageguard import (
    DEFAULT_COOKIE_MAX_AGE,
    DEFAULT_COOKIE_NAME,
    PageGuard,
)
from webapi_captcha.providers.path_trace import PathTraceProvider
from webapi_captcha.reputation import IPReputationChecker, StaticBlocklistReputationChecker
from webapi_captcha.risk import RiskEngine, RiskLevel, RunningRiskStore
from webapi_captcha.scoring import SignalScoreCheck
from webapi_captcha.transport import Transport


@dataclass
class CloudflareStyleGuard:
    """The two pieces `build_cloudflare_style_guard()` assembles.
    `page_guard` is what you call from a protected route
    (`await guard.page_guard.require_human(request)`); `gate` is the
    underlying `AdaptiveCaptchaGate` for anything else that wants direct
    access -- `is_currently_trusted()`, wiring the same gate into
    `extras.captcha_verify.setup(gate=...)` for a bot-side `/verify`
    command sharing the exact same trust/reputation policy, etc."""

    page_guard: PageGuard
    gate: AdaptiveCaptchaGate


def build_cloudflare_style_guard(
    transport: Transport,
    *,
    verify_url: Callable[[str, str], str],
    reputation: IPReputationChecker | None = None,
    escalation_provider: CaptchaProvider | None = None,
    verification_store: VerificationStore | None = None,
    decision_store: AdaptiveDecisionStore | None = None,
    trust_store: TrustStore | None = None,
    trust_ttl: timedelta = timedelta(hours=24),
    bind_trust_to_ip: bool = True,
    require_account: bool = False,
    extra_checks: Sequence[VerificationCheck] | None = None,
    extra_suspicious: Callable[[Request], bool] | None = None,
    purpose: str = "page_guard",
    cookie_name: str = DEFAULT_COOKIE_NAME,
    cookie_max_age: int = DEFAULT_COOKIE_MAX_AGE,
    ttl: timedelta = timedelta(minutes=15),
    risk_engine: RiskEngine | None = None,
    min_level_for_challenge: RiskLevel = RiskLevel.ELEVATED,
    escalation_providers: Mapping[RiskLevel, CaptchaProvider] | None = None,
    min_level_by_purpose: dict[str, RiskLevel] | None = None,
    running_risk_store: RunningRiskStore | None = None,
    running_risk_ttl: timedelta = timedelta(minutes=30),
    default_min_level: RiskLevel = RiskLevel.MINIMAL,
) -> CloudflareStyleGuard:
    """Every argument defaults to something that runs with zero external
    setup, so you can call this with only `transport` and `verify_url`
    to see the whole flow working, then swap in real pieces one at a
    time as they matter to you:

    - `reputation` (default: an *empty* `StaticBlocklistReputationChecker`
      -- flags nothing on its own). Bring a real IP-reputation source
      (your own blocklist, a paid API, your CDN's own signal) once you
      have one; this package ships no opinion on which to trust.
    - `escalation_provider` (default: `PathTraceProvider` -- the
      line-drawing/trace captcha, backed by a fresh `MemoryCaptchaStore`).
      Swap in `ReCaptchaProvider`/`HCaptchaProvider`/`TurnstileProvider`/
      your own for a different challenge kind, or a
      `FallbackCaptchaProvider` composing several.
    - `verification_store`/`decision_store`/`trust_store` (default:
      the in-memory versions of each -- fine for a single process;
      swap in the `webapi_captcha.sql` equivalents once you run
      more than one web replica).
    - `extra_checks` (default: `[SignalScoreCheck()]` -- the behavioral
      scoring heuristics run alongside the reputation-driven captcha
      decision). Pass your own list (including an empty one) to replace
      it entirely, or build on `default_behavior_heuristics()` yourself
      for a reweighted version.
    - `bind_trust_to_ip` (default `True`, unlike `AdaptiveCaptchaGate`'s
      own default of `False`) -- re-challenge immediately if a trusted
      visitor's connecting IP changes, instead of trust following the
      account everywhere; pass `False` for the latter.

    All other keyword arguments are `AdaptiveCaptchaGate`'s or
    `PageGuard`'s own, passed straight through -- see those classes'
    docstrings for what each does.
    """
    resolved_provider = escalation_provider or PathTraceProvider(MemoryCaptchaStore())
    checks = list(extra_checks) if extra_checks is not None else [SignalScoreCheck()]

    gate = AdaptiveCaptchaGate(
        transport,
        verification_store or MemoryVerificationStore(),
        reputation or StaticBlocklistReputationChecker(),
        resolved_provider,
        decision_store or MemoryAdaptiveDecisionStore(),
        require_account=require_account,
        extra_checks=checks,
        trust_store=trust_store or MemoryTrustStore(),
        trust_ttl=trust_ttl,
        bind_trust_to_ip=bind_trust_to_ip,
        ttl=ttl,
        risk_engine=risk_engine,
        min_level_for_challenge=min_level_for_challenge,
        escalation_providers=escalation_providers,
        min_level_by_purpose=min_level_by_purpose,
        running_risk_store=running_risk_store,
        running_risk_ttl=running_risk_ttl,
    )
    guard = PageGuard(
        gate,
        verify_url=verify_url,
        cookie_name=cookie_name,
        cookie_max_age=cookie_max_age,
        purpose=purpose,
        extra_suspicious=extra_suspicious,
        default_min_level=default_min_level,
    )
    return CloudflareStyleGuard(page_guard=guard, gate=gate)
