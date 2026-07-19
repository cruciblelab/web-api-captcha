"""Exercises `AdaptiveCaptchaGate` -- the IP-reputation-driven escalation
gate. Same overall shape as test_captcha_gate.py's coverage of
`CaptchaGate`, but for the dynamic decision instead of a static one."""

import asyncio
from datetime import timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from webapi_captcha.adaptive import (
    AdaptiveCaptchaGate,
    MemoryAdaptiveDecisionStore,
    MemoryTrustStore,
)
from webapi_captcha.checks import PredicateCheck, VerificationContext
from webapi_captcha.memory import MemoryCaptchaStore, MemoryVerificationStore
from webapi_captcha.providers.math_captcha import MathCaptchaProvider
from webapi_captcha.providers.path_trace import PathTraceProvider
from webapi_captcha.receipts import TrustTokenIssuer, TrustTokenVerifier
from webapi_captcha.reputation import StaticBlocklistReputationChecker
from webapi_captcha.risk import (
    MemoryRunningRiskStore,
    RiskContext,
    RiskContribution,
    RiskEngine,
    RiskLevel,
)
from webapi_captcha.transport import InProcessTransport


class _OverrideSignal:
    """A RiskSignal that always hard-overrides to a fixed level -- used
    to simulate "IP reputation is outright bad" without depending on
    ReputationRiskSignal's own tests."""

    name = "override"
    weight = 1.0

    def __init__(self, level: RiskLevel) -> None:
        self.level = level

    async def assess(self, ctx: RiskContext) -> RiskContribution:
        return RiskContribution(suspicion=1.0, hard_override=self.level)


class _FixedRevalidationSignal:
    """A RiskSignal with a fixed graded suspicion and no hard_override --
    used to test trusted_revalidation_threshold's boundary."""

    name = "fixed"
    weight = 1.0

    def __init__(self, suspicion: float) -> None:
        self.suspicion = suspicion

    async def assess(self, ctx: RiskContext) -> RiskContribution:
        return RiskContribution(suspicion=self.suspicion)


def _make_gate(**kwargs: object) -> AdaptiveCaptchaGate:
    return AdaptiveCaptchaGate(
        InProcessTransport(),
        MemoryVerificationStore(),
        StaticBlocklistReputationChecker(blocked_ips={"1.2.3.4"}),
        MathCaptchaProvider(MemoryCaptchaStore()),
        MemoryAdaptiveDecisionStore(),
        **kwargs,  # type: ignore[arg-type]
    )


async def test_create_verification_has_no_challenge_yet() -> None:
    """Nothing is decided at mint time -- only when the link is opened."""
    gate = _make_gate()

    request = await gate.create_verification(user_id=100, purpose="signup")

    assert request.challenge is None
    assert request.token


async def test_clean_ip_gets_no_captcha() -> None:
    gate = _make_gate()
    request = await gate.create_verification(user_id=100, purpose="signup")

    info = await gate.get_info(request.token, client_ip="9.9.9.9")

    assert info is not None
    assert info["requires_captcha"] is False
    assert info["challenge"] is None


async def test_suspicious_ip_gets_a_real_captcha_challenge() -> None:
    gate = _make_gate()
    request = await gate.create_verification(user_id=100, purpose="signup")

    info = await gate.get_info(request.token, client_ip="1.2.3.4")

    assert info is not None
    assert info["requires_captcha"] is True
    assert info["challenge"] is not None
    assert info["challenge"].kind == "math"


async def test_decision_is_made_once_and_persists_across_calls() -> None:
    """A second get_info() call (a page reload) must not re-roll the
    decision or re-issue a new challenge."""
    gate = _make_gate()
    request = await gate.create_verification(user_id=100, purpose="signup")

    first = await gate.get_info(request.token, client_ip="1.2.3.4")
    second = await gate.get_info(request.token, client_ip="1.2.3.4")

    assert first is not None and second is not None
    assert first["challenge"].challenge_id == second["challenge"].challenge_id


async def test_clean_ip_verification_passes_without_any_captcha_response() -> None:
    gate = _make_gate()
    request = await gate.create_verification(user_id=100, purpose="signup")
    await gate.get_info(request.token, client_ip="9.9.9.9")

    result = await gate.verify(request.token, client_ip="9.9.9.9")

    assert result.verified is True
    assert result.passed == []


async def test_get_info_distinguishes_already_verified_from_gone() -> None:
    """Same regression as CaptchaGate's: a reload after success must not
    look identical to a gone/expired token."""
    gate = _make_gate()
    request = await gate.create_verification(user_id=100, purpose="signup")
    await gate.get_info(request.token, client_ip="9.9.9.9")
    await gate.verify(request.token, client_ip="9.9.9.9")

    info = await gate.get_info(request.token, client_ip="9.9.9.9")
    assert info is not None, "an already-verified token must not look 'gone'"
    assert info["verified"] is True

    assert await gate.get_info("never-issued-token", client_ip="9.9.9.9") is None


async def test_suspicious_ip_verification_requires_solving_the_captcha() -> None:
    gate = _make_gate()
    request = await gate.create_verification(user_id=100, purpose="signup")
    info = await gate.get_info(request.token, client_ip="1.2.3.4")
    assert info is not None
    store: MemoryCaptchaStore = gate.escalation_provider.store  # type: ignore[union-attr]
    pending = await store.get(info["challenge"].challenge_id)
    assert pending is not None

    wrong = await gate.verify(request.token, "not-the-answer", client_ip="1.2.3.4")
    assert wrong.verified is False
    assert wrong.failed_check == "captcha"

    right = await gate.verify(request.token, pending.answer, client_ip="1.2.3.4")
    assert right.verified is True
    assert right.passed == ["captcha"]


async def test_require_account_and_extra_checks_still_apply_regardless_of_ip() -> None:
    """The IP-driven captcha requirement is additive, not a replacement
    for require_account/extra_checks -- both still run either way."""
    seen_signals = []

    async def custom_check(ctx: VerificationContext) -> bool:
        seen_signals.append(ctx.signals)
        return ctx.signals.get("ok") is True

    gate = _make_gate(extra_checks=[PredicateCheck("custom", custom_check)])
    request = await gate.create_verification(user_id=100, purpose="signup")
    await gate.get_info(request.token, client_ip="9.9.9.9")  # clean IP, no captcha

    blocked = await gate.verify(request.token, client_ip="9.9.9.9", signals={})
    assert blocked.verified is False
    assert blocked.failed_check == "custom"

    ok = await gate.verify(request.token, client_ip="9.9.9.9", signals={"ok": True})
    assert ok.verified is True


async def test_user_agent_reaches_a_custom_check() -> None:
    async def reject_curl(ctx: VerificationContext) -> bool:
        return "curl" not in (ctx.user_agent or "").lower()

    gate = _make_gate(extra_checks=[PredicateCheck("no-curl", reject_curl)])
    request = await gate.create_verification(user_id=100, purpose="signup")
    await gate.get_info(request.token, client_ip="9.9.9.9")  # clean IP, no captcha

    blocked = await gate.verify(request.token, client_ip="9.9.9.9", user_agent="curl/8.0.0")
    assert blocked.verified is False
    assert blocked.failed_check == "no-curl"

    request2 = await gate.create_verification(user_id=101, purpose="signup")
    await gate.get_info(request2.token, client_ip="9.9.9.9")
    ok = await gate.verify(request2.token, client_ip="9.9.9.9", user_agent="Mozilla/5.0")
    assert ok.verified is True


async def test_trust_store_skips_reputation_check_for_recently_verified_users() -> None:
    trust_store = MemoryTrustStore()
    gate = _make_gate(trust_store=trust_store)

    # first verification from a suspicious IP -- must solve the captcha
    request1 = await gate.create_verification(user_id=100, purpose="signup")
    info1 = await gate.get_info(request1.token, client_ip="1.2.3.4")
    assert info1 is not None and info1["requires_captcha"] is True
    store: MemoryCaptchaStore = gate.escalation_provider.store  # type: ignore[union-attr]
    pending1 = await store.get(info1["challenge"].challenge_id)
    assert pending1 is not None
    await gate.verify(request1.token, pending1.answer, client_ip="1.2.3.4")

    # second verification, same user, still a suspicious IP -- but now trusted
    request2 = await gate.create_verification(user_id=100, purpose="signup")
    info2 = await gate.get_info(request2.token, client_ip="1.2.3.4")
    assert info2 is not None
    assert info2["requires_captcha"] is False


async def test_trust_expires_after_ttl() -> None:
    trust_store = MemoryTrustStore()
    await trust_store.trust(100, ttl=timedelta(seconds=-1))  # already expired

    assert await trust_store.is_trusted(100) is False


async def test_bind_trust_to_ip_requires_the_same_connecting_ip() -> None:
    """A real requirement from testing: connect from IP A, then IP B --
    re-challenge immediately. With bind_trust_to_ip=True, trust earned
    from one IP must not carry over to a different one."""
    trust_store = MemoryTrustStore()
    gate = _make_gate(trust_store=trust_store, bind_trust_to_ip=True)

    request1 = await gate.create_verification(user_id=100, purpose="signup")
    info1 = await gate.get_info(request1.token, client_ip="1.2.3.4")
    assert info1 is not None and info1["requires_captcha"] is True
    store: MemoryCaptchaStore = gate.escalation_provider.store  # type: ignore[union-attr]
    pending1 = await store.get(info1["challenge"].challenge_id)
    assert pending1 is not None
    await gate.verify(request1.token, pending1.answer, client_ip="1.2.3.4")
    assert await gate.is_currently_trusted(100, client_ip="1.2.3.4") is True

    # Same account, but the connection now comes from a DIFFERENT
    # (also-suspicious) IP -- trust earned on 1.2.3.4 must not carry
    # over, even though the account itself hasn't changed.
    assert await gate.is_currently_trusted(100, client_ip="6.6.6.6") is False
    request2 = await gate.create_verification(user_id=100, purpose="signup")
    blocklist: StaticBlocklistReputationChecker = gate.reputation  # type: ignore[assignment]
    blocklist.block("6.6.6.6")
    info2 = await gate.get_info(request2.token, client_ip="6.6.6.6")
    assert info2 is not None and info2["requires_captcha"] is True


async def test_without_bind_trust_to_ip_trust_follows_the_account_anywhere() -> None:
    """Default behavior (bind_trust_to_ip=False, the pre-existing
    contract) is unchanged: trust earned on one IP still applies from a
    different one."""
    trust_store = MemoryTrustStore()
    gate = _make_gate(trust_store=trust_store)  # bind_trust_to_ip defaults to False

    request1 = await gate.create_verification(user_id=100, purpose="signup")
    info1 = await gate.get_info(request1.token, client_ip="1.2.3.4")
    store: MemoryCaptchaStore = gate.escalation_provider.store  # type: ignore[union-attr]
    pending1 = await store.get(info1["challenge"].challenge_id)  # type: ignore[union-attr]
    assert pending1 is not None
    await gate.verify(request1.token, pending1.answer, client_ip="1.2.3.4")

    assert await gate.is_currently_trusted(100, client_ip="6.6.6.6") is True


async def test_is_currently_trusted_false_without_a_trust_store() -> None:
    gate = _make_gate()  # no trust_store passed
    assert await gate.is_currently_trusted(100, client_ip="1.2.3.4") is False


class _SlowReputationChecker:
    """An `IPReputationChecker` with a real, controllable suspension
    point -- lets a test force two concurrent `get_info()`/`verify()`
    calls for the same token to genuinely interleave (a plain in-memory
    check like `StaticBlocklistReputationChecker`'s has no real `await`
    suspension point, so without this, "concurrent" asyncio tasks would
    just run to completion one after another with no actual race
    window)."""

    def __init__(self, suspicious_ips: set[str], release: asyncio.Event) -> None:
        self._suspicious_ips = suspicious_ips
        self._release = release

    async def is_suspicious(self, ip: str) -> bool:
        await self._release.wait()
        return ip in self._suspicious_ips


async def test_concurrent_get_info_calls_resolve_to_the_same_decision() -> None:
    """Regression test: `_resolve_decision` used to have no locking, so
    two concurrent `get_info()` calls for the same token (a double page
    load, a client retry, two open tabs) could both see no decision
    persisted yet and independently `escalation_provider.issue()` a
    DIFFERENT challenge -- whichever `decision_store.set()` landed last
    silently won, so a user who then solved the *other* (still displayed
    on their screen) challenge would fail."""
    release = asyncio.Event()
    gate = AdaptiveCaptchaGate(
        InProcessTransport(),
        MemoryVerificationStore(),
        _SlowReputationChecker({"1.2.3.4"}, release),
        MathCaptchaProvider(MemoryCaptchaStore()),
        MemoryAdaptiveDecisionStore(),
    )
    request = await gate.create_verification(user_id=100, purpose="signup")

    task_a = asyncio.create_task(gate.get_info(request.token, client_ip="1.2.3.4"))
    task_b = asyncio.create_task(gate.get_info(request.token, client_ip="1.2.3.4"))
    await asyncio.sleep(0.01)  # let both reach is_suspicious() and start waiting
    release.set()
    info_a, info_b = await asyncio.gather(task_a, task_b)

    assert info_a is not None and info_b is not None
    assert info_a["challenge"].challenge_id == info_b["challenge"].challenge_id, (
        "both concurrent calls must agree on the SAME challenge -- solving "
        "either one must succeed"
    )

    store: MemoryCaptchaStore = gate.escalation_provider.store  # type: ignore[union-attr]
    pending = await store.get(info_a["challenge"].challenge_id)
    assert pending is not None
    result = await gate.verify(request.token, pending.answer, client_ip="1.2.3.4")
    assert result.verified is True


async def test_verify_of_unknown_token_fails_gracefully() -> None:
    gate = _make_gate()

    result = await gate.verify("does-not-exist", client_ip="9.9.9.9")

    assert result.verified is False


async def test_get_info_of_unknown_token_is_none() -> None:
    gate = _make_gate()

    assert await gate.get_info("does-not-exist", client_ip="9.9.9.9") is None


async def test_verify_is_idempotent_once_already_solved() -> None:
    gate = _make_gate()
    request = await gate.create_verification(user_id=100, purpose="signup")
    await gate.get_info(request.token, client_ip="9.9.9.9")
    first = await gate.verify(request.token, client_ip="9.9.9.9")
    assert first.verified is True

    second = await gate.verify(request.token, client_ip="9.9.9.9")
    assert second.verified is True


async def test_on_verified_fires_with_purpose_filter() -> None:
    from webapi_captcha.events import CaptchaVerified

    gate = _make_gate()
    notified: list[CaptchaVerified] = []
    gate.on_verified(lambda event: notified.append(event), purpose="signup")  # type: ignore[arg-type,return-value]

    request = await gate.create_verification(user_id=100, purpose="signup")
    await gate.get_info(request.token, client_ip="9.9.9.9")
    await gate.verify(request.token, client_ip="9.9.9.9")
    await asyncio.sleep(0.05)

    assert len(notified) == 1
    assert notified[0].purpose == "signup"


async def test_missing_client_ip_is_treated_as_not_suspicious() -> None:
    """No IP known (e.g. a bot-side call with no HTTP request at all) ->
    fail open on the reputation check specifically -- it simply has
    nothing to evaluate, same "abstain rather than penalize" principle as
    the signal-based heuristics elsewhere in this package."""
    gate = _make_gate()
    request = await gate.create_verification(user_id=100, purpose="signup")

    info = await gate.get_info(request.token, client_ip=None)

    assert info is not None
    assert info["requires_captcha"] is False


async def test_risk_engine_hard_override_issues_from_the_tiered_provider() -> None:
    """A hard_override to HIGH should escalate via the HIGH-tier provider
    (a different one from the plain default), not the single default
    escalation_provider -- the "IP reputation is outright bad, skip
    straight to the strongest configured response" case."""
    strict_store = MemoryCaptchaStore()
    strict_provider = PathTraceProvider(strict_store)
    gate = _make_gate(
        risk_engine=RiskEngine([_OverrideSignal(RiskLevel.HIGH)]),
        escalation_providers={RiskLevel.HIGH: strict_provider},
    )
    request = await gate.create_verification(user_id=100, purpose="signup")

    info = await gate.get_info(request.token, client_ip="9.9.9.9")  # clean IP -- irrelevant now

    assert info is not None
    assert info["requires_captcha"] is True
    assert info["challenge"] is not None
    assert info["challenge"].kind == strict_provider.kind


async def test_min_level_by_purpose_forces_escalation_on_a_clean_ip() -> None:
    gate = _make_gate(
        risk_engine=RiskEngine([]),  # no signals at all -> would otherwise be MINIMAL
        min_level_by_purpose={"checkout": RiskLevel.ELEVATED},
    )
    request = await gate.create_verification(user_id=100, purpose="checkout")

    info = await gate.get_info(request.token, client_ip="9.9.9.9")

    assert info is not None
    assert info["requires_captcha"] is True


async def test_running_risk_store_floor_escalates_a_fresh_tokens_decision() -> None:
    running_risk_store = MemoryRunningRiskStore()
    gate = _make_gate(
        risk_engine=RiskEngine([]),
        running_risk_store=running_risk_store,
    )
    await running_risk_store.bump(100, RiskLevel.HIGH, ttl=timedelta(minutes=5))

    request = await gate.create_verification(user_id=100, purpose="signup")
    info = await gate.get_info(request.token, client_ip="9.9.9.9")  # clean IP

    assert info is not None
    assert info["requires_captcha"] is True


def _make_verifier() -> tuple[TrustTokenIssuer, TrustTokenVerifier]:
    key = Ed25519PrivateKey.generate()
    issuer = TrustTokenIssuer(key, issuer_id="site-a")
    verifier = TrustTokenVerifier({"site-a": key.public_key()})
    return issuer, verifier


async def test_is_currently_trusted_true_via_valid_trust_token_with_no_trust_store() -> None:
    issuer, verifier = _make_verifier()
    gate = _make_gate(trust_store=None, trust_token_verifier=verifier)
    token = issuer.issue("visitor-1", ttl=timedelta(hours=1))

    assert await gate.is_currently_trusted(100, trust_token=token) is True


async def test_is_currently_trusted_false_via_invalid_token_falls_back_to_trust_store() -> None:
    _, verifier = _make_verifier()
    trust_store = MemoryTrustStore()
    await trust_store.trust(100, ttl=timedelta(hours=1))
    gate = _make_gate(trust_store=trust_store, trust_token_verifier=verifier)

    assert await gate.is_currently_trusted(100, trust_token="garbage") is True


async def test_is_currently_trusted_false_when_neither_source_says_trusted() -> None:
    _, verifier = _make_verifier()
    gate = _make_gate(trust_store=MemoryTrustStore(), trust_token_verifier=verifier)

    assert await gate.is_currently_trusted(100, trust_token="garbage") is False


async def test_get_info_and_verify_accept_trust_token_and_skip_escalation() -> None:
    """End to end: a suspicious IP that would normally escalate, but a
    valid trust_token bypasses the escalation decision entirely."""
    issuer, verifier = _make_verifier()
    gate = _make_gate(trust_store=None, trust_token_verifier=verifier)
    token = issuer.issue("visitor-1", ttl=timedelta(hours=1))

    request = await gate.create_verification(user_id=100, purpose="signup")
    info = await gate.get_info(request.token, client_ip="1.2.3.4", trust_token=token)

    assert info is not None
    assert info["requires_captcha"] is False

    result = await gate.verify(
        request.token, client_ip="1.2.3.4", signals={}, trust_token=token
    )
    assert result.verified is True


# -- trusted_revalidation: "trusted" is not necessarily an unconditional bypass --


class _RaisingSignal:
    name = "boom"
    weight = 1.0

    async def assess(self, ctx: RiskContext) -> RiskContribution:
        raise RuntimeError("flaky revalidation check")


async def test_trusted_revalidation_revokes_trust_when_it_flags() -> None:
    trust_store = MemoryTrustStore()
    await trust_store.trust(100, ttl=timedelta(hours=1))
    gate = _make_gate(
        trust_store=trust_store,
        trusted_revalidation=_OverrideSignal(RiskLevel.HIGH),
    )

    assert await gate.is_currently_trusted(100, client_ip="1.2.3.4") is False


async def test_trusted_revalidation_keeps_trust_when_it_does_not_flag() -> None:
    trust_store = MemoryTrustStore()
    await trust_store.trust(100, ttl=timedelta(hours=1))
    gate = _make_gate(
        trust_store=trust_store,
        trusted_revalidation=_FixedRevalidationSignal(0.0),
    )

    assert await gate.is_currently_trusted(100, client_ip="1.2.3.4") is True


async def test_trusted_revalidation_only_runs_when_otherwise_trusted() -> None:
    """No trust_store/trust_token match at all -- trusted_revalidation
    must not run (and can't spuriously grant trust on its own)."""
    gate = _make_gate(
        trust_store=MemoryTrustStore(),  # nobody trusted yet
        trusted_revalidation=_OverrideSignal(RiskLevel.HIGH),
    )

    assert await gate.is_currently_trusted(100, client_ip="1.2.3.4") is False


async def test_trusted_revalidation_exception_fails_open_keeps_trust() -> None:
    trust_store = MemoryTrustStore()
    await trust_store.trust(100, ttl=timedelta(hours=1))
    gate = _make_gate(trust_store=trust_store, trusted_revalidation=_RaisingSignal())

    assert await gate.is_currently_trusted(100, client_ip="1.2.3.4") is True


async def test_trusted_revalidation_threshold_is_configurable() -> None:
    trust_store = MemoryTrustStore()
    await trust_store.trust(100, ttl=timedelta(hours=1))
    gate = _make_gate(
        trust_store=trust_store,
        trusted_revalidation=_FixedRevalidationSignal(0.4),
        trusted_revalidation_threshold=0.5,
    )
    assert await gate.is_currently_trusted(100, client_ip="1.2.3.4") is True  # below threshold

    gate2 = _make_gate(
        trust_store=trust_store,
        trusted_revalidation=_FixedRevalidationSignal(0.6),
        trusted_revalidation_threshold=0.5,
    )
    assert await gate2.is_currently_trusted(100, client_ip="1.2.3.4") is False  # at/above


# -- reputation is optional: drop the built-in IP-reputation path for a pure risk_engine --


async def test_gate_can_be_built_with_no_reputation_when_a_risk_engine_is_given() -> None:
    gate = AdaptiveCaptchaGate(
        InProcessTransport(),
        MemoryVerificationStore(),
        escalation_provider=MathCaptchaProvider(MemoryCaptchaStore()),
        risk_engine=RiskEngine([_OverrideSignal(RiskLevel.HIGH)]),
    )
    request = await gate.create_verification(user_id=100, purpose="signup")

    info = await gate.get_info(request.token, client_ip="1.1.1.1")  # any IP -- no reputation used

    assert info is not None
    assert info["requires_captcha"] is True  # risk_engine alone drove the escalation


async def test_gate_defaults_a_decision_store_when_omitted() -> None:
    gate = AdaptiveCaptchaGate(
        InProcessTransport(),
        MemoryVerificationStore(),
        escalation_provider=MathCaptchaProvider(MemoryCaptchaStore()),
        risk_engine=RiskEngine([]),
    )
    from webapi_captcha.adaptive import MemoryAdaptiveDecisionStore

    assert isinstance(gate.decision_store, MemoryAdaptiveDecisionStore)


async def test_gate_rejects_neither_reputation_nor_risk_engine() -> None:
    try:
        AdaptiveCaptchaGate(
            InProcessTransport(),
            MemoryVerificationStore(),
            escalation_provider=MathCaptchaProvider(MemoryCaptchaStore()),
        )
        raise AssertionError("expected a ValueError for a gate that could never escalate")
    except ValueError:
        pass


async def test_escalation_without_a_configured_provider_raises_a_clear_error() -> None:
    gate = AdaptiveCaptchaGate(
        InProcessTransport(),
        MemoryVerificationStore(),
        risk_engine=RiskEngine([_OverrideSignal(RiskLevel.HIGH)]),
    )  # no escalation_provider at all
    request = await gate.create_verification(user_id=100, purpose="signup")

    try:
        await gate.get_info(request.token, client_ip="1.1.1.1")
        raise AssertionError("expected a ValueError when escalating with no provider configured")
    except ValueError:
        pass


async def test_is_currently_trusted_rejects_a_token_for_a_different_subject() -> None:
    issuer, verifier = _make_verifier()
    gate = _make_gate(trust_store=None, trust_token_verifier=verifier)
    token = issuer.issue("visitor-1", ttl=timedelta(hours=1))

    trusted = await gate.is_currently_trusted(
        100, trust_token=token, expected_subject_id="visitor-2"
    )
    assert trusted is False


async def test_is_currently_trusted_accepts_a_token_for_the_expected_subject() -> None:
    issuer, verifier = _make_verifier()
    gate = _make_gate(trust_store=None, trust_token_verifier=verifier)
    token = issuer.issue("visitor-1", ttl=timedelta(hours=1))

    trusted = await gate.is_currently_trusted(
        100, trust_token=token, expected_subject_id="visitor-1"
    )
    assert trusted is True


async def test_is_currently_trusted_enforces_required_purpose() -> None:
    issuer, verifier = _make_verifier()
    gate = _make_gate(trust_store=None, trust_token_verifier=verifier)
    token = issuer.issue("visitor-1", ttl=timedelta(hours=1), purpose="checkout")

    assert await gate.is_currently_trusted(
        100, trust_token=token, required_purpose="login"
    ) is False
    assert await gate.is_currently_trusted(
        100, trust_token=token, required_purpose="checkout"
    ) is True
