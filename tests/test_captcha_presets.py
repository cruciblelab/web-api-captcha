"""Exercises build_cloudflare_style_guard() -- the one-call quickstart
wiring AdaptiveCaptchaGate + PageGuard + sensible defaults together."""

from datetime import timedelta

from webapi_captcha.checks import PredicateCheck
from webapi_captcha.presets import build_cloudflare_style_guard
from webapi_captcha.providers.path_trace import PathTraceProvider
from webapi_captcha.reputation import StaticBlocklistReputationChecker
from webapi_captcha.scoring import SignalScoreCheck
from webapi_captcha.transport import InProcessTransport


def _verify_url(token: str, return_to: str) -> str:
    return f"/verify/{token}?return_to={return_to}"


async def test_zero_config_call_produces_a_working_guard() -> None:
    guard = build_cloudflare_style_guard(InProcessTransport(), verify_url=_verify_url)

    assert guard.page_guard.gate is guard.gate
    # An empty StaticBlocklistReputationChecker (the default) flags nothing.
    assert await guard.gate.reputation.is_suspicious("1.2.3.4") is False


async def test_default_escalation_provider_is_path_trace() -> None:
    guard = build_cloudflare_style_guard(InProcessTransport(), verify_url=_verify_url)

    assert isinstance(guard.gate.escalation_provider, PathTraceProvider)


async def test_default_extra_checks_is_signal_score_check() -> None:
    guard = build_cloudflare_style_guard(InProcessTransport(), verify_url=_verify_url)

    assert len(guard.gate.extra_checks) == 1
    assert isinstance(guard.gate.extra_checks[0], SignalScoreCheck)


async def test_bind_trust_to_ip_defaults_to_true() -> None:
    """The specific "IP changed, re-challenge" behavior this preset was
    built for -- unlike AdaptiveCaptchaGate's own default of False."""
    guard = build_cloudflare_style_guard(InProcessTransport(), verify_url=_verify_url)

    assert guard.gate.bind_trust_to_ip is True

    await guard.gate.trust_store.trust(100, ttl=timedelta(hours=1), ip="1.1.1.1")

    assert await guard.gate.is_currently_trusted(100, client_ip="1.1.1.1") is True
    assert await guard.gate.is_currently_trusted(100, client_ip="9.9.9.9") is False


async def test_custom_reputation_checker_is_used() -> None:
    blocklist = StaticBlocklistReputationChecker(blocked_ips={"6.6.6.6"})
    guard = build_cloudflare_style_guard(
        InProcessTransport(), verify_url=_verify_url, reputation=blocklist
    )

    assert guard.gate.reputation is blocklist
    assert await guard.gate.reputation.is_suspicious("6.6.6.6") is True


async def test_extra_checks_override_replaces_the_default() -> None:
    my_check = PredicateCheck("custom", lambda ctx: True)
    guard = build_cloudflare_style_guard(
        InProcessTransport(), verify_url=_verify_url, extra_checks=[my_check]
    )

    assert guard.gate.extra_checks == [my_check]


async def test_end_to_end_clean_ip_needs_no_captcha() -> None:
    guard = build_cloudflare_style_guard(
        InProcessTransport(),
        verify_url=_verify_url,
        extra_checks=[],  # isolate from behavior-scoring's own signals requirement
    )

    request = await guard.gate.create_verification(user_id=1, purpose="page_guard")
    info = await guard.gate.get_info(request.token, client_ip="1.1.1.1")

    assert info is not None
    assert info["requires_captcha"] is False


async def test_end_to_end_blocked_ip_requires_the_default_captcha() -> None:
    blocklist = StaticBlocklistReputationChecker(blocked_ips={"6.6.6.6"})
    guard = build_cloudflare_style_guard(
        InProcessTransport(), verify_url=_verify_url, reputation=blocklist, extra_checks=[]
    )

    request = await guard.gate.create_verification(user_id=1, purpose="page_guard")
    info = await guard.gate.get_info(request.token, client_ip="6.6.6.6")

    assert info is not None
    assert info["requires_captcha"] is True
    assert info["challenge"] is not None
    assert info["challenge"].kind == "path-trace"
