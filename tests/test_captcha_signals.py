"""Exercises the instrumentation-signal PredicateCheck helpers -- the
transparent, honest heuristics for the invisible layer."""

from datetime import UTC, datetime, timedelta

from webapi_captcha.checks import VerificationContext
from webapi_captcha.models import VerificationRequest
from webapi_captcha.signals import (
    honeypot_field_empty,
    reject_headless_user_agent,
    reject_webdriver,
    require_min_interaction_ms,
    require_signal_flag,
)


def _ctx(signals: dict, *, user_agent: str | None = None) -> VerificationContext:
    now = datetime.now(UTC)
    request = VerificationRequest(
        token="t1",
        user_id=100,
        purpose="test",
        created_at=now,
        expires_at=now + timedelta(minutes=10),
    )
    return VerificationContext(request=request, signals=signals, user_agent=user_agent)


async def test_reject_webdriver_blocks_a_reported_webdriver() -> None:
    outcome = await reject_webdriver().run(_ctx({"webdriver": True}))

    assert outcome.passed is False
    assert "webdriver" in (outcome.detail or "")


async def test_reject_webdriver_passes_when_absent_or_false() -> None:
    assert (await reject_webdriver().run(_ctx({}))).passed is True
    assert (await reject_webdriver().run(_ctx({"webdriver": False}))).passed is True


async def test_require_signal_flag() -> None:
    check = require_signal_flag("passed_js_attestation")

    assert (await check.run(_ctx({"passed_js_attestation": True}))).passed is True
    assert (await check.run(_ctx({}))).passed is False
    assert (await check.run(_ctx({"passed_js_attestation": False}))).passed is False


async def test_require_min_interaction_ms() -> None:
    check = require_min_interaction_ms(400)

    assert (await check.run(_ctx({"interaction_ms": 900}))).passed is True
    assert (await check.run(_ctx({"interaction_ms": 3}))).passed is False
    # not reported at all -> treated as failing (a silent submit is suspicious)
    assert (await check.run(_ctx({}))).passed is False


async def test_honeypot_field_empty_passes_when_untouched() -> None:
    check = honeypot_field_empty("website")

    assert (await check.run(_ctx({}))).passed is True
    assert (await check.run(_ctx({"website": ""}))).passed is True


async def test_honeypot_field_empty_fails_when_a_bot_filled_it_in() -> None:
    check = honeypot_field_empty("website")

    outcome = await check.run(_ctx({"website": "http://spam.example"}))

    assert outcome.passed is False
    assert "website" in (outcome.detail or "")


async def test_reject_headless_user_agent_passes_for_an_ordinary_browser() -> None:
    check = reject_headless_user_agent()
    ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    assert (await check.run(_ctx({}, user_agent=ua))).passed is True


async def test_reject_headless_user_agent_passes_when_absent() -> None:
    """No User-Agent at all abstains rather than fails -- legitimate
    non-browser clients strip it too."""
    check = reject_headless_user_agent()

    assert (await check.run(_ctx({}, user_agent=None))).passed is True


async def test_reject_headless_user_agent_blocks_known_automation_tools() -> None:
    check = reject_headless_user_agent()

    outcome = await check.run(
        _ctx({}, user_agent="Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/120.0.0.0")
    )

    assert outcome.passed is False
    assert "headlesschrome" in (outcome.detail or "")


async def test_reject_headless_user_agent_honors_custom_patterns() -> None:
    check = reject_headless_user_agent(patterns=("mybot",))

    assert (await check.run(_ctx({}, user_agent="HeadlessChrome/120"))).passed is True
    assert (await check.run(_ctx({}, user_agent="MyBot/1.0"))).passed is False
