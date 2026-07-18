"""Direct coverage of the composable verification checks -- edge cases the
gate-level tests don't hit head-on."""

from datetime import UTC, datetime, timedelta

from webapi_captcha.checks import (
    AccountMatchCheck,
    CaptchaCheck,
    CheckOutcome,
    PredicateCheck,
    VerificationContext,
)
from webapi_captcha.memory import MemoryCaptchaStore
from webapi_captcha.models import CaptchaChallenge, VerificationRequest
from webapi_captcha.providers.math_captcha import MathCaptchaProvider


def _request(*, user_id: int = 100, with_challenge: bool = True) -> VerificationRequest:
    now = datetime.now(UTC)
    return VerificationRequest(
        token="t1",
        user_id=user_id,
        purpose="test",
        challenge=(
            CaptchaChallenge(challenge_id="c1", kind="math", prompt="1 + 1 = ?")
            if with_challenge
            else None
        ),
        created_at=now,
        expires_at=now + timedelta(minutes=10),
    )


async def test_account_check_fails_when_not_signed_in() -> None:
    ctx = VerificationContext(request=_request(), authenticated_user_id=None)

    outcome = await AccountMatchCheck().run(ctx)

    assert outcome.passed is False
    assert "not signed in" in (outcome.detail or "")


async def test_account_check_fails_for_a_different_user() -> None:
    ctx = VerificationContext(request=_request(user_id=100), authenticated_user_id=999)

    outcome = await AccountMatchCheck().run(ctx)

    assert outcome.passed is False
    assert "different account" in (outcome.detail or "")


async def test_account_check_passes_for_the_matching_user() -> None:
    ctx = VerificationContext(request=_request(user_id=100), authenticated_user_id=100)

    outcome = await AccountMatchCheck().run(ctx)

    assert outcome.passed is True


async def test_captcha_check_fails_when_there_is_no_challenge() -> None:
    provider = MathCaptchaProvider(MemoryCaptchaStore())
    ctx = VerificationContext(request=_request(with_challenge=False), captcha_response="anything")

    outcome = await CaptchaCheck(provider).run(ctx)

    assert outcome.passed is False
    assert "no captcha challenge" in (outcome.detail or "")


async def test_captcha_check_fails_when_no_answer_submitted() -> None:
    provider = MathCaptchaProvider(MemoryCaptchaStore())
    ctx = VerificationContext(request=_request(), captcha_response=None)

    outcome = await CaptchaCheck(provider).run(ctx)

    assert outcome.passed is False
    assert "no captcha answer" in (outcome.detail or "")


async def test_predicate_check_accepts_a_plain_bool() -> None:
    async def always_true(ctx: VerificationContext) -> bool:
        return True

    outcome = await PredicateCheck("x", always_true).run(
        VerificationContext(request=_request())
    )

    assert outcome.passed is True


async def test_predicate_check_can_return_a_detailed_outcome() -> None:
    async def with_reason(ctx: VerificationContext) -> CheckOutcome:
        return CheckOutcome(False, "custom reason here")

    outcome = await PredicateCheck("x", with_reason).run(
        VerificationContext(request=_request())
    )

    assert outcome.passed is False
    assert outcome.detail == "custom reason here"


async def test_predicate_check_reads_client_signals() -> None:
    async def needs_signal(ctx: VerificationContext) -> bool:
        return ctx.signals.get("score", 0) > 50

    passing = await PredicateCheck("x", needs_signal).run(
        VerificationContext(request=_request(), signals={"score": 80})
    )
    failing = await PredicateCheck("x", needs_signal).run(
        VerificationContext(request=_request(), signals={"score": 10})
    )

    assert passing.passed is True
    assert failing.passed is False
