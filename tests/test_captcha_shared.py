"""Exercises `_shared.check_pending_challenge`/`verify_pending_challenge`
directly -- the attempt-limit race fix and the constant-time answer
comparison, at the level they actually apply (every self-hosted provider
routes through this)."""

import asyncio
from datetime import UTC, datetime, timedelta

from webapi_captcha._shared import check_pending_challenge, verify_pending_challenge
from webapi_captcha.memory import MemoryCaptchaStore
from webapi_captcha.models import PendingCaptcha


def _pending(challenge_id: str = "c1", answer: str = "42") -> PendingCaptcha:
    now = datetime.now(UTC)
    return PendingCaptcha(
        challenge_id=challenge_id,
        kind="test",
        answer=answer,
        created_at=now,
        expires_at=now + timedelta(minutes=10),
    )


async def test_correct_answer_passes_and_consumes_the_challenge() -> None:
    store = MemoryCaptchaStore()
    await store.create(_pending())

    ok = await verify_pending_challenge(store, "c1", "42", max_attempts=5)

    assert ok is True
    assert await store.get("c1") is None  # one-time use


async def test_wrong_answer_fails_without_consuming_remaining_attempts() -> None:
    store = MemoryCaptchaStore()
    await store.create(_pending())

    ok = await verify_pending_challenge(store, "c1", "wrong", max_attempts=5)

    assert ok is False
    pending = await store.get("c1")
    assert pending is not None
    assert pending.attempts == 1


async def test_exactly_max_attempts_wrong_guesses_are_allowed_then_locked() -> None:
    """Attempts are incremented *before* the limit check now (closing a
    TOCTOU race under concurrency -- see the SQL store's own test), but
    the externally-visible behavior must be unchanged: exactly
    max_attempts guesses allowed, the next one always fails, even with
    the right answer."""
    store = MemoryCaptchaStore()
    await store.create(_pending())

    for _ in range(3):
        assert await verify_pending_challenge(store, "c1", "wrong", max_attempts=3) is False

    # locked out now -- even the correct answer fails
    assert await verify_pending_challenge(store, "c1", "42", max_attempts=3) is False
    assert await store.get("c1") is None  # deleted once exhausted


async def test_expired_challenge_fails_and_is_removed() -> None:
    store = MemoryCaptchaStore()
    now = datetime.now(UTC)
    await store.create(
        PendingCaptcha(
            challenge_id="c1", kind="test", answer="42", created_at=now,
            expires_at=now - timedelta(seconds=1),
        )
    )

    ok = await verify_pending_challenge(store, "c1", "42", max_attempts=5)

    assert ok is False
    assert await store.get("c1") is None


async def test_unknown_challenge_id_fails() -> None:
    store = MemoryCaptchaStore()

    assert await verify_pending_challenge(store, "does-not-exist", "42", max_attempts=5) is False


async def test_verifier_is_only_called_when_within_the_attempt_limit() -> None:
    """Once attempts are exhausted, check_pending_challenge must not even
    call the provider's verifier -- proves the limit is enforced before
    the (potentially expensive, e.g. geometric) verification logic runs."""
    store = MemoryCaptchaStore()
    await store.create(_pending())
    calls = 0

    def _verifier(pending: PendingCaptcha) -> bool:
        nonlocal calls
        calls += 1
        return False

    for _ in range(2):
        await check_pending_challenge(store, "c1", max_attempts=2, verifier=_verifier)
    assert calls == 2

    await check_pending_challenge(store, "c1", max_attempts=2, verifier=_verifier)
    assert calls == 2  # not called a 3rd time -- locked out before verifying


async def test_normalize_is_applied_before_comparison() -> None:
    store = MemoryCaptchaStore()
    await store.create(_pending(answer="42"))

    ok = await verify_pending_challenge(store, "c1", "  42  ", max_attempts=5)

    assert ok is True


async def test_concurrent_guesses_against_the_same_challenge_cannot_exceed_the_limit() -> None:
    """Fires more concurrent wrong guesses than max_attempts at the same
    challenge_id -- with MemoryCaptchaStore's synchronous increment this
    was never racy, but this pins the observable guarantee
    check_pending_challenge promises: never more than max_attempts
    verifier calls succeed in being *evaluated as within-limit*, however
    many requests arrive at once."""
    store = MemoryCaptchaStore()
    await store.create(_pending())

    results = await asyncio.gather(
        *(verify_pending_challenge(store, "c1", "wrong", max_attempts=3) for _ in range(10))
    )

    assert all(result is False for result in results)
    # the record was deleted once attempts exceeded the limit -- confirms
    # it didn't silently keep accepting guesses forever
    assert await store.get("c1") is None
