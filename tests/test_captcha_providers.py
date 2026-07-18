"""Exercises MathCaptchaProvider/TextCaptchaProvider's full issue()/
verify() flow against a real MemoryCaptchaStore and real (Pillow)
rendering -- not mocked."""

from datetime import timedelta

from webapi_captcha.memory import MemoryCaptchaStore
from webapi_captcha.providers.math_captcha import MathCaptchaProvider
from webapi_captcha.providers.text_captcha import TextCaptchaProvider


async def test_math_provider_issues_a_real_image_challenge() -> None:
    provider = MathCaptchaProvider(MemoryCaptchaStore())

    challenge = await provider.issue()

    assert challenge.kind == "math"
    assert challenge.image_data_uri is not None
    assert challenge.image_data_uri.startswith("data:image/png;base64,")
    assert challenge.site_key is None


async def test_math_provider_accepts_the_correct_answer() -> None:
    store = MemoryCaptchaStore()
    provider = MathCaptchaProvider(store)
    challenge = await provider.issue()
    pending = await store.get(challenge.challenge_id)
    assert pending is not None

    ok = await provider.verify(challenge.challenge_id, pending.answer)

    assert ok is True


async def test_math_provider_keeps_multiplication_to_single_digits(monkeypatch) -> None:
    """1-20 x 1-20 can produce e.g. "16 x 19" -- not a trivial mental-math
    captcha anymore. Force the "*" operator and confirm the resulting
    product never exceeds 9*9=81, i.e. both operands stayed single-digit."""
    import webapi_captcha.providers.math_captcha as math_captcha_module

    monkeypatch.setattr(math_captcha_module.random, "choice", lambda ops: "*")
    store = MemoryCaptchaStore()
    provider = MathCaptchaProvider(store)

    for _ in range(50):
        challenge = await provider.issue()
        pending = await store.get(challenge.challenge_id)
        assert pending is not None
        assert int(pending.answer) <= 81
        await store.delete(challenge.challenge_id)


async def test_math_provider_rejects_a_wrong_answer() -> None:
    store = MemoryCaptchaStore()
    provider = MathCaptchaProvider(store)
    challenge = await provider.issue()
    pending = await store.get(challenge.challenge_id)
    assert pending is not None
    wrong_answer = str(int(pending.answer) + 1000)

    ok = await provider.verify(challenge.challenge_id, wrong_answer)

    assert ok is False


async def test_math_provider_answer_is_one_time_use() -> None:
    store = MemoryCaptchaStore()
    provider = MathCaptchaProvider(store)
    challenge = await provider.issue()
    pending = await store.get(challenge.challenge_id)
    assert pending is not None

    first = await provider.verify(challenge.challenge_id, pending.answer)
    second = await provider.verify(challenge.challenge_id, pending.answer)

    assert first is True
    assert second is False  # already consumed, can't replay


async def test_math_provider_locks_out_after_max_attempts() -> None:
    store = MemoryCaptchaStore()
    provider = MathCaptchaProvider(store, max_attempts=3)
    challenge = await provider.issue()

    for _ in range(3):
        assert await provider.verify(challenge.challenge_id, "not-the-answer") is False

    pending = await store.get(challenge.challenge_id)
    assert pending is not None
    correct_answer = pending.answer
    # even the real answer is rejected now -- the challenge was invalidated
    assert await provider.verify(challenge.challenge_id, correct_answer) is False


async def test_math_provider_rejects_an_expired_challenge() -> None:
    store = MemoryCaptchaStore()
    provider = MathCaptchaProvider(store, ttl=timedelta(seconds=-1))  # already expired
    challenge = await provider.issue()
    pending = await store.get(challenge.challenge_id)
    assert pending is not None

    ok = await provider.verify(challenge.challenge_id, pending.answer)

    assert ok is False


async def test_math_provider_verify_of_unknown_challenge_id_is_false() -> None:
    provider = MathCaptchaProvider(MemoryCaptchaStore())

    assert await provider.verify("never-issued", "42") is False


async def test_text_provider_issues_a_real_image_challenge() -> None:
    provider = TextCaptchaProvider(MemoryCaptchaStore())

    challenge = await provider.issue()

    assert challenge.kind == "text"
    assert challenge.image_data_uri is not None


async def test_text_provider_accepts_the_correct_answer_case_insensitively() -> None:
    store = MemoryCaptchaStore()
    provider = TextCaptchaProvider(store, length=6)
    challenge = await provider.issue()
    pending = await store.get(challenge.challenge_id)
    assert pending is not None

    ok = await provider.verify(challenge.challenge_id, pending.answer.lower())

    assert ok is True


async def test_text_provider_rejects_a_wrong_answer() -> None:
    store = MemoryCaptchaStore()
    provider = TextCaptchaProvider(store, length=6)
    challenge = await provider.issue()

    ok = await provider.verify(challenge.challenge_id, "WRONGWRONG")

    assert ok is False


async def test_text_provider_alphabet_excludes_ambiguous_characters() -> None:
    """0/O and 1/I/l are excluded so a human squinting at a distorted
    image never has to guess which one it is."""
    store = MemoryCaptchaStore()
    provider = TextCaptchaProvider(store, length=50)

    challenge = await provider.issue()
    pending = await store.get(challenge.challenge_id)

    assert pending is not None
    assert not set(pending.answer) & set("01OIL")
