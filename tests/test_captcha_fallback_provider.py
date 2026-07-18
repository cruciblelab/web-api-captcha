"""Exercises FallbackCaptchaProvider -- composing several CaptchaProviders
so a primary provider's issue() failure degrades to the next one instead
of surfacing an error, while verify() always routes back to whichever
provider actually issued a given challenge."""

import pytest

from webapi_captcha.models import CaptchaChallenge
from webapi_captcha.providers.fallback import FallbackCaptchaProvider


class _FakeProvider:
    def __init__(self, kind: str, *, fail_issue: bool = False) -> None:
        self.kind = kind
        self.fail_issue = fail_issue
        self.verified_with: list[str] = []

    async def issue(self) -> CaptchaChallenge:
        if self.fail_issue:
            raise RuntimeError(f"{self.kind} provider is down")
        return CaptchaChallenge(challenge_id=f"{self.kind}-id", kind=self.kind, prompt="solve me")

    async def verify(self, challenge_id: str, response: str) -> bool:
        self.verified_with.append(challenge_id)
        return response == "correct"


async def test_empty_provider_list_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least one provider"):
        FallbackCaptchaProvider([])


async def test_issue_uses_the_primary_when_it_succeeds() -> None:
    primary = _FakeProvider("math")
    secondary = _FakeProvider("text")
    provider = FallbackCaptchaProvider([primary, secondary])

    challenge = await provider.issue()

    assert challenge.kind == "math"  # the real child kind, not "fallback"
    assert challenge.challenge_id == "0:math-id"


async def test_issue_falls_back_when_the_primary_raises() -> None:
    primary = _FakeProvider("math", fail_issue=True)
    secondary = _FakeProvider("text")
    provider = FallbackCaptchaProvider([primary, secondary])

    challenge = await provider.issue()

    assert challenge.kind == "text"
    assert challenge.challenge_id == "1:text-id"


async def test_issue_reraises_when_every_provider_fails() -> None:
    primary = _FakeProvider("math", fail_issue=True)
    secondary = _FakeProvider("text", fail_issue=True)
    provider = FallbackCaptchaProvider([primary, secondary])

    with pytest.raises(RuntimeError, match="text provider is down"):
        await provider.issue()


async def test_verify_routes_to_the_provider_that_actually_issued_the_challenge() -> None:
    primary = _FakeProvider("math", fail_issue=True)
    secondary = _FakeProvider("text")
    provider = FallbackCaptchaProvider([primary, secondary])
    challenge = await provider.issue()  # falls back to secondary ("1:text-id")

    ok = await provider.verify(challenge.challenge_id, "correct")

    assert ok is True
    assert secondary.verified_with == ["text-id"]
    assert primary.verified_with == []  # never asked -- it never issued this one


async def test_verify_fails_closed_on_a_malformed_challenge_id() -> None:
    provider = FallbackCaptchaProvider([_FakeProvider("math")])

    assert await provider.verify("not-a-valid-prefix", "correct") is False


async def test_verify_fails_closed_on_an_out_of_range_index() -> None:
    provider = FallbackCaptchaProvider([_FakeProvider("math")])

    assert await provider.verify("5:some-id", "correct") is False
