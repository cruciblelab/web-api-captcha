"""Exercises ReCaptchaProvider/HCaptchaProvider against a mocked
siteverify HTTP endpoint (respx) -- no local challenge/answer state to
test here, Google/hCaptcha hold that."""

import httpx
import respx

from webapi_captcha.providers.hcaptcha import HCaptchaProvider
from webapi_captcha.providers.recaptcha import ReCaptchaProvider
from webapi_captcha.providers.turnstile import TurnstileProvider


async def test_recaptcha_issue_returns_the_site_key() -> None:
    provider = ReCaptchaProvider(site_key="site-123", secret_key="secret-456")

    challenge = await provider.issue()

    assert challenge.kind == "recaptcha"
    assert challenge.site_key == "site-123"
    assert challenge.image_data_uri is None


@respx.mock
async def test_recaptcha_verify_succeeds() -> None:
    respx.post("https://www.google.com/recaptcha/api/siteverify").mock(
        return_value=httpx.Response(200, json={"success": True})
    )
    provider = ReCaptchaProvider(site_key="site-123", secret_key="secret-456")

    ok = await provider.verify("site-123", "widget-response-token")

    assert ok is True


@respx.mock
async def test_recaptcha_verify_fails_when_google_says_no() -> None:
    respx.post("https://www.google.com/recaptcha/api/siteverify").mock(
        return_value=httpx.Response(
            200, json={"success": False, "error-codes": ["invalid-input-response"]}
        )
    )
    provider = ReCaptchaProvider(site_key="site-123", secret_key="secret-456")

    ok = await provider.verify("site-123", "bad-token")

    assert ok is False


@respx.mock
async def test_recaptcha_verify_handles_a_network_error_cleanly() -> None:
    respx.post("https://www.google.com/recaptcha/api/siteverify").mock(
        side_effect=httpx.ConnectError("boom")
    )
    provider = ReCaptchaProvider(site_key="site-123", secret_key="secret-456")

    ok = await provider.verify("site-123", "widget-response-token")

    assert ok is False


@respx.mock
async def test_recaptcha_verify_fails_closed_on_a_non_json_200_response() -> None:
    """Regression test: a 200 response with a non-JSON body (a proxy/WAF
    interstitial, a maintenance page -- real things that happen in front
    of third-party APIs) used to make `resp.json()` raise
    `json.JSONDecodeError` (a `ValueError`), uncaught by the
    `except httpx.HTTPError` that only guards non-2xx statuses --
    surfacing as an unhandled 500 instead of the documented fail-closed
    `False`."""
    respx.post("https://www.google.com/recaptcha/api/siteverify").mock(
        return_value=httpx.Response(200, text="<html>Service Unavailable</html>")
    )
    provider = ReCaptchaProvider(site_key="site-123", secret_key="secret-456")

    ok = await provider.verify("site-123", "widget-response-token")

    assert ok is False


@respx.mock
async def test_recaptcha_verify_fails_closed_on_valid_json_that_is_not_an_object() -> None:
    respx.post("https://www.google.com/recaptcha/api/siteverify").mock(
        return_value=httpx.Response(200, json=["not", "a", "dict"])
    )
    provider = ReCaptchaProvider(site_key="site-123", secret_key="secret-456")

    ok = await provider.verify("site-123", "widget-response-token")

    assert ok is False


async def test_hcaptcha_issue_returns_the_site_key() -> None:
    provider = HCaptchaProvider(site_key="site-abc", secret_key="secret-def")

    challenge = await provider.issue()

    assert challenge.kind == "hcaptcha"
    assert challenge.site_key == "site-abc"


@respx.mock
async def test_hcaptcha_verify_succeeds() -> None:
    respx.post("https://hcaptcha.com/siteverify").mock(
        return_value=httpx.Response(200, json={"success": True})
    )
    provider = HCaptchaProvider(site_key="site-abc", secret_key="secret-def")

    ok = await provider.verify("site-abc", "widget-response-token")

    assert ok is True


@respx.mock
async def test_hcaptcha_verify_fails_when_hcaptcha_says_no() -> None:
    respx.post("https://hcaptcha.com/siteverify").mock(
        return_value=httpx.Response(200, json={"success": False})
    )
    provider = HCaptchaProvider(site_key="site-abc", secret_key="secret-def")

    ok = await provider.verify("site-abc", "bad-token")

    assert ok is False


@respx.mock
async def test_hcaptcha_verify_fails_closed_on_a_non_json_200_response() -> None:
    """Same regression as ReCaptchaProvider's identical test."""
    respx.post("https://hcaptcha.com/siteverify").mock(
        return_value=httpx.Response(200, text="<html>Service Unavailable</html>")
    )
    provider = HCaptchaProvider(site_key="site-abc", secret_key="secret-def")

    ok = await provider.verify("site-abc", "widget-response-token")

    assert ok is False


async def test_turnstile_issue_returns_the_site_key() -> None:
    provider = TurnstileProvider(site_key="site-xyz", secret_key="secret-ghi")

    challenge = await provider.issue()

    assert challenge.kind == "turnstile"
    assert challenge.site_key == "site-xyz"
    assert challenge.image_data_uri is None


@respx.mock
async def test_turnstile_verify_succeeds() -> None:
    respx.post("https://challenges.cloudflare.com/turnstile/v0/siteverify").mock(
        return_value=httpx.Response(200, json={"success": True})
    )
    provider = TurnstileProvider(site_key="site-xyz", secret_key="secret-ghi")

    ok = await provider.verify("site-xyz", "widget-response-token")

    assert ok is True


@respx.mock
async def test_turnstile_verify_fails_when_cloudflare_says_no() -> None:
    respx.post("https://challenges.cloudflare.com/turnstile/v0/siteverify").mock(
        return_value=httpx.Response(200, json={"success": False})
    )
    provider = TurnstileProvider(site_key="site-xyz", secret_key="secret-ghi")

    ok = await provider.verify("site-xyz", "bad-token")

    assert ok is False


@respx.mock
async def test_turnstile_verify_handles_a_network_error_cleanly() -> None:
    respx.post("https://challenges.cloudflare.com/turnstile/v0/siteverify").mock(
        side_effect=httpx.ConnectError("boom")
    )
    provider = TurnstileProvider(site_key="site-xyz", secret_key="secret-ghi")

    ok = await provider.verify("site-xyz", "widget-response-token")

    assert ok is False


@respx.mock
async def test_turnstile_verify_fails_closed_on_a_non_json_200_response() -> None:
    """Same regression as ReCaptchaProvider/HCaptchaProvider's identical
    test -- learned from that fix and applied here from the start."""
    respx.post("https://challenges.cloudflare.com/turnstile/v0/siteverify").mock(
        return_value=httpx.Response(200, text="<html>Service Unavailable</html>")
    )
    provider = TurnstileProvider(site_key="site-xyz", secret_key="secret-ghi")

    ok = await provider.verify("site-xyz", "widget-response-token")

    assert ok is False


@respx.mock
async def test_turnstile_verify_fails_closed_on_valid_json_that_is_not_an_object() -> None:
    respx.post("https://challenges.cloudflare.com/turnstile/v0/siteverify").mock(
        return_value=httpx.Response(200, json=["not", "a", "dict"])
    )
    provider = TurnstileProvider(site_key="site-xyz", secret_key="secret-ghi")

    ok = await provider.verify("site-xyz", "widget-response-token")

    assert ok is False
