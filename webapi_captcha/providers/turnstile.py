"""Cloudflare Turnstile as a `CaptchaProvider`. Same shape as
`webapi_captcha.providers.recaptcha.ReCaptchaProvider`/
`hcaptcha.HCaptchaProvider` -- no local challenge/answer state, Cloudflare
holds that. `issue()` returns your `site_key` for the frontend widget;
`verify()` posts the widget's response token to Turnstile's own
`siteverify` endpoint. Needs only `httpx`, already a core dependency -- no
extra install required.
"""

from __future__ import annotations

import httpx

from webapi_captcha.models import CaptchaChallenge
from webapi_captcha.providers._http import _LazyHttpClientMixin

_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


class TurnstileProvider(_LazyHttpClientMixin):
    """Get `site_key`/`secret_key` from
    https://dash.cloudflare.com/?to=/:account/turnstile. Embed Turnstile's
    own JS (`https://challenges.cloudflare.com/turnstile/v0/api.js`) plus a
    `<div class="cf-turnstile" data-sitekey="...">` on your page using the
    `site_key` this returns -- this class only handles server-side
    verification, it doesn't render or serve Turnstile's widget itself.

    Reuses one internally-created `httpx.AsyncClient` across every
    `verify()` call (see `_LazyHttpClientMixin`) -- call `await
    provider.aclose()` on app shutdown if you didn't pass your own
    `http_client=`.
    """

    kind = "turnstile"

    def __init__(
        self,
        *,
        site_key: str,
        secret_key: str,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.site_key = site_key
        self._secret_key = secret_key
        self._init_http_client(http_client)

    async def issue(self) -> CaptchaChallenge:
        return CaptchaChallenge(
            challenge_id=self.site_key,
            kind=self.kind,
            prompt="Complete the Turnstile challenge.",
            site_key=self.site_key,
        )

    async def verify(self, challenge_id: str, response: str) -> bool:
        client = self._http_client()
        try:
            resp = await client.post(
                _VERIFY_URL, data={"secret": self._secret_key, "response": response}
            )
            resp.raise_for_status()
            data = resp.json()
            return isinstance(data, dict) and bool(data.get("success"))
        except (httpx.HTTPError, ValueError):
            # Same fail-closed fix as ReCaptchaProvider/HCaptchaProvider's
            # verify() -- a 200 with a non-JSON body (proxy/WAF
            # interstitial, maintenance page) makes `resp.json()` raise
            # `json.JSONDecodeError` (a `ValueError`), which must not
            # propagate uncaught as an unhandled 500.
            return False
