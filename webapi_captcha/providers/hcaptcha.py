"""hCaptcha as a `CaptchaProvider`. Same shape as
`webapi_captcha.providers.recaptcha.ReCaptchaProvider` -- no local
challenge/answer state, hCaptcha holds that. `issue()` returns your
`site_key` for the frontend widget; `verify()` posts the widget's
response token to hCaptcha's own `siteverify` endpoint. Needs only
`httpx`, already a core dependency -- no extra install required.
"""

from __future__ import annotations

import httpx

from webapi_captcha.models import CaptchaChallenge

_VERIFY_URL = "https://hcaptcha.com/siteverify"


class HCaptchaProvider:
    """Get `site_key`/`secret_key` from https://dashboard.hcaptcha.com.
    Embed hCaptcha's own JS (`https://js.hcaptcha.com/1/api.js`) plus a
    `<div class="h-captcha" data-sitekey="...">` on your page using the
    `site_key` this returns -- this class only handles server-side
    verification, it doesn't render or serve hCaptcha's widget itself.
    """

    kind = "hcaptcha"

    def __init__(
        self,
        *,
        site_key: str,
        secret_key: str,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.site_key = site_key
        self._secret_key = secret_key
        self._external_http_client = http_client

    async def issue(self) -> CaptchaChallenge:
        return CaptchaChallenge(
            challenge_id=self.site_key,
            kind=self.kind,
            prompt="Complete the hCaptcha challenge.",
            site_key=self.site_key,
        )

    async def verify(self, challenge_id: str, response: str) -> bool:
        client = self._external_http_client or httpx.AsyncClient()
        try:
            resp = await client.post(
                _VERIFY_URL, data={"secret": self._secret_key, "response": response}
            )
            resp.raise_for_status()
            data = resp.json()
            return isinstance(data, dict) and bool(data.get("success"))
        except (httpx.HTTPError, ValueError):
            # See ReCaptchaProvider.verify()'s identical fix -- a 200
            # with a non-JSON body (proxy/WAF interstitial, maintenance
            # page) made `resp.json()` raise `json.JSONDecodeError` (a
            # `ValueError`), uncaught, instead of the documented
            # fail-closed `False`.
            return False
        finally:
            if self._external_http_client is None:
                await client.aclose()
