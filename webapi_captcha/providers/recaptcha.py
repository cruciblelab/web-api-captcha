"""Google reCAPTCHA (v2 checkbox) as a `CaptchaProvider`. No local
challenge/answer state -- Google holds that. `issue()` just returns your
`site_key` for the frontend widget to render; `verify()` posts the
widget's response token to Google's own `siteverify` endpoint. Needs only
`httpx`, already a core dependency -- no extra install required.
"""

from __future__ import annotations

import httpx

from webapi_captcha.models import CaptchaChallenge
from webapi_captcha.providers._http import _LazyHttpClientMixin

_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"


class ReCaptchaProvider(_LazyHttpClientMixin):
    """Get `site_key`/`secret_key` from
    https://www.google.com/recaptcha/admin. Embed reCAPTCHA's own JS
    (`https://www.google.com/recaptcha/api.js`) plus a
    `<div class="g-recaptcha" data-sitekey="...">` on your page using the
    `site_key` this returns -- this class only handles server-side
    verification, it doesn't render or serve Google's widget itself.

    Reuses one internally-created `httpx.AsyncClient` across every
    `verify()` call (see `_LazyHttpClientMixin`) instead of opening and
    closing a fresh one each time -- call `await provider.aclose()` on
    app shutdown if you didn't pass your own `http_client=`.
    """

    kind = "recaptcha"

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
        # No server-side challenge state to create -- Google's widget IS
        # the challenge. challenge_id is unused by verify() below (kept
        # only so this satisfies the same CaptchaProvider shape as every
        # self-hosted provider); real state lives entirely with Google.
        return CaptchaChallenge(
            challenge_id=self.site_key,
            kind=self.kind,
            prompt="Complete the reCAPTCHA challenge.",
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
            # `resp.raise_for_status()` only raises on a non-2xx status --
            # a 200 with a non-JSON body (a proxy/WAF interstitial, a
            # maintenance page, any CDN error page in front of Google's
            # API, all real things that happen to third-party services)
            # makes `resp.json()` raise `json.JSONDecodeError` (a
            # `ValueError` subclass), which used to propagate uncaught
            # here as an unhandled 500 instead of the documented
            # fail-closed `False`.
            return False
