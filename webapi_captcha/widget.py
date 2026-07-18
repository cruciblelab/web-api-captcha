"""A ready-made, drop-in frontend widget for `CaptchaGate` -- the "fast
path" companion to writing your own UI against `build_captcha_router()`.
Mount it, drop one `<div>` and one `<script>` tag into your page, done: a
Cloudflare-Turnstile-style checkbox that automatically renders whichever
challenge kind the gate issued (a Math/Text image, an invisible
Proof-of-Work search, a Path-Trace canvas, or a reCAPTCHA/hCaptcha
widget), silently collects the behavioral signals
`SignalScoreCheck`/`RepeatedMovementCheck` use, and calls back into your
own page's JS when it's done.

Entirely optional, same "use it or write your own" principle as the rest
of `webapi_captcha` -- using it never precludes writing your own frontend
against the raw gate endpoints instead (or alongside it, for a different
page).

Usage:
    app.include_router(build_captcha_widget_router())

    <div class="wac-captcha-widget" data-token="{token}"></div>
    <script src="/static/webapi-captcha-widget.js" data-callback="onVerified"></script>
    <script>
      function onVerified(result) {
        // result.verified, result.failed_check, result.detail
      }
    </script>

Every internal step (mouse approach, exact click position, the check-
animation delay, each check's pass/fail, the final verdict) also fires a
`wac-captcha-widget-log` CustomEvent on `document` with
`{ token, message, ok, detail }`, for pages that want their own visible
timeline instead of (or in addition to) the `onVerified` callback.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import Response

_WIDGET_JS = (Path(__file__).parent / "widget.js").read_text()

DEFAULT_WIDGET_MOUNT_PATH = "/static/webapi-captcha-widget.js"


def build_captcha_widget_router(*, mount_path: str = DEFAULT_WIDGET_MOUNT_PATH) -> APIRouter:
    """Serves the bundled widget script at `mount_path`. Talks to whatever
    `build_captcha_router()` you've already mounted (`GET
    /api/captcha/gate/{token}`, `POST /api/captcha/gate/{token}/verify`)
    -- mount both together."""
    router = APIRouter(tags=["captcha-widget"])

    @router.get(mount_path)
    async def widget_script() -> Response:
        return Response(content=_WIDGET_JS, media_type="application/javascript")

    return router
