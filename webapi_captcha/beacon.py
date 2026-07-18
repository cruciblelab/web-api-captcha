"""A ready-made, drop-in frontend "beacon" for `build_passive_risk_router()`
(`webapi_captcha.pageguard`) -- the piece that was previously left as an
exercise for the reader ("wire your own small POST, or extend widget.js's
existing signal collection"). Deliberately NOT part of `webapi_captcha.widget`:
`CaptchaWidget` is scoped to one `<div class="wac-captcha-widget"
data-token="...">` tied to a live `CaptchaGate` verification token, but a
`PageGuard`-protected page typically shows NO widget at all when the
visitor looks clean -- that invisibility is the whole point of `PageGuard`.
This beacon has to work with zero captcha UI rendered anywhere on the page,
so it's a small, independent, UI-less script instead.

Usage:
    app.include_router(build_passive_risk_beacon_router())
    app.include_router(build_passive_risk_router(guard))

    <script src="/static/webapi-captcha-beacon.js"></script>

Drop that one script tag on any page `PageGuard` protects (or any page at
all -- it degrades to harmless no-op POSTs if the passive-risk endpoint
isn't mounted). It collects the same lightweight signals
`SignalScoreCheck` reads, on a page-wide basis, and periodically reports
them to whatever `data-endpoint` points at (default: `/api/captcha/
passive-signal`, matching `build_passive_risk_router()`'s own default
mount path, so the zero-attribute case just works).

Entirely optional, same "use it or don't" principle as every other bundled
piece here -- skip this and POST to the endpoint from your own code
instead if you want different signals or a different cadence.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import Response

_BEACON_JS = (Path(__file__).parent / "beacon.js").read_text()

DEFAULT_BEACON_MOUNT_PATH = "/static/webapi-captcha-beacon.js"


def build_passive_risk_beacon_router(*, mount_path: str = DEFAULT_BEACON_MOUNT_PATH) -> APIRouter:
    """Serves the bundled beacon script at `mount_path`. Unconditional --
    unlike `build_passive_risk_router()`, this takes no `PageGuard`/gate
    argument and is never gated/empty, since it's just a static asset;
    whether the endpoint it POSTs to is actually mounted (and wired to a
    `risk_engine`/`running_risk_store`) is that router's own concern."""
    router = APIRouter(tags=["captcha-beacon"])

    @router.get(mount_path)
    async def beacon_script() -> Response:
        return Response(content=_BEACON_JS, media_type="application/javascript")

    return router
