"""Shared lazy, reused `httpx.AsyncClient` for the third-party providers
(`ReCaptchaProvider`/`HCaptchaProvider`/`TurnstileProvider`).

Each of these providers' `verify()` used to open a brand new
`httpx.AsyncClient()` and close it immediately after, every single call
-- a full TCP+TLS handshake on every verification, real latency/resource
cost under any real volume. This mixin creates ONE client per provider
INSTANCE, lazily (on first use), and reuses it across every subsequent
call -- connections get to actually stay warm (keep-alive) instead of
being torn down and rebuilt each time.

Pass your own `http_client=` at construction time instead if you want to
share a single client across multiple providers (or your whole app) --
that one is never touched or closed by this mixin; its lifecycle stays
entirely yours."""

from __future__ import annotations

import httpx


class _LazyHttpClientMixin:
    _external_http_client: httpx.AsyncClient | None
    _owned_http_client: httpx.AsyncClient | None

    def _init_http_client(self, http_client: httpx.AsyncClient | None) -> None:
        self._external_http_client = http_client
        self._owned_http_client = None

    def _http_client(self) -> httpx.AsyncClient:
        if self._external_http_client is not None:
            return self._external_http_client
        if self._owned_http_client is None:
            self._owned_http_client = httpx.AsyncClient()
        return self._owned_http_client

    async def aclose(self) -> None:
        """Closes the client this provider created internally, if any --
        a caller-supplied `http_client=` is never closed here, since its
        lifecycle belongs to whoever created it. Call this during your
        app's shutdown if you never passed your own `http_client=`."""
        if self._owned_http_client is not None:
            await self._owned_http_client.aclose()
            self._owned_http_client = None
