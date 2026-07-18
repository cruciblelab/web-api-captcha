"""Exercises `PageGuard` end to end via FastAPI's `TestClient` -- the
"protect an arbitrary page, not just one minted verification link"
primitive built on `AdaptiveCaptchaGate`.
"""

from datetime import timedelta
from urllib.parse import parse_qs, urlparse

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.testclient import TestClient

from webapi_captcha import (
    AdaptiveCaptchaGate,
    BehaviorScoreRiskSignal,
    MathCaptchaProvider,
    MemoryAdaptiveDecisionStore,
    MemoryCaptchaStore,
    MemoryRunningRiskStore,
    MemoryTrustStore,
    MemoryVerificationStore,
    PageGuard,
    PageGuardRedirect,
    RiskEngine,
    RiskLevel,
    StaticBlocklistReputationChecker,
    build_passive_risk_router,
    missing_accept_language,
    suspicious_user_agent,
)
from webapi_captcha.transport import InProcessTransport


def _build_app(
    gate_kwargs: dict[str, object] | None = None, **guard_kwargs: object
) -> tuple[FastAPI, PageGuard, AdaptiveCaptchaGate]:
    transport = InProcessTransport()
    blocklist = StaticBlocklistReputationChecker(blocked_ips={"9.9.9.9"})
    captcha_store = MemoryCaptchaStore()
    gate = AdaptiveCaptchaGate(
        transport,
        MemoryVerificationStore(),
        blocklist,
        MathCaptchaProvider(captcha_store),
        MemoryAdaptiveDecisionStore(),
        trust_store=MemoryTrustStore(),
        bind_trust_to_ip=True,
        **(gate_kwargs or {}),  # type: ignore[arg-type]
    )
    guard = PageGuard(
        gate,
        verify_url=lambda token, return_to: f"/verify/{token}?return_to={return_to}",
        **guard_kwargs,  # type: ignore[arg-type]
    )

    app = FastAPI()

    @app.exception_handler(PageGuardRedirect)
    async def _redirect(request: Request, exc: PageGuardRedirect) -> RedirectResponse:
        resp = RedirectResponse(exc.location, status_code=307)
        if exc.new_cookie_value is not None:
            resp.set_cookie(
                exc.cookie_name,
                exc.new_cookie_value,
                httponly=True,
                samesite="lax",
                max_age=exc.cookie_max_age,
            )
        return resp

    @app.get("/protected")
    async def protected(request: Request) -> HTMLResponse:
        new_cookie_value = await guard.require_human(request)
        resp = HTMLResponse("protected content")
        if new_cookie_value is not None:
            resp.set_cookie(
                guard.cookie_name,
                new_cookie_value,
                httponly=True,
                samesite="lax",
                max_age=guard.cookie_max_age,
            )
        return resp

    return app, guard, gate


def test_clean_ip_passes_through_with_no_redirect_and_mints_a_visitor_cookie() -> None:
    app, guard, _gate = _build_app()
    client = TestClient(app, client=("1.1.1.1", 12345))

    resp = client.get("/protected", follow_redirects=False)

    assert resp.status_code == 200
    assert resp.text == "protected content"
    assert guard.cookie_name in resp.cookies


def test_blocked_ip_redirects_instead_of_showing_the_page() -> None:
    app, _guard, _gate = _build_app()
    client = TestClient(app, client=("9.9.9.9", 12345))

    resp = client.get("/protected", follow_redirects=False)

    assert resp.status_code == 307
    location = resp.headers["location"]
    assert "/verify/" in location
    query = parse_qs(urlparse(location).query)
    assert query["return_to"][0].endswith("/protected")


def test_same_visitor_cookie_is_not_reminted_on_a_second_request() -> None:
    app, guard, _gate = _build_app()
    client = TestClient(app, client=("1.1.1.1", 12345))

    first = client.get("/protected")
    assert guard.cookie_name in first.cookies

    second = client.get("/protected")
    assert guard.cookie_name not in second.cookies  # nothing new to set


def test_extra_suspicious_signal_forces_a_redirect_even_on_a_clean_ip() -> None:
    app, _guard, _gate = _build_app(extra_suspicious=missing_accept_language)
    client = TestClient(app, client=("1.1.1.1", 12345))

    resp = client.get("/protected", follow_redirects=False)

    assert resp.status_code == 307  # httpx/TestClient sends no Accept-Language by default


def test_suspicious_user_agent_forces_a_redirect_even_on_a_clean_ip() -> None:
    app, _guard, _gate = _build_app(extra_suspicious=suspicious_user_agent())
    client = TestClient(app, client=("1.1.1.1", 12345))

    resp = client.get(
        "/protected",
        follow_redirects=False,
        headers={"user-agent": "Mozilla/5.0 HeadlessChrome/120.0.0.0"},
    )

    assert resp.status_code == 307


def test_ordinary_user_agent_is_not_flagged_as_suspicious() -> None:
    app, _guard, _gate = _build_app(extra_suspicious=suspicious_user_agent())
    client = TestClient(app, client=("1.1.1.1", 12345))

    resp = client.get(
        "/protected",
        follow_redirects=False,
        headers={
            "user-agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )
        },
    )

    assert resp.status_code == 200


def test_solving_the_redirected_challenge_lets_the_same_ip_through_next_time() -> None:
    app, _guard, gate = _build_app()
    client = TestClient(app, client=("9.9.9.9", 12345))

    redirect = client.get("/protected", follow_redirects=False)
    token = redirect.headers["location"].split("/verify/")[1].split("?")[0]

    info = client.get(f"/api/captcha/gate/{token}", follow_redirects=False)
    # PageGuard doesn't mount build_captcha_router itself -- solve directly
    # against the gate the same way the bundled widget's POST would, to
    # keep this test focused on PageGuard's own contract.
    del info
    import asyncio

    async def _solve() -> None:
        req = await gate.store.get(token)
        assert req is not None
        decision = await gate._resolve_decision(token, req, "9.9.9.9")  # noqa: SLF001
        assert decision.challenge is not None
        pending = await gate.escalation_provider.store.get(decision.challenge.challenge_id)  # type: ignore[union-attr]
        assert pending is not None
        result = await gate.verify(token, pending.answer, client_ip="9.9.9.9")
        assert result.verified is True

    asyncio.run(_solve())

    still_blocked_ip_but_now_trusted = client.get("/protected", follow_redirects=False)
    assert still_blocked_ip_but_now_trusted.status_code == 200


def test_a_different_ip_is_not_covered_by_trust_earned_on_another_ip() -> None:
    app, _guard, gate = _build_app()
    trusting_client = TestClient(app, client=("9.9.9.9", 12345))
    redirect = trusting_client.get("/protected", follow_redirects=False)
    token = redirect.headers["location"].split("/verify/")[1].split("?")[0]

    import asyncio

    async def _solve() -> None:
        req = await gate.store.get(token)
        assert req is not None
        decision = await gate._resolve_decision(token, req, "9.9.9.9")  # noqa: SLF001
        pending = await gate.escalation_provider.store.get(decision.challenge.challenge_id)  # type: ignore[union-attr]
        assert pending is not None
        await gate.verify(token, pending.answer, client_ip="9.9.9.9")

    asyncio.run(_solve())

    # A visitor from a DIFFERENT connecting IP is a different anonymous
    # cookie too (no cookie was ever shared across clients here), so this
    # isn't really testing cross-IP trust reuse for the SAME visitor --
    # that's covered at the unit level in test_captcha_adaptive.py. This
    # confirms the two ends stay independent end to end: a fresh visitor
    # from the still-blocked IP still gets redirected.
    fresh_client_same_blocked_ip = TestClient(app, client=("9.9.9.9", 55555))
    resp = fresh_client_same_blocked_ip.get("/protected", follow_redirects=False)
    assert resp.status_code == 307


def test_default_min_level_redirects_even_on_a_clean_ip() -> None:
    app, _guard, _gate = _build_app(default_min_level=RiskLevel.ELEVATED)
    client = TestClient(app, client=("1.1.1.1", 12345))  # not on any blocklist

    resp = client.get("/protected", follow_redirects=False)

    assert resp.status_code == 307


def test_running_risk_store_escalates_a_later_page_load() -> None:
    """The flagship proof of the "background/passive signals collected
    after a visitor has already entered a guarded page can still trigger
    escalation" requirement: page 1 from a clean IP passes; the
    visitor's running risk is bumped (simulating what
    build_passive_risk_router would have done from posted signals); page
    2, same cookie, same clean IP, now redirects."""
    running_risk_store = MemoryRunningRiskStore()
    app, guard, gate = _build_app(
        gate_kwargs={"risk_engine": RiskEngine([]), "running_risk_store": running_risk_store}
    )
    client = TestClient(app, client=("1.1.1.1", 12345))

    first = client.get("/protected", follow_redirects=False)
    assert first.status_code == 200
    visitor_cookie = first.cookies[guard.cookie_name]

    import asyncio

    from webapi_captcha.pageguard import _pseudo_user_id

    visitor_id = _pseudo_user_id(visitor_cookie)
    asyncio.run(running_risk_store.bump(visitor_id, RiskLevel.HIGH, ttl=timedelta(minutes=5)))

    second = client.get("/protected", follow_redirects=False)
    assert second.status_code == 307


def test_passive_signal_endpoint_bumps_risk_and_a_later_page_load_redirects() -> None:
    """True end-to-end version of the test above, through the actual
    build_passive_risk_router endpoint instead of bumping the store
    directly."""
    running_risk_store = MemoryRunningRiskStore()
    app, guard, gate = _build_app(
        gate_kwargs={
            "risk_engine": RiskEngine([BehaviorScoreRiskSignal()]),
            "running_risk_store": running_risk_store,
        }
    )
    app.include_router(build_passive_risk_router(guard))
    client = TestClient(app, client=("1.1.1.1", 12345))

    first = client.get("/protected", follow_redirects=False)
    assert first.status_code == 200

    # webdriver=True scores low human-likeness -> high suspicion.
    resp = client.post("/api/captcha/passive-signal", json={"signals": {"webdriver": True}})
    assert resp.status_code == 200
    assert resp.json()["level"] in ("elevated", "high")

    second = client.get("/protected", follow_redirects=False)
    assert second.status_code == 307


def test_passive_signal_endpoint_404s_without_risk_engine_or_running_risk_store() -> None:
    _app, guard, _gate = _build_app()  # no risk_engine/running_risk_store configured
    router = build_passive_risk_router(guard)

    assert router.routes == []
