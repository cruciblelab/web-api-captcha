"""Exercises build_captcha_router() end to end via FastAPI's TestClient --
both the plain web-usage endpoints (no auth, no signed-in user involved) and
the bot-gated verification endpoints (the giveaway-bot scenario).
"""

import asyncio

from fastapi import FastAPI
from fastapi.testclient import TestClient

from webapi_captcha import (
    CaptchaGate,
    MathCaptchaProvider,
    MemoryCaptchaStore,
    MemoryVerificationStore,
    build_captcha_router,
)
from webapi_captcha.ratelimit import TokenBucketLimiter
from webapi_captcha.transport import InProcessTransport


def _build_app(
    *,
    verify_rate_limiter: TokenBucketLimiter | None = None,
    challenge_rate_limiter: TokenBucketLimiter | None = None,
    gate_verify_ip_rate_limiter: TokenBucketLimiter | None = None,
) -> tuple[FastAPI, CaptchaGate]:
    app = FastAPI()
    transport = InProcessTransport()
    provider = MathCaptchaProvider(MemoryCaptchaStore())
    gate = CaptchaGate(transport, MemoryVerificationStore(), provider)

    app.state.webapi_captcha_providers = {"math": provider}
    app.state.webapi_captcha_gate = gate
    app.include_router(
        build_captcha_router(
            verify_rate_limiter=verify_rate_limiter,
            challenge_rate_limiter=challenge_rate_limiter,
            gate_verify_ip_rate_limiter=gate_verify_ip_rate_limiter,
        )
    )
    return app, gate


def _build_account_app() -> tuple[FastAPI, CaptchaGate]:
    """An account-only gate behind a plain `current_user_id_resolver` --
    the same wiring any app plugging its own auth into this router would
    use (see build_captcha_router's module docstring for the
    discord-webapi equivalent). `app.state.signed_in_user_id` starts as
    None ("not signed in"); `_log_in()` flips it."""
    app = FastAPI()
    transport = InProcessTransport()
    gate = CaptchaGate(
        transport, MemoryVerificationStore(), require_captcha=False, require_account=True
    )
    app.state.webapi_captcha_gate = gate
    app.state.signed_in_user_id = None

    async def resolve_current_user_id() -> int | None:
        return app.state.signed_in_user_id  # type: ignore[no-any-return]

    app.include_router(build_captcha_router(current_user_id_resolver=resolve_current_user_id))
    return app, gate


def _log_in(app: FastAPI, user_id: int = 1) -> None:
    app.state.signed_in_user_id = user_id


# -- plain web usage --


def test_create_challenge_returns_a_renderable_image() -> None:
    app, _gate = _build_app()
    with TestClient(app) as client:
        resp = client.get("/api/captcha/challenge", params={"kind": "math"})

        assert resp.status_code == 200
        body = resp.json()
        assert body["kind"] == "math"
        assert body["image_data_uri"].startswith("data:image/png;base64,")


def test_create_challenge_for_an_unregistered_kind_is_404() -> None:
    app, _gate = _build_app()
    with TestClient(app) as client:
        resp = client.get("/api/captcha/challenge", params={"kind": "not-registered"})

        assert resp.status_code == 404


def test_proof_of_work_challenge_round_trips_params_over_http() -> None:
    """The invisible layer through the real API: the PoW parameters reach
    the client in the challenge JSON's `params`, a real solve is posted
    back, and the server verifies it. Proves the parameterized-provider
    path works end to end over HTTP, not just in-process."""
    import hashlib

    from webapi_captcha import MemoryCaptchaStore, ProofOfWorkProvider
    from webapi_captcha.providers.proof_of_work import _leading_zero_bits

    app = FastAPI()
    provider = ProofOfWorkProvider(MemoryCaptchaStore(), difficulty=8)
    app.state.webapi_captcha_providers = {"pow": provider}
    app.include_router(build_captcha_router())

    with TestClient(app) as client:
        challenge = client.get("/api/captcha/challenge", params={"kind": "pow"}).json()
        assert challenge["image_data_uri"] is None
        prefix = challenge["params"]["prefix"]
        difficulty = challenge["params"]["difficulty"]

        nonce = 0
        while _leading_zero_bits(hashlib.sha256(f"{prefix}{nonce}".encode()).digest()) < difficulty:
            nonce += 1

        verify = client.post(
            "/api/captcha/verify",
            json={"kind": "pow", "challenge_id": challenge["challenge_id"], "response": str(nonce)},
        )
        assert verify.json() == {"verified": True}


def test_verify_challenge_round_trip() -> None:
    app, gate = _build_app()
    with TestClient(app) as client:
        challenge_resp = client.get("/api/captcha/challenge", params={"kind": "math"})
        challenge_id = challenge_resp.json()["challenge_id"]

        provider: MathCaptchaProvider = gate.provider  # type: ignore[assignment]
        # the test drives the browser side of a real flow -- reads the
        # correct answer server-side the same way inspecting the rendered
        # image with your own eyes would, rather than reaching into
        # rendering internals.
        pending = asyncio.run(provider.store.get(challenge_id))
        assert pending is not None

        verify_resp = client.post(
            "/api/captcha/verify",
            json={"kind": "math", "challenge_id": challenge_id, "response": pending.answer},
        )

        assert verify_resp.status_code == 200
        assert verify_resp.json() == {"verified": True}


def test_verify_challenge_with_a_wrong_answer() -> None:
    app, _gate = _build_app()
    with TestClient(app) as client:
        challenge_resp = client.get("/api/captcha/challenge", params={"kind": "math"})
        challenge_id = challenge_resp.json()["challenge_id"]

        verify_resp = client.post(
            "/api/captcha/verify",
            json={"kind": "math", "challenge_id": challenge_id, "response": "definitely-wrong"},
        )

        assert verify_resp.json() == {"verified": False}


def test_verify_rate_limit_returns_429_when_exceeded() -> None:
    app, _gate = _build_app(verify_rate_limiter=TokenBucketLimiter(1, 60.0))
    with TestClient(app) as client:
        first = client.post(
            "/api/captcha/verify", json={"kind": "math", "challenge_id": "x", "response": "y"}
        )
        second = client.post(
            "/api/captcha/verify", json={"kind": "math", "challenge_id": "x", "response": "y"}
        )

        assert first.status_code == 200
        assert second.status_code == 429


def test_challenge_rate_limit_returns_429_when_exceeded() -> None:
    """Regression test: GET /challenge had no rate limiter at all --
    issuing a self-hosted challenge writes a fresh CaptchaStore row every
    call, so unbounded issuance was a cheap way to fill that store."""
    app, _gate = _build_app(challenge_rate_limiter=TokenBucketLimiter(1, 60.0))
    with TestClient(app) as client:
        first = client.get("/api/captcha/challenge", params={"kind": "math"})
        second = client.get("/api/captcha/challenge", params={"kind": "math"})

        assert first.status_code == 200
        assert second.status_code == 429


def test_gate_verify_ip_rate_limit_catches_one_ip_across_many_tokens() -> None:
    """Regression test: the existing verify_rate_limiter on
    /gate/{token}/verify is keyed by *token*, so it only ever bounds
    guesses against one specific token -- it does nothing to stop one IP
    from attempting many different tokens, each with its own fresh
    per-token budget. gate_verify_ip_rate_limiter closes that gap."""
    app, gate = _build_app(gate_verify_ip_rate_limiter=TokenBucketLimiter(1, 60.0))
    with TestClient(app) as client:
        token_a = asyncio.run(gate.create_verification(user_id=1, purpose="x")).token
        token_b = asyncio.run(gate.create_verification(user_id=2, purpose="x")).token

        first = client.post(f"/api/captcha/gate/{token_a}/verify", json={})
        # A *different* token from the *same* IP -- the per-token limiter
        # alone would let this through (it's that token's very first
        # call), but the IP-keyed limiter has already spent its 1 call.
        second = client.post(f"/api/captcha/gate/{token_b}/verify", json={})

        assert first.status_code == 200
        assert second.status_code == 429


# -- bot-gated verification (the giveaway-bot scenario) --


def test_gate_get_info_renders_the_verification_links_challenge() -> None:
    app, gate = _build_app()
    with TestClient(app) as client:
        request = asyncio.run(
            gate.create_verification(user_id=100, guild_id=999, purpose="giveaway_entry")
        )

        resp = client.get(f"/api/captcha/gate/{request.token}")

        assert resp.status_code == 200
        body = resp.json()
        assert body["challenge"]["challenge_id"] == request.challenge.challenge_id
        assert body["requires_captcha"] is True
        assert body["requires_account"] is False


def test_gate_get_challenge_of_unknown_token_is_404() -> None:
    app, _gate = _build_app()
    with TestClient(app) as client:
        resp = client.get("/api/captcha/gate/never-issued")

        assert resp.status_code == 404


def test_gate_verify_solves_the_giveaway_scenario() -> None:
    """End to end: create a verification link (what a giveaway bot's
    /join command would do), fetch its challenge (what the web page the
    bot's link points to would do), solve it, confirm success."""
    app, gate = _build_app()
    with TestClient(app) as client:
        request = asyncio.run(
            gate.create_verification(
                user_id=100,
                guild_id=999,
                purpose="giveaway_entry",
                metadata={"giveaway_id": "spring-giveaway"},
            )
        )
        provider: MathCaptchaProvider = gate.provider  # type: ignore[assignment]
        pending = asyncio.run(provider.store.get(request.challenge.challenge_id))
        assert pending is not None

        verify_resp = client.post(
            f"/api/captcha/gate/{request.token}/verify",
            json={"captcha_response": pending.answer},
        )

        assert verify_resp.status_code == 200
        assert verify_resp.json()["verified"] is True

        # the link is now spent, but re-fetching its info is NOT a 404 --
        # a page reload after success has to be able to tell "already
        # verified" apart from "gone/expired" (a real bug reported from
        # physical testing: this used to also be a 404, so a reload after
        # a successful verification showed a confusing "invalid or
        # expired" message for a link that had actually succeeded).
        followup = client.get(f"/api/captcha/gate/{request.token}")
        assert followup.status_code == 200
        assert followup.json()["verified"] is True


def test_gate_verify_of_unknown_token_returns_not_verified() -> None:
    app, _gate = _build_app()
    with TestClient(app) as client:
        resp = client.post(
            "/api/captcha/gate/never-issued/verify", json={"captcha_response": "anything"}
        )

        assert resp.status_code == 200
        assert resp.json()["verified"] is False


# -- account binding through a caller-supplied current_user_id_resolver --


def test_account_only_gate_needs_the_right_signed_in_user_via_http() -> None:
    """The trust anchor a captcha alone can't give: through the actual
    web flow, verifying an account-only link requires being signed in as
    the exact user it was issued for. `_log_in()` signs in as user id=1,
    so a link for user 1 verifies once signed in; a link for a different
    user does not."""
    app, gate = _build_account_app()
    with TestClient(app) as client:
        # not logged in yet -> account check fails
        req_for_1 = asyncio.run(gate.create_verification(user_id=1, purpose="giveaway_entry"))
        anon = client.post(f"/api/captcha/gate/{req_for_1.token}/verify", json={})
        assert anon.json()["verified"] is False
        assert anon.json()["failed_check"] == "account"

        _log_in(app)  # now signed in as user id=1

        # a link issued for someone else -> still fails even while logged in
        req_for_other = asyncio.run(
            gate.create_verification(user_id=999, purpose="giveaway_entry")
        )
        wrong = client.post(f"/api/captcha/gate/{req_for_other.token}/verify", json={})
        assert wrong.json()["verified"] is False
        assert wrong.json()["failed_check"] == "account"

        # a link issued for the signed-in user -> passes
        right = client.post(f"/api/captcha/gate/{req_for_1.token}/verify", json={})
        assert right.json()["verified"] is True


def test_captcha_router_without_a_gate_configured_returns_404_for_gate_routes() -> None:
    app = FastAPI()
    provider = MathCaptchaProvider(MemoryCaptchaStore())
    app.state.webapi_captcha_providers = {"math": provider}
    app.include_router(build_captcha_router())

    with TestClient(app) as client:
        resp = client.get("/api/captcha/gate/whatever")

        assert resp.status_code == 404


def test_adaptive_gate_escalates_to_a_real_captcha_only_for_a_blocked_ip() -> None:
    """End-to-end through real HTTP requests (not calling the gate
    directly): a clean IP never sees a captcha at all; a blocked IP gets
    a real one and must solve it."""
    from webapi_captcha.adaptive import AdaptiveCaptchaGate, MemoryAdaptiveDecisionStore
    from webapi_captcha.reputation import StaticBlocklistReputationChecker

    app = FastAPI()
    transport = InProcessTransport()
    gate = AdaptiveCaptchaGate(
        transport,
        MemoryVerificationStore(),
        StaticBlocklistReputationChecker(blocked_ips={"6.6.6.6"}),
        MathCaptchaProvider(MemoryCaptchaStore()),
        MemoryAdaptiveDecisionStore(),
    )
    app.include_router(build_captcha_router(gate=gate))

    clean_client = TestClient(app, client=("9.9.9.9", 12345))
    with clean_client:
        req = asyncio.run(gate.create_verification(user_id=1, purpose="signup"))
        info = clean_client.get(f"/api/captcha/gate/{req.token}").json()
        assert info["requires_captcha"] is False
        result = clean_client.post(f"/api/captcha/gate/{req.token}/verify", json={})
        assert result.json()["verified"] is True

    blocked_client = TestClient(app, client=("6.6.6.6", 12345))
    with blocked_client:
        req2 = asyncio.run(gate.create_verification(user_id=2, purpose="signup"))
        info2 = blocked_client.get(f"/api/captcha/gate/{req2.token}").json()
        assert info2["requires_captcha"] is True
        assert info2["challenge"]["kind"] == "math"

        wrong = blocked_client.post(
            f"/api/captcha/gate/{req2.token}/verify", json={"captcha_response": "nope"}
        )
        assert wrong.json()["verified"] is False
        assert wrong.json()["failed_check"] == "captcha"


def test_verify_gate_passes_the_real_client_ip_through_to_checks() -> None:
    """The HTTP layer must actually capture request.client.host and hand
    it to CaptchaGate.verify() as client_ip -- otherwise a custom
    IP-reputation extra_check has nothing real to read (see
    VerificationContext.client_ip's docstring for why this has to come
    from the server, not the client-submitted signals bag)."""
    from webapi_captcha.checks import PredicateCheck, VerificationContext

    seen_ips: list[str | None] = []

    async def record_ip(ctx: VerificationContext) -> bool:
        seen_ips.append(ctx.client_ip)
        return True

    app = FastAPI()
    transport = InProcessTransport()
    gate = CaptchaGate(
        transport,
        MemoryVerificationStore(),
        require_captcha=False,
        extra_checks=[PredicateCheck("record-ip", record_ip)],
    )
    app.include_router(build_captcha_router(gate=gate))

    with TestClient(app) as client:
        req = asyncio.run(gate.create_verification(user_id=1, purpose="x"))
        client.post(f"/api/captcha/gate/{req.token}/verify", json={})

    assert len(seen_ips) == 1
    assert seen_ips[0] is not None  # TestClient reports a real (test) client host


def test_verify_gate_passes_the_real_user_agent_through_to_checks() -> None:
    """Same reasoning as client_ip: the HTTP layer must capture the
    request's own User-Agent header and hand it to CaptchaGate.verify()
    as user_agent, for signals.reject_headless_user_agent (or a custom
    check) to read."""
    from webapi_captcha.checks import PredicateCheck, VerificationContext

    seen_uas: list[str | None] = []

    async def record_ua(ctx: VerificationContext) -> bool:
        seen_uas.append(ctx.user_agent)
        return True

    app = FastAPI()
    transport = InProcessTransport()
    gate = CaptchaGate(
        transport,
        MemoryVerificationStore(),
        require_captcha=False,
        extra_checks=[PredicateCheck("record-ua", record_ua)],
    )
    app.include_router(build_captcha_router(gate=gate))

    with TestClient(app) as client:
        req = asyncio.run(gate.create_verification(user_id=1, purpose="x"))
        client.post(
            f"/api/captcha/gate/{req.token}/verify",
            json={},
            headers={"user-agent": "my-test-agent/1.0"},
        )

    assert seen_uas == ["my-test-agent/1.0"]


def test_two_gates_can_be_mounted_at_once_via_explicit_gate_param() -> None:
    """A bot with two independent gate purposes (e.g. giveaway entry vs. a
    separate "verify before appealing a ban" gate) mounts the router twice
    under different prefixes, each bound to its own gate via `gate=` --
    app.state's single-gate slot never comes into it, so there's no
    cross-talk between the two."""
    app = FastAPI()
    transport = InProcessTransport()
    giveaway_gate = CaptchaGate(
        transport, MemoryVerificationStore(), require_captcha=False, require_account=False
    )
    appeal_gate = CaptchaGate(
        transport, MemoryVerificationStore(), require_captcha=False, require_account=False
    )
    app.include_router(build_captcha_router(gate=giveaway_gate), prefix="/giveaway")
    app.include_router(build_captcha_router(gate=appeal_gate), prefix="/appeal")

    with TestClient(app) as client:
        giveaway_req = asyncio.run(giveaway_gate.create_verification(user_id=1, purpose="join"))
        appeal_req = asyncio.run(appeal_gate.create_verification(user_id=1, purpose="appeal"))

        # each token only resolves under its own gate's prefix
        assert client.get(f"/giveaway/api/captcha/gate/{giveaway_req.token}").status_code == 200
        assert client.get(f"/giveaway/api/captcha/gate/{appeal_req.token}").status_code == 404
        assert client.get(f"/appeal/api/captcha/gate/{appeal_req.token}").status_code == 200
        assert client.get(f"/appeal/api/captcha/gate/{giveaway_req.token}").status_code == 404

        giveaway_result = client.post(
            f"/giveaway/api/captcha/gate/{giveaway_req.token}/verify", json={}
        )
        assert giveaway_result.json()["verified"] is True
        appeal_result = client.post(
            f"/appeal/api/captcha/gate/{appeal_req.token}/verify", json={}
        )
        assert appeal_result.json()["verified"] is True


def test_explicit_gate_param_takes_precedence_over_app_state() -> None:
    app = FastAPI()
    transport = InProcessTransport()
    state_gate = CaptchaGate(
        transport, MemoryVerificationStore(), require_captcha=False, require_account=False
    )
    explicit_gate = CaptchaGate(
        transport, MemoryVerificationStore(), require_captcha=False, require_account=False
    )
    app.state.webapi_captcha_gate = state_gate
    app.include_router(build_captcha_router(gate=explicit_gate), prefix="/explicit")

    with TestClient(app) as client:
        explicit_req = asyncio.run(explicit_gate.create_verification(user_id=1, purpose="x"))
        state_req = asyncio.run(state_gate.create_verification(user_id=1, purpose="x"))

        assert client.get(f"/explicit/api/captcha/gate/{explicit_req.token}").status_code == 200
        # the state gate's own token isn't known to the explicitly-bound gate
        assert client.get(f"/explicit/api/captcha/gate/{state_req.token}").status_code == 404
