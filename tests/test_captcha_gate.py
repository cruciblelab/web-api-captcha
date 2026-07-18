"""Exercises CaptchaGate end to end -- the bot-gated verification flow
the giveaway-bot scenario in captcha/gate.py's docstring describes:
create a verification link, render its challenge, solve it, and confirm
the bot side is notified over Transport the moment it's solved."""

import asyncio
from datetime import timedelta

from webapi_captcha.checks import PredicateCheck, VerificationContext
from webapi_captcha.events import CaptchaVerified
from webapi_captcha.gate import CaptchaGate
from webapi_captcha.memory import MemoryCaptchaStore, MemoryVerificationStore
from webapi_captcha.providers.math_captcha import MathCaptchaProvider
from webapi_captcha.transport import InProcessTransport


def _make_gate(**kwargs: object) -> CaptchaGate:
    return CaptchaGate(
        InProcessTransport(),
        MemoryVerificationStore(),
        MathCaptchaProvider(MemoryCaptchaStore()),
        **kwargs,  # type: ignore[arg-type]
    )


async def test_create_verification_returns_a_token_and_challenge() -> None:
    gate = _make_gate()

    request = await gate.create_verification(
        user_id=100, guild_id=999, purpose="giveaway_entry", metadata={"giveaway_id": "abc"}
    )

    assert request.token
    assert request.user_id == 100
    assert request.guild_id == 999
    assert request.purpose == "giveaway_entry"
    assert request.metadata == {"giveaway_id": "abc"}
    assert request.challenge.image_data_uri is not None
    assert request.verified is False


async def test_get_challenge_returns_the_same_challenge_the_link_was_created_with() -> None:
    gate = _make_gate()
    request = await gate.create_verification(user_id=100, purpose="giveaway_entry")

    challenge = await gate.get_challenge(request.token)

    assert challenge is not None
    assert challenge.challenge_id == request.challenge.challenge_id


async def test_get_challenge_of_unknown_token_is_none() -> None:
    gate = _make_gate()

    assert await gate.get_challenge("never-issued") is None


async def test_full_giveaway_scenario_verify_notifies_the_bot_side() -> None:
    """The exact scenario CaptchaGate was built for: a giveaway bot's
    /join creates a verification link, DMs it to the user (not modeled
    here -- that's the bot's own choice of delivery), the user solves it
    on the web, and the bot -- subscribed via on_verified() -- gets told
    "you're in!" the instant it's solved, without polling."""
    gate = _make_gate()
    notified: list[CaptchaVerified] = []

    async def on_verified(event: CaptchaVerified) -> None:
        notified.append(event)

    gate.on_verified(on_verified)

    request = await gate.create_verification(
        user_id=100, guild_id=999, purpose="giveaway_entry", metadata={"giveaway_id": "abc"}
    )
    store: MemoryCaptchaStore = gate.provider.store  # type: ignore[attr-defined]
    pending = await store.get(request.challenge.challenge_id)
    assert pending is not None

    ok = await gate.verify(request.token, pending.answer)
    await asyncio.sleep(0.05)  # let InProcessTransport's fire-and-forget dispatch run

    assert ok.verified is True
    assert ok.passed == ["captcha"]
    assert len(notified) == 1
    assert notified[0].token == request.token
    assert notified[0].user_id == 100
    assert notified[0].guild_id == 999
    assert notified[0].purpose == "giveaway_entry"
    assert notified[0].metadata == {"giveaway_id": "abc"}
    assert notified[0].checks_passed == ["captcha"]


async def test_on_verified_without_purpose_filter_sees_every_gate_on_a_shared_transport() -> None:
    """The trap this is documenting: `captcha_verified` is one event type
    shared by every gate on the same Transport. Without a `purpose=`
    filter, a handler subscribed on gate A also fires for gate B's
    verifications -- this is the *old*, unfiltered default behavior,
    preserved for backwards compatibility."""
    transport = InProcessTransport()
    store = MemoryCaptchaStore()
    gate_a = CaptchaGate(transport, MemoryVerificationStore(), MathCaptchaProvider(store))
    gate_b = CaptchaGate(transport, MemoryVerificationStore(), MathCaptchaProvider(store))
    seen: list[CaptchaVerified] = []
    gate_a.on_verified(lambda event: seen.append(event))  # type: ignore[arg-type,return-value]

    req_a = await gate_a.create_verification(user_id=1, purpose="purpose_a")
    pending_a = await store.get(req_a.challenge.challenge_id)
    assert pending_a is not None
    await gate_a.verify(req_a.token, pending_a.answer)

    req_b = await gate_b.create_verification(user_id=2, purpose="purpose_b")
    pending_b = await store.get(req_b.challenge.challenge_id)
    assert pending_b is not None
    await gate_b.verify(req_b.token, pending_b.answer)
    await asyncio.sleep(0.05)

    assert [e.purpose for e in seen] == ["purpose_a", "purpose_b"]


async def test_on_verified_purpose_filter_ignores_other_gates_events() -> None:
    """Pass `purpose=` to fix the trap above: a handler only sees events
    whose `purpose` matches, so two gates sharing one Transport (a
    giveaway gate and a separate appeal gate, say) don't cross-fire."""
    transport = InProcessTransport()
    store = MemoryCaptchaStore()
    gate_a = CaptchaGate(transport, MemoryVerificationStore(), MathCaptchaProvider(store))
    gate_b = CaptchaGate(transport, MemoryVerificationStore(), MathCaptchaProvider(store))
    seen_a: list[CaptchaVerified] = []
    seen_b: list[CaptchaVerified] = []
    gate_a.on_verified(lambda event: seen_a.append(event), purpose="purpose_a")  # type: ignore[arg-type,return-value]
    gate_b.on_verified(lambda event: seen_b.append(event), purpose="purpose_b")  # type: ignore[arg-type,return-value]

    req_a = await gate_a.create_verification(user_id=1, purpose="purpose_a")
    pending_a = await store.get(req_a.challenge.challenge_id)
    assert pending_a is not None
    await gate_a.verify(req_a.token, pending_a.answer)

    req_b = await gate_b.create_verification(user_id=2, purpose="purpose_b")
    pending_b = await store.get(req_b.challenge.challenge_id)
    assert pending_b is not None
    await gate_b.verify(req_b.token, pending_b.answer)
    await asyncio.sleep(0.05)

    assert len(seen_a) == 1 and seen_a[0].purpose == "purpose_a"
    assert len(seen_b) == 1 and seen_b[0].purpose == "purpose_b"


async def test_verify_with_the_wrong_answer_does_not_notify_the_bot_side() -> None:
    gate = _make_gate()
    notified: list[CaptchaVerified] = []
    gate.on_verified(lambda event: notified.append(event))  # type: ignore[arg-type,return-value]

    request = await gate.create_verification(user_id=100, purpose="giveaway_entry")
    ok = await gate.verify(request.token, "definitely-wrong")

    assert ok.verified is False
    assert ok.failed_check == "captcha"
    assert notified == []


async def test_verify_is_idempotent_once_already_solved() -> None:
    """A page refresh re-posting the same solved form must not re-check
    the provider (which could reject a second use of a one-time answer) --
    it should just confirm "yes, already verified"."""
    gate = _make_gate()
    request = await gate.create_verification(user_id=100, purpose="giveaway_entry")
    store: MemoryCaptchaStore = gate.provider.store  # type: ignore[attr-defined]
    pending = await store.get(request.challenge.challenge_id)
    assert pending is not None

    first = await gate.verify(request.token, pending.answer)
    second = await gate.verify(request.token, "anything-at-all")

    assert first.verified is True
    assert second.verified is True


async def test_concurrent_verify_calls_for_the_same_token_only_succeed_and_publish_once() -> None:
    """Regression test: verify()'s check-then-mark-verified sequence used
    to have no locking, so two concurrent calls for the same token (a
    double-click, a client retry -- nothing server-side prevented it)
    could both observe verified=False, both pass their checks, and both
    publish captcha_verified -- a duplicate DM/credit for a bot-side
    on_verified() handler, contradicting verify()'s own "idempotent"
    claim. Uses a PredicateCheck with a real await inside it (an external
    anti-fraud service, per that class's own docstring) to force the two
    calls to genuinely interleave rather than run sequentially."""
    release = asyncio.Event()

    async def slow_check(ctx: VerificationContext) -> bool:
        await release.wait()
        return True

    gate = _make_gate(extra_checks=[PredicateCheck("slow", slow_check)])
    request = await gate.create_verification(user_id=100, purpose="giveaway_entry")
    store: MemoryCaptchaStore = gate.provider.store  # type: ignore[attr-defined]
    pending = await store.get(request.challenge.challenge_id)
    assert pending is not None

    verified_events: list[CaptchaVerified] = []

    async def on_verified(event: CaptchaVerified) -> None:
        verified_events.append(event)

    gate.on_verified(on_verified)

    async def call_verify() -> object:
        return await gate.verify(request.token, pending.answer)

    task_a = asyncio.create_task(call_verify())
    task_b = asyncio.create_task(call_verify())
    await asyncio.sleep(0.01)  # let both reach the slow check and start waiting
    release.set()
    result_a, result_b = await asyncio.gather(task_a, task_b)
    await asyncio.sleep(0.01)  # let the publish's fire-and-forget subscriber task run

    assert [result_a.verified, result_b.verified] == [True, True]
    assert len(verified_events) == 1, (
        "captcha_verified must publish exactly once for two concurrent "
        "verify() calls on the same token, not once per caller"
    )


async def test_get_challenge_after_verification_is_none() -> None:
    """A solved link has nothing left to show -- re-visiting it shouldn't
    render a stale challenge."""
    gate = _make_gate()
    request = await gate.create_verification(user_id=100, purpose="giveaway_entry")
    store: MemoryCaptchaStore = gate.provider.store  # type: ignore[attr-defined]
    pending = await store.get(request.challenge.challenge_id)
    assert pending is not None
    await gate.verify(request.token, pending.answer)

    assert await gate.get_challenge(request.token) is None


async def test_get_info_distinguishes_already_verified_from_gone() -> None:
    """Regression test for a real bug reported from physical testing: a
    page reload after a successful verification used to return `None`
    from `get_info()` -- exactly the same as a truly expired/unknown
    token -- so the frontend showed "this link is invalid or expired" for
    a link that had actually already succeeded. `verified=True` must be
    distinguishable from "gone" (`None`)."""
    gate = _make_gate()
    request = await gate.create_verification(user_id=100, purpose="giveaway_entry")
    store: MemoryCaptchaStore = gate.provider.store  # type: ignore[attr-defined]
    pending = await store.get(request.challenge.challenge_id)
    assert pending is not None

    before = await gate.get_info(request.token)
    assert before is not None
    assert before["verified"] is False

    await gate.verify(request.token, pending.answer)

    after = await gate.get_info(request.token)
    assert after is not None, "an already-verified token must not look 'gone'"
    assert after["verified"] is True
    assert after["challenge"] is None

    gone = await gate.get_info("never-issued-token")
    assert gone is None


async def test_expired_verification_is_treated_as_gone() -> None:
    gate = _make_gate(ttl=timedelta(seconds=-1))
    request = await gate.create_verification(user_id=100, purpose="giveaway_entry")

    assert await gate.get_challenge(request.token) is None
    assert not await gate.verify(request.token, "anything")


async def test_verify_of_unknown_token_is_false() -> None:
    gate = _make_gate()

    assert not await gate.verify("never-issued", "anything")


# -- account binding: the core "which account, not just a human" trust anchor --


async def test_account_only_gate_requires_the_right_signed_in_user() -> None:
    """require_captcha=False, require_account=True -- no image, the user
    just has to be signed in as the exact account the link was issued
    for. A forwarded link solved by someone else fails."""
    gate = CaptchaGate(
        InProcessTransport(),
        MemoryVerificationStore(),
        require_captcha=False,
        require_account=True,
    )
    request = await gate.create_verification(user_id=100, purpose="giveaway_entry")

    # no captcha challenge was issued for an account-only gate
    assert request.challenge is None

    # not signed in -> fails
    assert not await gate.verify(request.token)
    # signed in as the wrong account -> fails
    wrong = await gate.verify(request.token, authenticated_user_id=999)
    assert wrong.verified is False
    assert wrong.failed_check == "account"
    # signed in as the right account -> passes
    right = await gate.verify(request.token, authenticated_user_id=100)
    assert right.verified is True
    assert right.passed == ["account"]


async def test_safety_mode_requires_both_captcha_and_account() -> None:
    gate = CaptchaGate(
        InProcessTransport(),
        MemoryVerificationStore(),
        MathCaptchaProvider(MemoryCaptchaStore()),
        require_captcha=True,
        require_account=True,
    )
    request = await gate.create_verification(user_id=100, purpose="giveaway_entry")
    store: MemoryCaptchaStore = gate.provider.store  # type: ignore[union-attr]
    pending = await store.get(request.challenge.challenge_id)
    assert pending is not None

    # right captcha but not signed in -> account check blocks it
    only_captcha = await gate.verify(request.token, pending.answer)
    assert only_captcha.verified is False
    assert only_captcha.failed_check == "account"

    # right captcha AND right account -> both pass (account runs first, the
    # consuming captcha check last -- see CaptchaGate.__init__)
    both = await gate.verify(request.token, pending.answer, authenticated_user_id=100)
    assert both.verified is True
    assert both.passed == ["account", "captcha"]


async def test_click_only_gate_verifies_on_possession_of_the_link_alone() -> None:
    """No captcha, no account -- an empty check list. Merely POSTing to the
    valid (secret, one-time) token verifies it. The lowest-friction mode."""
    gate = CaptchaGate(
        InProcessTransport(),
        MemoryVerificationStore(),
        require_captcha=False,
        require_account=False,
    )
    request = await gate.create_verification(user_id=100, purpose="giveaway_entry")

    result = await gate.verify(request.token)

    assert result.verified is True
    assert result.passed == []


async def test_extra_checks_let_you_stack_your_own_layer() -> None:
    """The cake-layers case: our captcha layer plus the consumer's own
    check (here a trivial signal-based PredicateCheck). Both must pass."""
    seen_signals: list[dict] = []

    async def has_valid_signal(ctx: VerificationContext) -> bool:
        seen_signals.append(ctx.signals)
        return ctx.signals.get("passed_client_side_check") is True

    gate = CaptchaGate(
        InProcessTransport(),
        MemoryVerificationStore(),
        MathCaptchaProvider(MemoryCaptchaStore()),
        extra_checks=[PredicateCheck("client-signal", has_valid_signal)],
    )
    request = await gate.create_verification(user_id=100, purpose="giveaway_entry")
    store: MemoryCaptchaStore = gate.provider.store  # type: ignore[union-attr]
    pending = await store.get(request.challenge.challenge_id)
    assert pending is not None

    # captcha right but the custom signal missing -> the extra check blocks it
    blocked = await gate.verify(request.token, pending.answer, signals={})
    assert blocked.verified is False
    assert blocked.failed_check == "client-signal"

    # captcha right AND the custom signal present -> both pass
    ok = await gate.verify(
        request.token, pending.answer, signals={"passed_client_side_check": True}
    )
    assert ok.verified is True
    assert ok.passed == ["client-signal", "captcha"]


async def test_client_ip_reaches_a_custom_check_for_your_own_ip_reputation() -> None:
    """Answers a real question: can a consumer add their own signal, e.g.
    IP reputation, to the checks? Yes -- via extra_checks, same as any
    other custom layer -- but IP specifically isn't something the client
    submits via `signals` (that would be self-reported and forgeable);
    it has to come from the server's own observation of the connection,
    which is exactly what `ctx.client_ip` is for. This is a stand-in for
    "call your own reputation service/blocklist"."""
    blocked_ips = {"1.2.3.4"}

    async def reject_known_bad_ips(ctx: VerificationContext) -> bool:
        return ctx.client_ip not in blocked_ips

    gate = CaptchaGate(
        InProcessTransport(),
        MemoryVerificationStore(),
        MathCaptchaProvider(MemoryCaptchaStore()),
        extra_checks=[PredicateCheck("ip-reputation", reject_known_bad_ips)],
    )
    store: MemoryCaptchaStore = gate.provider.store  # type: ignore[union-attr]

    bad_req = await gate.create_verification(user_id=100, purpose="x")
    bad_pending = await store.get(bad_req.challenge.challenge_id)
    assert bad_pending is not None
    blocked = await gate.verify(bad_req.token, bad_pending.answer, client_ip="1.2.3.4")
    assert blocked.verified is False
    assert blocked.failed_check == "ip-reputation"

    good_req = await gate.create_verification(user_id=100, purpose="x")
    good_pending = await store.get(good_req.challenge.challenge_id)
    assert good_pending is not None
    ok = await gate.verify(good_req.token, good_pending.answer, client_ip="5.6.7.8")
    assert ok.verified is True


async def test_user_agent_reaches_a_custom_check() -> None:
    """Same reasoning as client_ip: user_agent is a server-observed value
    (the request's own User-Agent header), threaded through verify() into
    VerificationContext for a custom check (or the bundled
    signals.reject_headless_user_agent) to read."""

    async def reject_curl(ctx: VerificationContext) -> bool:
        return "curl" not in (ctx.user_agent or "").lower()

    gate = CaptchaGate(
        InProcessTransport(),
        MemoryVerificationStore(),
        MathCaptchaProvider(MemoryCaptchaStore()),
        extra_checks=[PredicateCheck("no-curl", reject_curl)],
    )
    store: MemoryCaptchaStore = gate.provider.store  # type: ignore[union-attr]

    bad_req = await gate.create_verification(user_id=100, purpose="x")
    bad_pending = await store.get(bad_req.challenge.challenge_id)
    assert bad_pending is not None
    blocked = await gate.verify(bad_req.token, bad_pending.answer, user_agent="curl/8.0.0")
    assert blocked.verified is False
    assert blocked.failed_check == "no-curl"

    good_req = await gate.create_verification(user_id=100, purpose="x")
    good_pending = await store.get(good_req.challenge.challenge_id)
    assert good_pending is not None
    ok = await gate.verify(good_req.token, good_pending.answer, user_agent="Mozilla/5.0")
    assert ok.verified is True


def test_require_captcha_without_a_provider_raises() -> None:
    import pytest

    with pytest.raises(ValueError, match="CaptchaProvider"):
        CaptchaGate(InProcessTransport(), MemoryVerificationStore(), require_captcha=True)
