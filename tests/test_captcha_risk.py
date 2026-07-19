"""Exercises `RiskEngine` and its adapters -- the multi-signal decision
layer combining `IPReputationChecker`/`SignalScoreCheck`/custom signals
into one ordered `RiskLevel`, in front of `AdaptiveCaptchaGate`/
`PageGuard`'s escalation decision."""

from datetime import UTC, datetime, timedelta

from webapi_captcha.checks import VerificationContext
from webapi_captcha.models import VerificationRequest
from webapi_captcha.replay_guard import (
    MemoryTrajectoryFingerprintStore,
    RepeatedMovementCheck,
    fingerprint_trajectory,
)
from webapi_captcha.reputation import StaticBlocklistReputationChecker
from webapi_captcha.risk import (
    BehaviorScoreRiskSignal,
    ConditionalRiskSignal,
    CorroboratedRiskSignal,
    MemoryRunningRiskStore,
    ReplayRiskSignal,
    ReputationRiskSignal,
    RiskContext,
    RiskContribution,
    RiskEngine,
    RiskLevel,
)
from webapi_captcha.scoring import SignalScoreCheck


class _FixedSignal:
    def __init__(self, name: str, suspicion: float | None, weight: float = 1.0) -> None:
        self.name = name
        self.weight = weight
        self._suspicion = suspicion
        self.calls = 0

    async def assess(self, ctx: RiskContext) -> RiskContribution:
        self.calls += 1
        return RiskContribution(suspicion=self._suspicion)


class _OverrideSignal:
    def __init__(self, name: str, level: RiskLevel, weight: float = 1.0) -> None:
        self.name = name
        self.weight = weight
        self.level = level
        self.calls = 0

    async def assess(self, ctx: RiskContext) -> RiskContribution:
        self.calls += 1
        return RiskContribution(suspicion=1.0, hard_override=self.level)


class _RaisingSignal:
    name = "boom"
    weight = 1.0

    async def assess(self, ctx: RiskContext) -> RiskContribution:
        raise RuntimeError("flaky third-party API")


async def test_all_abstaining_signals_produce_minimal_risk() -> None:
    engine = RiskEngine([_FixedSignal("a", None), _FixedSignal("b", None)])
    assessment = await engine.assess(RiskContext())
    assert assessment.level == RiskLevel.MINIMAL
    assert assessment.suspicion == 0.0


async def test_weighted_suspicion_crosses_each_threshold_boundary() -> None:
    engine = RiskEngine([_FixedSignal("s", 0.9)])
    assessment = await engine.assess(RiskContext())
    assert assessment.level == RiskLevel.HIGH

    engine = RiskEngine([_FixedSignal("s", 0.6)])
    assessment = await engine.assess(RiskContext())
    assert assessment.level == RiskLevel.ELEVATED

    engine = RiskEngine([_FixedSignal("s", 0.3)])
    assessment = await engine.assess(RiskContext())
    assert assessment.level == RiskLevel.LOW

    engine = RiskEngine([_FixedSignal("s", 0.1)])
    assessment = await engine.assess(RiskContext())
    assert assessment.level == RiskLevel.MINIMAL


async def test_hard_override_wins_regardless_of_other_signals_suspicion() -> None:
    engine = RiskEngine(
        [_FixedSignal("clean", 0.0, weight=100.0), _OverrideSignal("bad", RiskLevel.HIGH)]
    )
    assessment = await engine.assess(RiskContext())
    assert assessment.level == RiskLevel.HIGH
    assert assessment.override_signal == "bad"


async def test_two_conflicting_overrides_the_higher_one_wins() -> None:
    engine = RiskEngine(
        [
            _OverrideSignal("low-override", RiskLevel.LOW),
            _OverrideSignal("high-override", RiskLevel.HIGH),
        ],
        short_circuit_on_override=False,
    )
    assessment = await engine.assess(RiskContext())
    assert assessment.level == RiskLevel.HIGH
    assert assessment.override_signal == "high-override"


async def test_short_circuit_on_override_skips_signals_after_it() -> None:
    trailing = _FixedSignal("never-called", 0.0)
    engine = RiskEngine(
        [_OverrideSignal("bad", RiskLevel.HIGH), trailing], short_circuit_on_override=True
    )
    await engine.assess(RiskContext())
    assert trailing.calls == 0


async def test_without_short_circuit_every_signal_still_runs_but_override_still_wins() -> None:
    trailing = _FixedSignal("still-called", 0.0)
    engine = RiskEngine(
        [_OverrideSignal("bad", RiskLevel.HIGH), trailing], short_circuit_on_override=False
    )
    assessment = await engine.assess(RiskContext())
    assert trailing.calls == 1
    assert assessment.level == RiskLevel.HIGH


async def test_a_signal_raising_is_treated_as_an_abstention_not_a_crash() -> None:
    engine = RiskEngine([_RaisingSignal(), _FixedSignal("ok", 0.9)])
    assessment = await engine.assess(RiskContext())
    assert assessment.level == RiskLevel.HIGH  # the other signal still counted
    assert assessment.contributions["boom"].suspicion is None


async def test_reputation_risk_signal_flags_as_a_hard_override() -> None:
    blocklist = StaticBlocklistReputationChecker(blocked_ips={"9.9.9.9"})
    signal = ReputationRiskSignal(blocklist, override_level=RiskLevel.HIGH)

    flagged = await signal.assess(RiskContext(client_ip="9.9.9.9"))
    assert flagged.hard_override == RiskLevel.HIGH

    clean = await signal.assess(RiskContext(client_ip="1.1.1.1"))
    assert clean.hard_override is None
    assert clean.suspicion == 0.0

    abstained = await signal.assess(RiskContext(client_ip=None))
    assert abstained.suspicion is None


async def test_behavior_score_risk_signal_inverts_signal_score_check() -> None:
    check = SignalScoreCheck()
    signals = {"webdriver": True}  # scores low human-likeness
    score, _ = check.compute(signals)

    contribution = await BehaviorScoreRiskSignal(check).assess(RiskContext(signals=signals))
    assert contribution.suspicion == 1.0 - score


async def test_behavior_score_risk_signal_abstains_with_no_signals_collected_yet() -> None:
    contribution = await BehaviorScoreRiskSignal().assess(RiskContext(signals={}))
    assert contribution.suspicion is None


async def test_risk_engine_is_suspicious_drop_in_at_the_elevated_line() -> None:
    engine = RiskEngine([_FixedSignal("s", 0.6)])  # ELEVATED
    assert await engine.is_suspicious("1.2.3.4") is True

    engine = RiskEngine([_FixedSignal("s", 0.3)])  # LOW
    assert await engine.is_suspicious("1.2.3.4") is False


async def test_add_signal_appends_by_default_and_inserts_before_a_named_signal() -> None:
    engine = RiskEngine([_FixedSignal("a", 0.0)])
    engine.add_signal(_FixedSignal("c", 0.0))
    assert [s.name for s in engine.signals] == ["a", "c"]

    engine.add_signal(_FixedSignal("b", 0.0), before="c")
    assert [s.name for s in engine.signals] == ["a", "b", "c"]


async def test_remove_signal_removes_and_returns_it_or_none_if_missing() -> None:
    target = _FixedSignal("gone", 0.0)
    engine = RiskEngine([_FixedSignal("a", 0.0), target])

    removed = engine.remove_signal("gone")
    assert removed is target
    assert [s.name for s in engine.signals] == ["a"]

    assert engine.remove_signal("gone") is None


async def test_get_signal_finds_by_name_and_its_weight_can_be_tuned_in_place() -> None:
    signal = _FixedSignal("tunable", 0.9, weight=1.0)
    engine = RiskEngine([signal])

    found = engine.get_signal("tunable")
    assert found is signal
    found.weight = 5.0  # type: ignore[union-attr]
    assert signal.weight == 5.0

    assert engine.get_signal("missing") is None


async def test_running_risk_store_bump_raises_but_never_lowers_the_level() -> None:
    store = MemoryRunningRiskStore()
    assert await store.get(1) is None

    result = await store.bump(1, RiskLevel.ELEVATED, ttl=timedelta(minutes=5))
    assert result == RiskLevel.ELEVATED
    assert await store.get(1) == RiskLevel.ELEVATED

    # A lower bump does not downgrade.
    result = await store.bump(1, RiskLevel.LOW, ttl=timedelta(minutes=5))
    assert result == RiskLevel.ELEVATED
    assert await store.get(1) == RiskLevel.ELEVATED

    result = await store.bump(1, RiskLevel.HIGH, ttl=timedelta(minutes=5))
    assert result == RiskLevel.HIGH


# -- enabled toggle --


async def test_disabled_signal_is_skipped_entirely_no_contribution_entry() -> None:
    signal = _FixedSignal("toggle-me", 0.9)
    signal.enabled = False  # type: ignore[attr-defined]
    engine = RiskEngine([signal])

    assessment = await engine.assess(RiskContext())

    assert "toggle-me" not in assessment.contributions
    assert assessment.level == RiskLevel.MINIMAL


async def test_disabled_signal_does_not_count_toward_short_circuit_bookkeeping() -> None:
    disabled_override = _OverrideSignal("disabled-override", RiskLevel.HIGH)
    disabled_override.enabled = False  # type: ignore[attr-defined]
    trailing = _FixedSignal("still-runs", 0.0)
    engine = RiskEngine([disabled_override, trailing], short_circuit_on_override=True)

    assessment = await engine.assess(RiskContext())

    assert trailing.calls == 1
    assert assessment.level == RiskLevel.MINIMAL


async def test_signal_without_enabled_attribute_defaults_to_enabled() -> None:
    signal = _FixedSignal("no-enabled-attr", 0.9)
    assert not hasattr(signal, "enabled")
    engine = RiskEngine([signal])

    assessment = await engine.assess(RiskContext())

    assert "no-enabled-attr" in assessment.contributions


async def test_reputation_and_behavior_signals_accept_and_store_enabled_kwarg() -> None:
    reputation_signal = ReputationRiskSignal(
        StaticBlocklistReputationChecker(blocked_ips={"1.2.3.4"}), enabled=False
    )
    behavior_signal = BehaviorScoreRiskSignal(enabled=False)
    assert reputation_signal.enabled is False
    assert behavior_signal.enabled is False

    engine = RiskEngine([reputation_signal, behavior_signal])
    assessment = await engine.assess(RiskContext(client_ip="1.2.3.4", signals={"webdriver": True}))

    assert assessment.contributions == {}
    assert assessment.level == RiskLevel.MINIMAL


# -- CorroboratedRiskSignal --


async def test_corroborated_signal_does_not_override_when_only_one_of_two_children_flags() -> None:
    composite = CorroboratedRiskSignal(
        [_OverrideSignal("bad-ip", RiskLevel.HIGH), _FixedSignal("clean-behavior", 0.0)]
    )
    contribution = await composite.assess(RiskContext())
    assert contribution.hard_override is None


async def test_corroborated_signal_overrides_when_all_children_flag() -> None:
    composite = CorroboratedRiskSignal(
        [_OverrideSignal("bad-ip", RiskLevel.HIGH), _FixedSignal("bad-behavior", 0.9)]
    )
    contribution = await composite.assess(RiskContext())
    assert contribution.hard_override == RiskLevel.HIGH


async def test_corroborated_signal_min_agreements_allows_k_of_n() -> None:
    composite = CorroboratedRiskSignal(
        [
            _OverrideSignal("a", RiskLevel.HIGH),
            _FixedSignal("b", 0.9),
            _FixedSignal("c", 0.0),  # the one holdout
        ],
        min_agreements=2,
    )
    contribution = await composite.assess(RiskContext())
    assert contribution.hard_override == RiskLevel.HIGH


async def test_corroborated_signal_abstaining_child_blocks_default_all_must_agree() -> None:
    composite = CorroboratedRiskSignal(
        [_OverrideSignal("a", RiskLevel.HIGH), _FixedSignal("abstains", None)]
    )
    contribution = await composite.assess(RiskContext())
    assert contribution.hard_override is None


async def test_corroborated_signal_disabled_child_is_excluded_not_counted_as_unflagged() -> None:
    disabled = _FixedSignal("disabled", 0.0)
    disabled.enabled = False  # type: ignore[attr-defined]
    composite = CorroboratedRiskSignal(
        [_OverrideSignal("a", RiskLevel.HIGH), _FixedSignal("b", 0.9), disabled]
    )
    contribution = await composite.assess(RiskContext())
    assert contribution.hard_override == RiskLevel.HIGH


async def test_corroborated_signal_suspicion_is_the_agreement_fraction_when_not_firing() -> None:
    # "a" (0.2) stays below the default suspicion_threshold (0.5) so it
    # doesn't count as agreeing; "b" (0.6) does -- 1 of 2 agree.
    composite = CorroboratedRiskSignal([_FixedSignal("a", 0.2), _FixedSignal("b", 0.6)])
    contribution = await composite.assess(RiskContext())
    assert contribution.hard_override is None
    assert contribution.suspicion == 0.5


async def test_corroborated_signal_one_agreeing_child_does_not_leak_its_own_suspicion() -> None:
    """Regression test for the bug the agreement-fraction design fixes:
    a single agreeing child (ReputationRiskSignal-shaped: suspicion=1.0)
    alongside an ABSTAINING one must not let the composite's own
    suspicion come out as 1.0 (which would independently cross
    RiskEngine's HIGH threshold, silently defeating corroboration)."""
    composite = CorroboratedRiskSignal(
        [_OverrideSignal("agrees", RiskLevel.HIGH), _FixedSignal("abstains", None)]
    )
    contribution = await composite.assess(RiskContext())
    assert contribution.hard_override is None
    assert contribution.suspicion == 0.5
    assert contribution.suspicion < 0.75  # RiskEngine's default HIGH threshold


async def test_corroborated_signal_abstains_when_all_children_abstain_or_are_disabled() -> None:
    disabled = _FixedSignal("disabled", 0.9)
    disabled.enabled = False  # type: ignore[attr-defined]
    composite = CorroboratedRiskSignal([_FixedSignal("abstains", None), disabled])
    contribution = await composite.assess(RiskContext())
    assert contribution.suspicion is None
    assert contribution.hard_override is None


async def test_corroborated_signal_child_exception_is_treated_as_abstention_not_a_crash() -> None:
    composite = CorroboratedRiskSignal([_RaisingSignal(), _FixedSignal("b", 0.9)])
    contribution = await composite.assess(RiskContext())
    assert contribution.hard_override is None  # only one (of two active) agreed


async def test_corroborated_signal_evaluates_every_child_ignoring_outer_short_circuit() -> None:
    a = _OverrideSignal("a", RiskLevel.HIGH)
    b = _FixedSignal("b", 0.0)
    composite = CorroboratedRiskSignal([a, b])
    await composite.assess(RiskContext())
    assert a.calls == 1
    assert b.calls == 1


async def test_corroborated_reputation_and_behavior_integration_via_risk_engine() -> None:
    blocklist = StaticBlocklistReputationChecker(blocked_ips={"9.9.9.9"})
    composite = CorroboratedRiskSignal(
        [ReputationRiskSignal(blocklist), BehaviorScoreRiskSignal()]
    )
    engine = RiskEngine([composite])

    # Blocklisted IP alone, no behavior signals collected yet -> no override.
    assessment = await engine.assess(RiskContext(client_ip="9.9.9.9"))
    assert assessment.level < RiskLevel.HIGH

    # Blocklisted IP AND suspicious behavior -> HIGH.
    assessment = await engine.assess(
        RiskContext(client_ip="9.9.9.9", signals={"webdriver": True})
    )
    assert assessment.level == RiskLevel.HIGH


# -- ReplayRiskSignal --

_TRAJECTORY_A = [[0, 0, 0], [10, 5, 20], [25, 12, 45], [40, 15, 70], [50, 15, 100]]


async def test_replay_risk_signal_abstains_with_no_trajectory_or_touch_pointer() -> None:
    signal = ReplayRiskSignal(MemoryTrajectoryFingerprintStore())

    assert (await signal.assess(RiskContext(signals={}))).suspicion is None
    assert (
        await signal.assess(RiskContext(signals={"pointer_type": "touch"}))
    ).suspicion is None


async def test_replay_risk_signal_never_calls_store_record() -> None:
    class _SpyStore:
        def __init__(self) -> None:
            self.record_calls = 0

        async def seen_recently(self, fingerprint: str) -> bool:
            return False

        async def record(self, fingerprint: str, ttl: timedelta) -> None:
            self.record_calls += 1

    store = _SpyStore()
    signal = ReplayRiskSignal(store)  # type: ignore[arg-type]
    for _ in range(5):
        await signal.assess(RiskContext(signals={"mouse_trajectory": _TRAJECTORY_A}))

    assert store.record_calls == 0


async def test_replay_risk_signal_flags_a_fingerprint_recorded_by_repeated_movement_check() -> None:
    store = MemoryTrajectoryFingerprintStore()
    check = RepeatedMovementCheck(store)
    signal = ReplayRiskSignal(store)

    now = datetime.now(UTC)
    request = VerificationRequest(
        token="t1",
        user_id=1,
        purpose="test",
        created_at=now,
        expires_at=now + timedelta(minutes=10),
    )
    ctx = VerificationContext(request=request, signals={"mouse_trajectory": _TRAJECTORY_A})
    outcome = await check.run(ctx)
    assert outcome.passed is True  # first time -- not a replay, and it gets recorded

    contribution = await signal.assess(RiskContext(signals={"mouse_trajectory": _TRAJECTORY_A}))
    assert contribution.hard_override == RiskLevel.HIGH


async def test_replay_risk_signal_does_not_self_poison_across_repeated_assess_calls() -> None:
    store = MemoryTrajectoryFingerprintStore()
    signal = ReplayRiskSignal(store)

    for _ in range(10):
        contribution = await signal.assess(RiskContext(signals={"mouse_trajectory": _TRAJECTORY_A}))
        assert contribution.hard_override is None


async def test_replay_risk_signal_override_level_none_produces_graded_suspicion() -> None:
    store = MemoryTrajectoryFingerprintStore()
    signal = ReplayRiskSignal(store, override_level=None)

    # Manufacture a "seen" fingerprint by recording the real one directly.
    fp = fingerprint_trajectory(_TRAJECTORY_A)
    assert fp is not None
    await store.record(fp, timedelta(hours=1))

    contribution = await signal.assess(RiskContext(signals={"mouse_trajectory": _TRAJECTORY_A}))
    assert contribution.hard_override is None
    assert contribution.suspicion == 1.0


async def test_replay_risk_signal_custom_grid_params_match_a_configured_check() -> None:
    store = MemoryTrajectoryFingerprintStore()
    check = RepeatedMovementCheck(store, grid_px=1.0, grid_ms=5.0)
    signal = ReplayRiskSignal(store, grid_px=1.0, grid_ms=5.0)

    now = datetime.now(UTC)
    request = VerificationRequest(
        token="t2",
        user_id=1,
        purpose="test",
        created_at=now,
        expires_at=now + timedelta(minutes=10),
    )
    ctx = VerificationContext(request=request, signals={"mouse_trajectory": _TRAJECTORY_A})
    await check.run(ctx)

    contribution = await signal.assess(RiskContext(signals={"mouse_trajectory": _TRAJECTORY_A}))
    assert contribution.hard_override == RiskLevel.HIGH


async def test_replay_risk_signal_respects_enabled_toggle_via_risk_engine() -> None:
    store = MemoryTrajectoryFingerprintStore()
    signal = ReplayRiskSignal(store, enabled=False)
    engine = RiskEngine([signal])

    assessment = await engine.assess(RiskContext(signals={"mouse_trajectory": _TRAJECTORY_A}))
    assert "replay" not in assessment.contributions


# -- ConditionalRiskSignal: "run `then` only if `when` flags" --


async def test_conditional_runs_then_only_when_the_when_signal_flags() -> None:
    gate = _FixedSignal("gate", 0.9)  # flags (>= default 0.5 threshold)
    followup = _FixedSignal("followup", 0.7)
    signal = ConditionalRiskSignal(when=gate, then=followup)

    contribution = await signal.assess(RiskContext())

    assert contribution.suspicion == 0.7  # then's own contribution surfaced
    assert followup.calls == 1


async def test_conditional_skips_then_entirely_when_when_does_not_flag() -> None:
    gate = _FixedSignal("gate", 0.1)  # below threshold -> does not flag
    followup = _FixedSignal("followup", 0.9)
    signal = ConditionalRiskSignal(when=gate, then=followup)

    contribution = await signal.assess(RiskContext())

    assert contribution.suspicion is None  # abstains
    assert followup.calls == 0  # the expensive check was never run


async def test_conditional_treats_a_hard_override_when_signal_as_flagging() -> None:
    gate = _OverrideSignal("bad-ip", RiskLevel.HIGH)
    followup = _FixedSignal("followup", 0.6)
    signal = ConditionalRiskSignal(when=gate, then=followup)

    contribution = await signal.assess(RiskContext())

    assert contribution.suspicion == 0.6
    assert followup.calls == 1


async def test_conditional_when_signal_exception_fails_open_and_skips_then() -> None:
    followup = _FixedSignal("followup", 0.9)
    signal = ConditionalRiskSignal(when=_RaisingSignal(), then=followup)

    contribution = await signal.assess(RiskContext())

    assert contribution.suspicion is None
    assert followup.calls == 0


async def test_conditional_then_signal_exception_fails_open() -> None:
    gate = _FixedSignal("gate", 0.9)
    signal = ConditionalRiskSignal(when=gate, then=_RaisingSignal())

    contribution = await signal.assess(RiskContext())

    assert contribution.suspicion is None


async def test_conditional_chains_a_then_b_then_c() -> None:
    a = _FixedSignal("a", 0.9)
    b = _FixedSignal("b", 0.9)
    c = _FixedSignal("c", 0.8)
    chain = ConditionalRiskSignal(when=a, then=ConditionalRiskSignal(when=b, then=c))

    contribution = await chain.assess(RiskContext())

    assert contribution.suspicion == 0.8
    assert a.calls == 1 and b.calls == 1 and c.calls == 1


async def test_conditional_chain_stops_at_the_first_non_flagging_link() -> None:
    a = _FixedSignal("a", 0.9)
    b = _FixedSignal("b", 0.1)  # does not flag -> c never runs
    c = _FixedSignal("c", 0.9)
    chain = ConditionalRiskSignal(when=a, then=ConditionalRiskSignal(when=b, then=c))

    contribution = await chain.assess(RiskContext())

    assert contribution.suspicion is None
    assert a.calls == 1 and b.calls == 1 and c.calls == 0


async def test_conditional_integrates_into_risk_engine_gating_an_expensive_check() -> None:
    cheap_gate = _FixedSignal("cheap", 0.1)  # clean -> expensive check skipped
    expensive = _FixedSignal("expensive", 0.9)
    engine = RiskEngine([ConditionalRiskSignal(when=cheap_gate, then=expensive)])

    assessment = await engine.assess(RiskContext())

    assert assessment.level == RiskLevel.MINIMAL
    assert expensive.calls == 0
