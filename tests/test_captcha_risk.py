"""Exercises `RiskEngine` and its adapters -- the multi-signal decision
layer combining `IPReputationChecker`/`SignalScoreCheck`/custom signals
into one ordered `RiskLevel`, in front of `AdaptiveCaptchaGate`/
`PageGuard`'s escalation decision."""

from datetime import timedelta

from webapi_captcha.reputation import StaticBlocklistReputationChecker
from webapi_captcha.risk import (
    BehaviorScoreRiskSignal,
    MemoryRunningRiskStore,
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
