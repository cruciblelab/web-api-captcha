"""Exercises TieredTrustStore/TieredRunningRiskStore -- the fast/slow
cache-aside composition. Uses two Memory* stores as generic stand-ins
for "any TrustStore/RunningRiskStore" (fast and slow), proving the
wrapper is backend-agnostic -- no real Redis needed for these tests."""

from datetime import timedelta

from webapi_captcha.adaptive import MemoryTrustStore
from webapi_captcha.risk import MemoryRunningRiskStore, RiskLevel
from webapi_captcha.tiered import TieredRunningRiskStore, TieredTrustStore


async def test_tiered_trust_store_reads_fast_tier_first() -> None:
    fast, slow = MemoryTrustStore(), MemoryTrustStore()
    await fast.trust(1, ttl=timedelta(hours=1))
    tiered = TieredTrustStore(fast, slow)

    assert await tiered.is_trusted(1) is True
    assert await slow.is_trusted(1) is False  # never touched


async def test_tiered_trust_store_falls_back_to_slow_tier_on_fast_miss() -> None:
    fast, slow = MemoryTrustStore(), MemoryTrustStore()
    await slow.trust(1, ttl=timedelta(hours=1))
    tiered = TieredTrustStore(fast, slow)

    assert await tiered.is_trusted(1) is True


async def test_tiered_trust_store_write_caps_fast_tier_ttl() -> None:
    fast, slow = MemoryTrustStore(), MemoryTrustStore()
    tiered = TieredTrustStore(fast, slow, fast_ttl_cap=timedelta(seconds=-1))

    await tiered.trust(1, ttl=timedelta(hours=24))

    # Fast tier's own TTL was capped to a value already in the past --
    # its entry is effectively expired immediately.
    assert await fast.is_trusted(1) is False
    # Slow tier still got the full, uncapped ttl.
    assert await slow.is_trusted(1) is True
    # The composed read correctly falls through to slow.
    assert await tiered.is_trusted(1) is True


async def test_tiered_trust_store_neither_tier_trusted() -> None:
    tiered = TieredTrustStore(MemoryTrustStore(), MemoryTrustStore())
    assert await tiered.is_trusted(1) is False


async def test_tiered_running_risk_store_get_falls_back_to_slow_tier() -> None:
    fast, slow = MemoryRunningRiskStore(), MemoryRunningRiskStore()
    await slow.bump(1, RiskLevel.ELEVATED, ttl=timedelta(minutes=30))
    tiered = TieredRunningRiskStore(fast, slow)

    assert await tiered.get(1) == RiskLevel.ELEVATED


async def test_tiered_running_risk_store_bump_writes_both_tiers() -> None:
    fast, slow = MemoryRunningRiskStore(), MemoryRunningRiskStore()
    tiered = TieredRunningRiskStore(fast, slow)

    result = await tiered.bump(1, RiskLevel.HIGH, ttl=timedelta(minutes=30))

    assert result == RiskLevel.HIGH
    assert await fast.get(1) == RiskLevel.HIGH
    assert await slow.get(1) == RiskLevel.HIGH


async def test_tiered_running_risk_store_bump_merges_across_tiers_never_regresses() -> None:
    """The concrete regression scenario: HIGH is bumped, then the fast
    tier's entry expires (simulated here by a capped-to-the-past
    fast_ttl_cap) while the slow tier's still holds HIGH. A subsequent
    LOW bump must not let the merged/stored result regress below HIGH
    in either tier."""
    fast, slow = MemoryRunningRiskStore(), MemoryRunningRiskStore()
    tiered = TieredRunningRiskStore(fast, slow, fast_ttl_cap=timedelta(seconds=-1))

    await tiered.bump(1, RiskLevel.HIGH, ttl=timedelta(minutes=30))
    assert await fast.get(1) is None  # already expired due to the capped ttl
    assert await slow.get(1) == RiskLevel.HIGH

    result = await tiered.bump(1, RiskLevel.LOW, ttl=timedelta(minutes=30))

    assert result == RiskLevel.HIGH  # merged with the slow tier's still-live HIGH
    assert await slow.get(1) == RiskLevel.HIGH
    assert await tiered.get(1) == RiskLevel.HIGH


# -- resilience: the fast tier is disposable, the slow tier is the source of truth --


class _BrokenStore:
    """A TrustStore/RunningRiskStore stand-in that always raises --
    simulates a crashed/unreachable fast tier (e.g. Redis down)."""

    async def is_trusted(self, user_id: int, *, ip: str | None = None) -> bool:
        raise ConnectionError("simulated fast-tier outage")

    async def trust(self, user_id: int, *, ttl: timedelta, ip: str | None = None) -> None:
        raise ConnectionError("simulated fast-tier outage")

    async def get(self, user_id: int) -> RiskLevel | None:
        raise ConnectionError("simulated fast-tier outage")

    async def bump(self, user_id: int, level: RiskLevel, *, ttl: timedelta) -> RiskLevel:
        raise ConnectionError("simulated fast-tier outage")


async def test_tiered_trust_store_read_falls_back_to_slow_when_fast_tier_raises() -> None:
    slow = MemoryTrustStore()
    await slow.trust(1, ttl=timedelta(hours=1))
    tiered = TieredTrustStore(_BrokenStore(), slow)  # type: ignore[arg-type]

    assert await tiered.is_trusted(1) is True


async def test_tiered_trust_store_write_succeeds_when_only_fast_tier_raises() -> None:
    slow = MemoryTrustStore()
    tiered = TieredTrustStore(_BrokenStore(), slow)  # type: ignore[arg-type]

    await tiered.trust(1, ttl=timedelta(hours=1))  # must not raise

    assert await slow.is_trusted(1) is True  # the durable write still happened


async def test_tiered_trust_store_write_propagates_slow_tier_failure() -> None:
    fast = MemoryTrustStore()
    tiered = TieredTrustStore(fast, _BrokenStore())  # type: ignore[arg-type]

    try:
        await tiered.trust(1, ttl=timedelta(hours=1))
        raise AssertionError("expected the slow tier's failure to propagate")
    except ConnectionError:
        pass


async def test_tiered_trust_store_reports_fast_tier_errors() -> None:
    slow = MemoryTrustStore()
    reported: list[Exception] = []
    tiered = TieredTrustStore(
        _BrokenStore(), slow, on_fast_tier_error=reported.append  # type: ignore[arg-type]
    )

    await tiered.trust(1, ttl=timedelta(hours=1))
    await tiered.is_trusted(1)

    assert len(reported) == 2
    assert all(isinstance(exc, ConnectionError) for exc in reported)


async def test_tiered_running_risk_store_bump_succeeds_when_only_fast_tier_raises() -> None:
    slow = MemoryRunningRiskStore()
    tiered = TieredRunningRiskStore(_BrokenStore(), slow)  # type: ignore[arg-type]

    result = await tiered.bump(1, RiskLevel.HIGH, ttl=timedelta(minutes=30))

    assert result == RiskLevel.HIGH
    assert await slow.get(1) == RiskLevel.HIGH


async def test_tiered_running_risk_store_bump_propagates_slow_tier_failure() -> None:
    fast = MemoryRunningRiskStore()
    tiered = TieredRunningRiskStore(fast, _BrokenStore())  # type: ignore[arg-type]

    try:
        await tiered.bump(1, RiskLevel.HIGH, ttl=timedelta(minutes=30))
        raise AssertionError("expected the slow tier's failure to propagate")
    except ConnectionError:
        pass
