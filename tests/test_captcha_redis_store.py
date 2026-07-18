"""Exercises RedisTrustStore/RedisRunningRiskStore against fakeredis --
no live Redis service needed, matching the in-memory SQLite pattern
already used for the SQL store tests' `engine` fixture."""

from datetime import timedelta

import fakeredis.aioredis
import pytest_asyncio

from webapi_captcha.redis_store import RedisRunningRiskStore, RedisTrustStore
from webapi_captcha.risk import RiskLevel


@pytest_asyncio.fixture
async def redis() -> fakeredis.aioredis.FakeRedis:
    client = fakeredis.aioredis.FakeRedis()
    yield client
    await client.aclose()


async def test_redis_trust_store_trusts_then_expires(redis: fakeredis.aioredis.FakeRedis) -> None:
    store = RedisTrustStore(redis)

    assert await store.is_trusted(1) is False

    await store.trust(1, ttl=timedelta(hours=1))
    assert await store.is_trusted(1) is True

    await store.trust(2, ttl=timedelta(seconds=-1))  # already-expired ttl
    assert await store.is_trusted(2) is False


async def test_redis_trust_store_ip_binding(redis: fakeredis.aioredis.FakeRedis) -> None:
    store = RedisTrustStore(redis)
    await store.trust(1, ttl=timedelta(hours=1), ip="1.1.1.1")

    assert await store.is_trusted(1, ip="1.1.1.1") is True
    assert await store.is_trusted(1, ip="2.2.2.2") is False
    assert await store.is_trusted(1) is True  # ip=None -- no binding enforced


async def test_redis_running_risk_store_get_and_bump(
    redis: fakeredis.aioredis.FakeRedis,
) -> None:
    store = RedisRunningRiskStore(redis)

    assert await store.get(1) is None

    result = await store.bump(1, RiskLevel.ELEVATED, ttl=timedelta(minutes=30))
    assert result == RiskLevel.ELEVATED
    assert await store.get(1) == RiskLevel.ELEVATED


async def test_redis_running_risk_store_bump_never_lowers(
    redis: fakeredis.aioredis.FakeRedis,
) -> None:
    store = RedisRunningRiskStore(redis)

    await store.bump(1, RiskLevel.HIGH, ttl=timedelta(minutes=30))
    result = await store.bump(1, RiskLevel.LOW, ttl=timedelta(minutes=30))

    assert result == RiskLevel.HIGH
    assert await store.get(1) == RiskLevel.HIGH
