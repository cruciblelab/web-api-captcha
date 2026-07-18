"""`TrustStore`/`RunningRiskStore` backed by `redis.asyncio` -- the
concrete "Redis fast tier" to pair with `webapi_captcha.tiered`'s
`TieredTrustStore`/`TieredRunningRiskStore` (or use standalone, without
tiering, if Redis alone is all the persistence you want).

Requires the `webapi-captcha[redis]` extra. Not part of the `all` extra
on purpose: `all` today means "sql + render" -- storage/rendering
backends with no assumption of a live external service you have to run
(SQLite via `aiosqlite` is embedded). Redis is a real service dependency,
so it stays an explicit opt-in, same principle as `sql-postgres` not
being silently required either.

Uses Redis's own native key expiry (`SET ... EX ...`) for eviction --
no `purge_expired()` method here, unlike the SQL stores, since there's
nothing to lazily sweep."""

from __future__ import annotations

import json
from datetime import timedelta

from redis.asyncio import Redis

from webapi_captcha.risk import RiskLevel

DEFAULT_TRUST_KEY_PREFIX = "wac:trust:"
DEFAULT_RISK_KEY_PREFIX = "wac:risk:"


def _expire_seconds(ttl: timedelta) -> int | None:
    """Redis's `SET ... EX ...` rejects a zero/negative expiry outright
    (`ResponseError: invalid expire time in set`) rather than treating it
    as "already expired" the way the Memory stores' plain `datetime.now()
    + ttl` comparison does. `None` here tells the caller to skip the
    `SET` entirely (and delete any existing entry) instead of passing a
    value Redis would reject -- same effective outcome (a caller-visible
    "not trusted"/"nothing remembered"), just without the round trip
    erroring."""
    seconds = int(ttl.total_seconds())
    return seconds if seconds > 0 else None


class RedisTrustStore:
    """`TrustStore` backed by `redis.asyncio`. One key per `user_id`,
    holding JSON `{"bound_ip": ...}`, with a native Redis `EX` set to
    `ttl`."""

    def __init__(self, redis: Redis, *, key_prefix: str = DEFAULT_TRUST_KEY_PREFIX) -> None:
        self.redis = redis
        self.key_prefix = key_prefix

    def _key(self, user_id: int) -> str:
        return f"{self.key_prefix}{user_id}"

    async def is_trusted(self, user_id: int, *, ip: str | None = None) -> bool:
        raw = await self.redis.get(self._key(user_id))
        if raw is None:
            return False
        bound_ip = json.loads(raw).get("bound_ip")
        if ip is not None and bound_ip is not None and bound_ip != ip:
            return False
        return True

    async def trust(self, user_id: int, *, ttl: timedelta, ip: str | None = None) -> None:
        seconds = _expire_seconds(ttl)
        if seconds is None:
            await self.redis.delete(self._key(user_id))
            return
        await self.redis.set(self._key(user_id), json.dumps({"bound_ip": ip}), ex=seconds)


class RedisRunningRiskStore:
    """`RunningRiskStore` backed by `redis.asyncio`. **`bump()` is a
    plain GET-then-SET, NOT atomic** -- a known, documented limitation
    for this v1 (concurrent bumps for the same `user_id` can race the
    same way `MemoryRunningRiskStore`'s does; unlike `SQLRunningRiskStore`,
    which is protected by a retry-on-conflict upsert, this does not use a
    Lua script or `WATCH`/`MULTI` transaction). Flag optimizing this as a
    follow-up if it matters for your traffic pattern, not a blocker for
    typical use (per-visitor bump frequency is low)."""

    def __init__(self, redis: Redis, *, key_prefix: str = DEFAULT_RISK_KEY_PREFIX) -> None:
        self.redis = redis
        self.key_prefix = key_prefix

    def _key(self, user_id: int) -> str:
        return f"{self.key_prefix}{user_id}"

    async def get(self, user_id: int) -> RiskLevel | None:
        raw = await self.redis.get(self._key(user_id))
        if raw is None:
            return None
        return RiskLevel(int(raw))

    async def bump(self, user_id: int, level: RiskLevel, *, ttl: timedelta) -> RiskLevel:
        current = await self.get(user_id)
        new_level = level if current is None else max(current, level)
        seconds = _expire_seconds(ttl)
        if seconds is None:
            await self.redis.delete(self._key(user_id))
        else:
            await self.redis.set(self._key(user_id), str(int(new_level)), ex=seconds)
        return new_level
