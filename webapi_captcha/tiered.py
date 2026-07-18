"""Generic fast/slow tier composition for `TrustStore`/`RunningRiskStore`
-- e.g. a short-TTL Redis-backed store in front of a durable SQL one, so
recent lookups (the vast majority of traffic) stay cheap while older
records still live somewhere. Cache-aside, not age-inspection: writes go
to BOTH tiers (the fast tier's own TTL capped at `fast_ttl_cap`, so it
naturally evicts itself and needs no manual "is this record old enough
to demote" bookkeeping); reads check the fast tier first, falling back
to the slow tier on a miss.

Generic over the `TrustStore`/`RunningRiskStore` Protocols (`webapi_
captcha.adaptive`/`webapi_captcha.risk`) -- `fast`/`slow` can be any
combination of `Memory*`/`SQL*`/your own store/the `Redis*` stores in
`webapi_captcha.redis_store`. No new dependency here; this module only
composes existing Store implementations."""

from __future__ import annotations

import asyncio
from datetime import timedelta

from webapi_captcha.adaptive import TrustStore
from webapi_captcha.risk import RiskLevel, RunningRiskStore

DEFAULT_FAST_TTL_CAP = timedelta(hours=6)


class TieredTrustStore:
    """`TrustStore` over a fast/slow pair. `trust()` has no monotonicity
    contract (it unconditionally sets a new trusted-until), so a plain
    write to both tiers is correct -- no read-before-write needed here,
    unlike `TieredRunningRiskStore.bump()` below."""

    def __init__(
        self, fast: TrustStore, slow: TrustStore, *, fast_ttl_cap: timedelta = DEFAULT_FAST_TTL_CAP
    ) -> None:
        self.fast = fast
        self.slow = slow
        self.fast_ttl_cap = fast_ttl_cap

    async def is_trusted(self, user_id: int, *, ip: str | None = None) -> bool:
        if await self.fast.is_trusted(user_id, ip=ip):
            return True
        return await self.slow.is_trusted(user_id, ip=ip)

    async def trust(self, user_id: int, *, ttl: timedelta, ip: str | None = None) -> None:
        await asyncio.gather(
            self.fast.trust(user_id, ttl=min(ttl, self.fast_ttl_cap), ip=ip),
            self.slow.trust(user_id, ttl=ttl, ip=ip),
        )


class TieredRunningRiskStore:
    """`RunningRiskStore` over a fast/slow pair. Unlike `TieredTrustStore`,
    `bump()` cannot just write both tiers verbatim: `RunningRiskStore`'s
    contract is that a level only ever rises, never drops (see `webapi_
    captcha.risk`'s `MemoryRunningRiskStore`/`SQLRunningRiskStore`). If
    the fast tier's entry has expired (its TTL is capped at
    `fast_ttl_cap`, shorter than the slow tier's) but the slow tier's
    hasn't, writing a lower `level` straight to the fast tier would let
    an immediate fast-tier read return that lower level -- silently
    regressing below what the slow tier still correctly remembers. So
    `bump()` reads the TRUE current level across both tiers first (via
    `get()`, which already does fast-then-slow fallback), takes
    `max(current, level)`, and writes THAT merged result to both tiers --
    mirroring exactly what the single-store implementations already do
    internally, just composed across two backing stores."""

    def __init__(
        self,
        fast: RunningRiskStore,
        slow: RunningRiskStore,
        *,
        fast_ttl_cap: timedelta = DEFAULT_FAST_TTL_CAP,
    ) -> None:
        self.fast = fast
        self.slow = slow
        self.fast_ttl_cap = fast_ttl_cap

    async def get(self, user_id: int) -> RiskLevel | None:
        level = await self.fast.get(user_id)
        if level is not None:
            return level
        return await self.slow.get(user_id)

    async def bump(self, user_id: int, level: RiskLevel, *, ttl: timedelta) -> RiskLevel:
        current = await self.get(user_id)
        new_level = level if current is None else max(current, level)
        await asyncio.gather(
            self.fast.bump(user_id, new_level, ttl=min(ttl, self.fast_ttl_cap)),
            self.slow.bump(user_id, new_level, ttl=ttl),
        )
        return new_level
