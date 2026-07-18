"""Generic fast/slow tier composition for `TrustStore`/`RunningRiskStore`
-- e.g. a short-TTL Redis-backed store in front of a durable SQL one, so
recent lookups (the vast majority of traffic) stay cheap while older
records still live somewhere. Cache-aside, not age-inspection: writes go
to BOTH tiers (the fast tier's own TTL capped at `fast_ttl_cap`, so it
naturally evicts itself and needs no manual "is this record old enough
to demote" bookkeeping); reads check the fast tier first, falling back
to the slow tier on a miss.

**The slow tier is the source of truth; the fast tier is disposable.**
This governs every failure-handling decision below: a `slow` write
failing (or raising) always propagates -- that's real data at risk, and
silently swallowing it would mean a caller believes something was
remembered when it wasn't. A `fast` operation failing (a Redis outage,
a connection drop, a crash mid-write) NEVER propagates and never blocks
the `slow` write -- losing the cache is, at worst, a slower read next
time (it falls through to `slow`), never a correctness problem. Writes
go to `slow` FIRST, synchronously, then `fast` -- not both concurrently
via `asyncio.gather()` (an earlier version of this module did that, and
it has a real, tested-and-confirmed gap: if `fast` fails, `gather()`
propagates immediately, but `slow`'s coroutine keeps running unawaited
in the background -- if `slow` *also* fails, that second, more important
failure is silently retrieved-and-discarded by `gather()` with no trace,
and the caller never learns their durable write may not have happened).
Sequential slow-then-fast has no such gap: by the time `fast` is even
attempted, `slow`'s outcome is already known.

Fast-tier READ failures are handled the same way: if `fast.is_trusted()`
`/get()` raises (e.g. Redis is down), that's caught and treated as a
miss, falling through to `slow` -- an outage in the fast tier should
degrade performance, not correctness or availability.

Pass `on_fast_tier_error` to observe these swallowed failures (logging,
metrics, alerting) without them affecting behavior.

Generic over the `TrustStore`/`RunningRiskStore` Protocols (`webapi_
captcha.adaptive`/`webapi_captcha.risk`) -- `fast`/`slow` can be any
combination of `Memory*`/`SQL*`/your own store/the `Redis*` stores in
`webapi_captcha.redis_store`. No new dependency here; this module only
composes existing Store implementations."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta

from webapi_captcha.adaptive import TrustStore
from webapi_captcha.risk import RiskLevel, RunningRiskStore

DEFAULT_FAST_TTL_CAP = timedelta(hours=6)


def _report(on_fast_tier_error: Callable[[Exception], None] | None, exc: Exception) -> None:
    if on_fast_tier_error is not None:
        on_fast_tier_error(exc)


class TieredTrustStore:
    """`TrustStore` over a fast/slow pair. `trust()` has no monotonicity
    contract (it unconditionally sets a new trusted-until), so there's no
    read-before-write needed here, unlike `TieredRunningRiskStore.bump()`
    below -- just a plain write to each tier, slow first. See the module
    docstring for why slow-first/fast-never-propagates is the rule."""

    def __init__(
        self,
        fast: TrustStore,
        slow: TrustStore,
        *,
        fast_ttl_cap: timedelta = DEFAULT_FAST_TTL_CAP,
        on_fast_tier_error: Callable[[Exception], None] | None = None,
    ) -> None:
        self.fast = fast
        self.slow = slow
        self.fast_ttl_cap = fast_ttl_cap
        self.on_fast_tier_error = on_fast_tier_error

    async def is_trusted(self, user_id: int, *, ip: str | None = None) -> bool:
        try:
            if await self.fast.is_trusted(user_id, ip=ip):
                return True
        except Exception as exc:  # noqa: BLE001 -- fast tier is disposable, see module docstring
            _report(self.on_fast_tier_error, exc)
        return await self.slow.is_trusted(user_id, ip=ip)

    async def trust(self, user_id: int, *, ttl: timedelta, ip: str | None = None) -> None:
        await self.slow.trust(user_id, ttl=ttl, ip=ip)  # source of truth -- let errors propagate
        try:
            await self.fast.trust(user_id, ttl=min(ttl, self.fast_ttl_cap), ip=ip)
        except Exception as exc:  # noqa: BLE001 -- fast tier is disposable, see module docstring
            _report(self.on_fast_tier_error, exc)


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
    `max(current, level)`, and writes THAT merged result to both tiers,
    slow first -- see the module docstring for why slow-first/fast-
    never-propagates is the rule for failure handling too."""

    def __init__(
        self,
        fast: RunningRiskStore,
        slow: RunningRiskStore,
        *,
        fast_ttl_cap: timedelta = DEFAULT_FAST_TTL_CAP,
        on_fast_tier_error: Callable[[Exception], None] | None = None,
    ) -> None:
        self.fast = fast
        self.slow = slow
        self.fast_ttl_cap = fast_ttl_cap
        self.on_fast_tier_error = on_fast_tier_error

    async def get(self, user_id: int) -> RiskLevel | None:
        try:
            level = await self.fast.get(user_id)
            if level is not None:
                return level
        except Exception as exc:  # noqa: BLE001 -- fast tier is disposable, see module docstring
            _report(self.on_fast_tier_error, exc)
        return await self.slow.get(user_id)

    async def bump(self, user_id: int, level: RiskLevel, *, ttl: timedelta) -> RiskLevel:
        current = await self.get(user_id)
        new_level = level if current is None else max(current, level)
        # Source of truth first -- let errors propagate.
        await self.slow.bump(user_id, new_level, ttl=ttl)
        try:
            await self.fast.bump(user_id, new_level, ttl=min(ttl, self.fast_ttl_cap))
        except Exception as exc:  # noqa: BLE001 -- fast tier is disposable, see module docstring
            _report(self.on_fast_tier_error, exc)
        return new_level
