"""Cross-request replay detection -- the one defense in this package that
actually addresses the structural limit documented in
`webapi_captcha.scoring`: no single-request kinematic analysis can
tell a live human movement from a *replay* of a recorded one, because a
replayed genuine trajectory passes every kinematic check perfectly (it is
one). What a single request can never see, a *history* of requests can --
a bot replaying the same recording (its operator's own, purchased,
whatever) over and over, even across different accounts/devices/IPs to
dodge per-account or per-IP limits, leaves the same shape behind every
time. `RepeatedMovementCheck` catches exactly that: has this near-identical
mouse path been used for a verification recently, *by anyone*?

Deliberately global, not scoped to a user/IP/session -- the whole point is
catching the same recording surfacing under a *different* identity, which
per-account or per-IP rate limiting can't see by design.

Deliberately best-effort and fail-open, same as the rest of this package:
passes (doesn't block) when there's no `mouse_trajectory` to fingerprint,
or the pointer was touch/pen. It never penalizes a client that hasn't
wired `mouse_trajectory` up yet, and it doesn't try to catch "no movement
at all" -- that's what `signals.pointer_moves` and the interaction-time
heuristics in `captcha.scoring` are for. This check has exactly one job:
notice the *same* recording coming back.

Optional, like everything else here: drop it into a gate via
`extra_checks=[RepeatedMovementCheck(store)]`, or don't -- it isn't wired
into `SignalScoreCheck`'s default heuristics or any gate by default.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from webapi_captcha.checks import CheckOutcome, VerificationContext

# Positional/timing quantization for the fingerprint. Coarse enough that
# the natural jitter between two *different* human movements essentially
# never survives it identically (a real mouse path is noisy enough that
# rounding to a 6px/25ms grid still leaves plenty of entropy), but any
# exact replay of the same recording -- deltas from its own first sample
# -- collides every time, because the quantized deltas are identical.
DEFAULT_GRID_PX = 6.0
DEFAULT_GRID_MS = 25.0
DEFAULT_MAX_FINGERPRINT_POINTS = 200  # a coarse shape fingerprint doesn't need every sample
DEFAULT_MIN_FINGERPRINT_POINTS = 5


def fingerprint_trajectory(
    trajectory: Any,
    *,
    grid_px: float = DEFAULT_GRID_PX,
    grid_ms: float = DEFAULT_GRID_MS,
    max_points: int = DEFAULT_MAX_FINGERPRINT_POINTS,
    min_points: int = DEFAULT_MIN_FINGERPRINT_POINTS,
) -> str | None:
    """Builds a coarse, translation-invariant fingerprint from a
    `mouse_trajectory` signal: quantized `(dx, dy, dt)` deltas relative to
    the first sample, hashed. `None` if `trajectory` isn't a usable
    trajectory (missing, too short, malformed) -- callers treat that as
    "nothing to check", not as suspicious on its own.

    `grid_px`/`grid_ms`/`max_points`/`min_points` default to this
    module's own constants -- override them to make the fingerprint
    coarser (catch more near-identical-but-not-exact replays, at the
    cost of more false collisions between genuinely different
    movements) or finer (the opposite trade). `RepeatedMovementCheck`
    and `webapi_captcha.risk.ReplayRiskSignal` both accept the same four
    parameters and thread them through here -- keep them matched across
    both if you use both against the same store."""
    if not isinstance(trajectory, list) or len(trajectory) < min_points:
        return None
    points: list[tuple[float, float, float]] = []
    for sample in trajectory[:max_points]:
        if not isinstance(sample, list | tuple) or len(sample) != 3:
            return None
        try:
            points.append((float(sample[0]), float(sample[1]), float(sample[2])))
        except (TypeError, ValueError):
            return None
    x0, y0, t0 = points[0]
    quantized = tuple(
        (round((x - x0) / grid_px), round((y - y0) / grid_px), round((t - t0) / grid_ms))
        for x, y, t in points
    )
    return hashlib.sha256(repr(quantized).encode()).hexdigest()


class TrajectoryFingerprintStore(Protocol):
    """Where `RepeatedMovementCheck` remembers fingerprints it's already
    seen. Its own small Protocol (not reused from `CaptchaStore`) --
    this is a short-TTL "have I seen this shape before" cache, not a
    captcha answer, and doesn't need per-challenge attempt limits."""

    async def seen_recently(self, fingerprint: str) -> bool: ...

    async def record(self, fingerprint: str, ttl: timedelta) -> None: ...


class MemoryTrajectoryFingerprintStore:
    """Dict-backed `TrajectoryFingerprintStore`. Zero infrastructure -- the
    default. Not shared across processes; use
    `webapi_captcha.sql.SQLTrajectoryFingerprintStore` (or your own
    Redis-backed store) once you run more than one web replica, otherwise
    a replay bouncing between replicas behind a load balancer won't be
    caught reliably."""

    def __init__(self) -> None:
        self._seen: dict[str, datetime] = {}

    async def seen_recently(self, fingerprint: str) -> bool:
        self._sweep()
        return fingerprint in self._seen

    async def record(self, fingerprint: str, ttl: timedelta) -> None:
        self._seen[fingerprint] = datetime.now(UTC) + ttl

    def _sweep(self) -> None:
        now = datetime.now(UTC)
        for fingerprint in [fp for fp, expires_at in self._seen.items() if expires_at <= now]:
            del self._seen[fingerprint]


class RepeatedMovementCheck:
    """`VerificationCheck` that fails a verification whose mouse-trajectory
    fingerprint (see `fingerprint_trajectory`) matches one already recorded
    recently -- *by anyone*, not just this same user or session. See the
    module docstring for why "by anyone" (not per-user/per-IP) is the
    point: it's the one thing here that can catch a recording replayed
    across different identities to dodge ordinary rate limiting.

    Fails open (passes) when there's no `mouse_trajectory` to fingerprint
    or the pointer was touch/pen -- it never blocks a client that hasn't
    wired this signal up."""

    name = "no-repeated-movement"

    def __init__(
        self,
        store: TrajectoryFingerprintStore,
        *,
        ttl: timedelta = timedelta(hours=24),
        grid_px: float = DEFAULT_GRID_PX,
        grid_ms: float = DEFAULT_GRID_MS,
        max_fingerprint_points: int = DEFAULT_MAX_FINGERPRINT_POINTS,
        min_fingerprint_points: int = DEFAULT_MIN_FINGERPRINT_POINTS,
    ) -> None:
        self.store = store
        self.ttl = ttl
        self.grid_px = grid_px
        self.grid_ms = grid_ms
        self.max_fingerprint_points = max_fingerprint_points
        self.min_fingerprint_points = min_fingerprint_points

    async def run(self, ctx: VerificationContext) -> CheckOutcome:
        if ctx.signals.get("pointer_type") in ("touch", "pen"):
            return CheckOutcome(True)
        fingerprint = fingerprint_trajectory(
            ctx.signals.get("mouse_trajectory"),
            grid_px=self.grid_px,
            grid_ms=self.grid_ms,
            max_points=self.max_fingerprint_points,
            min_points=self.min_fingerprint_points,
        )
        if fingerprint is None:
            return CheckOutcome(True)
        if await self.store.seen_recently(fingerprint):
            return CheckOutcome(
                False, "this exact movement pattern was already used for a verification recently"
            )
        await self.store.record(fingerprint, self.ttl)
        return CheckOutcome(True)
