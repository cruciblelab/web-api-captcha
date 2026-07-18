"""Multi-signal risk assessment -- the decision layer that decides HOW
suspicious a visitor is, before `AdaptiveCaptchaGate`/`PageGuard` decide
WHAT to do about it (show nothing, a self-hosted challenge, or escalate
to a stricter/third-party provider).

Same "bring your own, we provide the seam" philosophy as
`webapi_captcha.reputation`: no bundled ML, no scoring service, just a
`Protocol` and a combinator. `RiskEngine` lets you combine IP reputation,
behavioral scoring, and any custom signal you write into ONE ordered
`RiskLevel`, instead of the single binary "suspicious or not" question
`AdaptiveCaptchaGate` asked before this module existed.

**Polarity, read this before writing your own `RiskSignal`.**
`RiskContribution.suspicion` is the OPPOSITE polarity of
`webapi_captcha.scoring`'s heuristics (there, 1.0 = looks human; here,
1.0 = maximally suspicious) -- chosen so it agrees with `RiskLevel`'s own
ordering (higher = worse) instead of fighting it. `BehaviorScoreRiskSignal`
below is a worked example of the `1.0 - score` inversion this requires
when adapting a human-likeness-style scorer -- copy it, don't skip it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import IntEnum
from typing import Any, Protocol, runtime_checkable

from webapi_captcha.reputation import IPReputationChecker
from webapi_captcha.scoring import SignalScoreCheck


class RiskLevel(IntEnum):
    """Ordered, low to high -- `IntEnum` so `>=`, `max()`, and sorting
    all work directly (`RiskLevel.HIGH > RiskLevel.LOW` is just true).

    Deliberately NOT named `TRUSTED` at the floor: `TrustStore`
    (`webapi_captcha.adaptive`) already means something specific and
    stronger elsewhere in this package -- an earned, persisted, TTL'd
    claim from a past successful verification. `MINIMAL` only claims
    "no evidence of risk observed right now," a much weaker statement.
    """

    MINIMAL = 0
    LOW = 1
    ELEVATED = 2
    HIGH = 3


@dataclass
class RiskContext:
    """Everything a `RiskSignal` gets to look at. Usable before any
    `VerificationRequest` necessarily exists -- `PageGuard` calls this
    before a page even loads, with `signals={}` (nothing collected yet,
    since the client-side widget hasn't run)."""

    client_ip: str | None = None
    user_id: int | None = None
    purpose: str | None = None
    route: str | None = None
    signals: dict[str, Any] = field(default_factory=dict)
    user_agent: str | None = None


@dataclass
class RiskContribution:
    """`suspicion`: 0.0 = no evidence of risk, 1.0 = maximally
    suspicious -- see the module docstring for why this is the opposite
    polarity of `SignalScoreCheck.compute()`. `None` means abstain
    (nothing to go on), same convention as `HeuristicFn` -- left out of
    the weighted average entirely, never counted as either trustworthy
    or suspicious.

    `hard_override`: set this to short-circuit straight to a
    `RiskLevel` regardless of every other signal's opinion -- the "IP
    reputation is outright bad, skip straight to the strongest
    configured response" case."""

    suspicion: float | None
    hard_override: RiskLevel | None = None
    detail: str | None = None


@runtime_checkable
class RiskSignal(Protocol):
    """A unit contributing to risk assessment. `weight` lives here
    (not a parallel name-keyed dict on the engine) so a signal's own
    tuning travels with it -- the same reason `ScoringHeuristic` bundles
    its weight with its scoring function instead of a separate mapping."""

    name: str
    weight: float

    async def assess(self, ctx: RiskContext) -> RiskContribution: ...


@dataclass
class RiskAssessment:
    level: RiskLevel
    suspicion: float
    contributions: dict[str, RiskContribution]
    override_signal: str | None = None


class RiskEngine:
    """Combines multiple `RiskSignal`s into one `RiskLevel`: any
    `hard_override` wins (the highest one, if more than one signal fires
    one), otherwise a weighted average of `suspicion` is mapped onto
    `level_thresholds`.

    Signal ORDER matters when `short_circuit_on_override=True` (the
    default): signals are evaluated in list order, and evaluation stops
    the moment one returns a `hard_override` -- put cheap/local checks
    (a blocklist) before expensive ones (a paid fraud-score API, a
    third-party call) so a blocklisted IP never pays for the checks
    behind it.

    Every signal runs inside its own `try`/`except`: an exception is
    treated as an abstention (recorded in `detail`), not a crash -- a
    flaky third-party reputation API must not take down the whole
    decision path, the same fail-open ethos as the rest of this package.
    """

    def __init__(
        self,
        signals: Sequence[RiskSignal],
        *,
        level_thresholds: dict[RiskLevel, float] | None = None,
        short_circuit_on_override: bool = True,
    ) -> None:
        self.signals = list(signals)
        self.level_thresholds = level_thresholds or {
            RiskLevel.LOW: 0.25,
            RiskLevel.ELEVATED: 0.5,
            RiskLevel.HIGH: 0.75,
        }
        self.short_circuit_on_override = short_circuit_on_override

    async def assess(self, ctx: RiskContext) -> RiskAssessment:
        contributions: dict[str, RiskContribution] = {}
        best_override: RiskLevel | None = None
        override_signal: str | None = None
        weighted_sum = 0.0
        total_weight = 0.0

        for signal in self.signals:
            try:
                contribution = await signal.assess(ctx)
            except Exception as exc:  # noqa: BLE001 -- fail open, see class docstring
                contribution = RiskContribution(suspicion=None, detail=f"signal raised: {exc!r}")

            contributions[signal.name] = contribution

            if contribution.hard_override is not None and (
                best_override is None or contribution.hard_override > best_override
            ):
                best_override = contribution.hard_override
                override_signal = signal.name
                if self.short_circuit_on_override:
                    break

            if contribution.suspicion is not None:
                weighted_sum += contribution.suspicion * signal.weight
                total_weight += signal.weight

        suspicion = 0.0 if total_weight == 0 else weighted_sum / total_weight

        if best_override is not None:
            return RiskAssessment(
                level=best_override,
                suspicion=suspicion,
                contributions=contributions,
                override_signal=override_signal,
            )

        level = RiskLevel.MINIMAL
        for candidate in (RiskLevel.HIGH, RiskLevel.ELEVATED, RiskLevel.LOW):
            threshold = self.level_thresholds.get(candidate)
            if threshold is not None and suspicion >= threshold:
                level = candidate
                break

        return RiskAssessment(level=level, suspicion=suspicion, contributions=contributions)

    async def is_suspicious(self, ip: str) -> bool:
        """Drop-in `IPReputationChecker` compatibility -- lets a
        `RiskEngine` be passed anywhere an `IPReputationChecker` is
        expected today (`AdaptiveCaptchaGate`'s `reputation=`,
        `presets.build_cloudflare_style_guard`'s `reputation=`) for
        basic binary blocking, with none of the richer native
        integration wired up. Uses `RiskLevel.ELEVATED` as the line;
        call `.assess()` directly and compare to your own threshold if
        that's not the cut point you want."""
        assessment = await self.assess(RiskContext(client_ip=ip))
        return assessment.level >= RiskLevel.ELEVATED


class ReputationRiskSignal:
    """Bridges an existing `IPReputationChecker` into `RiskSignal` --
    preserves EXACTLY today's `AdaptiveCaptchaGate` behavior
    (`is_suspicious()==True` means "always escalate to the strongest
    configured response," no averaging, no partial credit) by returning
    a `hard_override` rather than a blended contribution. This is what
    makes an existing blocklist/paid-API `IPReputationChecker` reusable
    inside a `RiskEngine` with zero rewriting, and is the direct
    implementation of "if IP reputation is outright bad, skip straight
    to the strongest tier."
    """

    name = "ip-reputation"
    weight = 3.0

    def __init__(
        self, reputation: IPReputationChecker, *, override_level: RiskLevel = RiskLevel.HIGH
    ) -> None:
        self.reputation = reputation
        self.override_level = override_level

    async def assess(self, ctx: RiskContext) -> RiskContribution:
        if ctx.client_ip is None:
            return RiskContribution(suspicion=None, detail="no client_ip to check")
        if await self.reputation.is_suspicious(ctx.client_ip):
            return RiskContribution(
                suspicion=1.0, hard_override=self.override_level, detail="flagged by reputation"
            )
        return RiskContribution(suspicion=0.0)


class BehaviorScoreRiskSignal:
    """Bridges `SignalScoreCheck`'s continuous human-likeness score into
    a `RiskSignal`. Abstains (`suspicion=None`) when `ctx.signals` is
    empty -- which it structurally IS the first time a decision is made
    (before any client-side widget has posted anything)."""

    name = "behavior-score"
    weight = 2.0

    def __init__(self, check: SignalScoreCheck | None = None) -> None:
        self.check = check or SignalScoreCheck()

    async def assess(self, ctx: RiskContext) -> RiskContribution:
        if not ctx.signals:
            return RiskContribution(suspicion=None, detail="no signals collected yet")
        score, breakdown = self.check.compute(ctx.signals)
        parts = ", ".join(f"{name}={value:.2f}" for name, value in breakdown.items())
        detail = f"human-likeness={score:.2f} [{parts}]"
        return RiskContribution(suspicion=1.0 - score, detail=detail)


class RunningRiskStore(Protocol):
    """Where a visitor's ACCUMULATED risk level is remembered as passive
    signals arrive over the course of a session -- independent of, and
    in addition to, any per-token `AdaptiveDecision`. Deliberately
    monotonic in one direction: `bump()` can only ever raise a visitor's
    remembered level within `ttl` of the last update, never lower it --
    a clean-looking page view on request #5 does not erase suspicion
    earned on request #2.

    Exists separately from `AdaptiveDecisionStore`
    (`webapi_captcha.adaptive`) on purpose: a decision is made once for
    ONE verification token and stays fixed for that token's life; this
    tracks a VISITOR across many requests/tokens and is expected to
    change."""

    async def get(self, user_id: int) -> RiskLevel | None: ...

    async def bump(self, user_id: int, level: RiskLevel, *, ttl: timedelta) -> RiskLevel: ...


class MemoryRunningRiskStore:
    """Dict-backed `RunningRiskStore`. Zero infrastructure -- the
    default."""

    def __init__(self) -> None:
        self._levels: dict[int, tuple[RiskLevel, datetime]] = {}

    async def get(self, user_id: int) -> RiskLevel | None:
        entry = self._levels.get(user_id)
        if entry is None:
            return None
        level, expires_at = entry
        if datetime.now(UTC) > expires_at:
            del self._levels[user_id]
            return None
        return level

    async def bump(self, user_id: int, level: RiskLevel, *, ttl: timedelta) -> RiskLevel:
        current = await self.get(user_id)
        new_level = level if current is None else max(current, level)
        self._levels[user_id] = (new_level, datetime.now(UTC) + ttl)
        return new_level
