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

from webapi_captcha.replay_guard import (
    DEFAULT_GRID_MS,
    DEFAULT_GRID_PX,
    DEFAULT_MAX_FINGERPRINT_POINTS,
    DEFAULT_MIN_FINGERPRINT_POINTS,
    TrajectoryFingerprintStore,
    fingerprint_trajectory,
)
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
    its weight with its scoring function instead of a separate mapping.

    An `enabled: bool` attribute is an OPTIONAL convention, not a
    Protocol requirement -- `RiskEngine.assess()` checks it via
    `getattr(signal, "enabled", True)`, so a signal with no such
    attribute (any existing hand-written signal, or a plain object)
    is simply always enabled, and nothing breaks. Every signal shipped
    in this module has one (`enabled: bool = True` in its `__init__`);
    write your own the same way if you want it toggleable at runtime
    the same way (`engine.get_signal("mine").enabled = False`) --
    Protocol membership is deliberately NOT required for this, since
    making it required would break every existing third-party signal
    that predates this convention, for no real benefit (Python doesn't
    need a declared attribute to allow reading/writing one)."""

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

    def add_signal(self, signal: RiskSignal, *, before: str | None = None) -> None:
        """Register a new signal at runtime -- e.g. wire in a paid
        fraud-score API only once an admin turns a feature flag on,
        without rebuilding the whole `RiskEngine`/gate/`PageGuard` stack.
        `signals`/`level_thresholds`/`short_circuit_on_override` are all
        plain public attributes too -- mutate them directly (`engine.
        signals.append(...)`, `engine.level_thresholds[RiskLevel.HIGH] =
        0.9`, ...) whenever a method here doesn't cover what you need;
        this class deliberately keeps no private/hidden state to work
        around.

        `before`: insert ahead of the first signal with this `name`
        instead of appending -- matters when
        `short_circuit_on_override=True`, since evaluation order decides
        which cheap checks run before an expensive one gets a chance to
        short-circuit (see the class docstring)."""
        if before is not None:
            for index, existing in enumerate(self.signals):
                if existing.name == before:
                    self.signals.insert(index, signal)
                    return
        self.signals.append(signal)

    def remove_signal(self, name: str) -> RiskSignal | None:
        """Removes and returns the first signal with this `name`, or
        `None` if none matched -- the inverse of `add_signal()`, for
        turning a signal off at runtime (e.g. a feature flag flip, a
        third-party API you've decided to stop trusting)."""
        for index, existing in enumerate(self.signals):
            if existing.name == name:
                return self.signals.pop(index)
        return None

    def get_signal(self, name: str) -> RiskSignal | None:
        """Looks up a registered signal by name -- e.g. to read or tweak
        its own `weight` in place (`engine.get_signal("behavior-score").
        weight = 4.0`) without removing and re-adding it."""
        for existing in self.signals:
            if existing.name == name:
                return existing
        return None

    async def assess(self, ctx: RiskContext) -> RiskAssessment:
        contributions: dict[str, RiskContribution] = {}
        best_override: RiskLevel | None = None
        override_signal: str | None = None
        weighted_sum = 0.0
        total_weight = 0.0

        for signal in self.signals:
            if not getattr(signal, "enabled", True):
                continue
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

    def __init__(
        self,
        reputation: IPReputationChecker,
        *,
        override_level: RiskLevel = RiskLevel.HIGH,
        name: str = "ip-reputation",
        weight: float = 3.0,
        enabled: bool = True,
    ) -> None:
        self.reputation = reputation
        self.override_level = override_level
        self.name = name
        self.weight = weight
        self.enabled = enabled

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

    def __init__(
        self,
        check: SignalScoreCheck | None = None,
        *,
        name: str = "behavior-score",
        weight: float = 2.0,
        enabled: bool = True,
    ) -> None:
        self.check = check or SignalScoreCheck()
        self.name = name
        self.weight = weight
        self.enabled = enabled

    async def assess(self, ctx: RiskContext) -> RiskContribution:
        if not ctx.signals:
            return RiskContribution(suspicion=None, detail="no signals collected yet")
        score, breakdown = self.check.compute(ctx.signals)
        parts = ", ".join(f"{name}={value:.2f}" for name, value in breakdown.items())
        detail = f"human-likeness={score:.2f} [{parts}]"
        return RiskContribution(suspicion=1.0 - score, detail=detail)


class CorroboratedRiskSignal:
    """Requires 2+ underlying signals to independently agree before
    firing an override -- the fix for `ReputationRiskSignal`'s own
    "IP reputation alone jumps straight to the strongest tier" behavior
    being too blunt for some deployments: wrap it alongside
    `BehaviorScoreRiskSignal` (or any other signal) here instead of
    adding `ReputationRiskSignal` to the engine directly, and a bad IP
    on its own no longer forces an escalation -- it needs a second
    signal to also look suspicious.

    A child "agrees" (counts towards `min_agreements`) if it either (a)
    returned its own `hard_override`, or (b) returned a `suspicion >=
    suspicion_threshold` -- (b) exists because most signals (e.g.
    `BehaviorScoreRiskSignal`) never set a `hard_override` at all, so
    without it, wrapping one here could never count as "agreeing,"
    making a mixed IP+behavior corroboration group impossible to build.

    An ABSTAINING child (`suspicion=None`, no override -- e.g.
    `ReputationRiskSignal` with no `client_ip`, `BehaviorScoreRiskSignal`
    with no signals collected yet) never counts as agreeing, but also
    isn't "clean" -- it's simply excluded from both the numerator and
    denominator, the same fail-closed-on-uncertainty posture as the rest
    of this package (an absent opinion should never quietly satisfy a
    corroboration requirement).

    A DISABLED child (`enabled=False`, see the `RiskSignal` Protocol
    docstring) is excluded the same way, entirely -- not counted in
    `min_agreements`'s denominator either. This matters: without it,
    disabling one child would make the (default) "every child must
    agree" requirement permanently unsatisfiable by an always-failing
    phantom participant. The trade-off this creates is deliberate and
    worth knowing: disabling children can make `min_agreements` (if set
    higher than the number of children left enabled) unreachable until
    you re-enable one -- surfaced here, not silently patched over.

    `min_agreements=None` (the default) means every currently-enabled
    child must agree -- literal AND. Set it explicitly (e.g. `2` over 3
    children) for k-of-n tolerance instead.

    When it fires, `suspicion=1.0` and `hard_override=override_level`
    (the composite's OWN configured level -- not derived from children's
    individual override levels, since most children never set one).

    When it doesn't fire, its own `suspicion` is `flagged / active` --
    the AGREEMENT FRACTION, not an average of the children's raw
    suspicion values. This was the trickiest design point, and worth
    spelling out because the first, more obvious choice (average the
    active children's `suspicion`) is subtly wrong: with only one
    non-abstaining child (a common shape -- e.g. `ReputationRiskSignal`
    flags while `BehaviorScoreRiskSignal` has no signals yet to work
    with), an average of one value degenerates to exactly that child's
    own `suspicion` -- which for `ReputationRiskSignal` is `1.0` on its
    own, high enough to cross `RiskEngine`'s default `HIGH` threshold by
    itself, silently recreating the unilateral-override problem this
    whole class exists to prevent, just one layer removed and with no
    `hard_override` set to make it obvious in a test. `flagged / active`
    doesn't have this failure mode: this branch only runs when `flagged
    < required`, so the fraction is always strictly below `required /
    active <= 1.0` -- it structurally cannot alone reach the same
    confidence as full agreement, which is the entire point.

    Evaluates EVERY enabled child, always -- ignores the outer
    `RiskEngine`'s `short_circuit_on_override`, since judging agreement
    structurally needs every child's opinion. Each child still runs
    inside its own `try`/`except` (an exception = abstention), same
    fail-open ethos as `RiskEngine.assess()` itself.
    """

    def __init__(
        self,
        signals: Sequence[RiskSignal],
        *,
        override_level: RiskLevel = RiskLevel.HIGH,
        suspicion_threshold: float = 0.5,
        min_agreements: int | None = None,
        name: str = "corroborated",
        weight: float = 3.0,
        enabled: bool = True,
    ) -> None:
        self.signals = list(signals)
        self.override_level = override_level
        self.suspicion_threshold = suspicion_threshold
        self.min_agreements = min_agreements
        self.name = name
        self.weight = weight
        self.enabled = enabled

    async def assess(self, ctx: RiskContext) -> RiskContribution:
        flagged = 0
        active = 0
        contributed = 0  # active children that weren't themselves abstentions

        for child in self.signals:
            if not getattr(child, "enabled", True):
                continue
            active += 1
            try:
                contribution = await child.assess(ctx)
            except Exception as exc:  # noqa: BLE001 -- fail open, see class docstring
                contribution = RiskContribution(suspicion=None, detail=f"signal raised: {exc!r}")

            if contribution.suspicion is not None or contribution.hard_override is not None:
                contributed += 1

            if _signal_flags(contribution, self.suspicion_threshold):
                flagged += 1

        if active == 0:
            return RiskContribution(suspicion=None, detail="no active child signals")
        if contributed == 0:
            return RiskContribution(suspicion=None, detail="every active child signal abstained")

        required = self.min_agreements if self.min_agreements is not None else active
        if flagged >= required:
            return RiskContribution(
                suspicion=1.0,
                hard_override=self.override_level,
                detail=f"{flagged}/{active} child signals agreed",
            )

        return RiskContribution(
            suspicion=flagged / active, detail=f"only {flagged}/{active} child signals agreed"
        )


def _signal_flags(contribution: RiskContribution, threshold: float) -> bool:
    """The shared "did this signal raise a concern" test used by both
    `CorroboratedRiskSignal` and `ConditionalRiskSignal`: a `hard_override`
    counts, or a graded `suspicion` at/above `threshold`. An abstention
    (`suspicion=None`, no override) never counts as flagging."""
    return contribution.hard_override is not None or (
        contribution.suspicion is not None and contribution.suspicion >= threshold
    )


class ConditionalRiskSignal:
    """Runs `then` ONLY when `when` flags first -- the "if IP reputation
    is suspicious, THEN also run this deeper/more-expensive check" chain,
    generalized to any two signals (neither has to be IP reputation).

    Why this exists separately from `RiskEngine`'s own ordering: the
    engine evaluates every signal and blends them; `short_circuit_on_
    override` only lets an *override* stop later signals early. Neither
    gives you "don't even RUN signal B unless cheap signal A already
    looked suspicious" -- which is exactly what you want when B is a paid
    fraud API, a slow third-party lookup, or any check you'd rather not
    pay for on the ~99% of traffic that A already cleared. `when` is the
    cheap gatekeeper; `then` is the expensive follow-up that only fires
    behind it.

    When `when` flags (`hard_override`, or `suspicion >= threshold`),
    this signal's contribution IS `then`'s contribution -- so `then` can
    hard-override, contribute a graded suspicion, or abstain, exactly as
    it would standalone. When `when` does NOT flag, this abstains
    (`suspicion=None`) WITHOUT running `then` at all -- that skipped call
    is the whole point.

    Chainable: `then` can itself be a `ConditionalRiskSignal`, so
    `A -> B -> C` (run B only if A flags, run C only if B then flags) is
    just `ConditionalRiskSignal(when=A, then=ConditionalRiskSignal(
    when=B, then=C))`. Build whatever chain you want; nothing here is
    hardcoded to reputation.

    `when`/`then` each run inside their own `try`/`except` (an exception
    is treated as an abstention -- and an exception in `when` means
    `then` is NOT run), same fail-open ethos as `RiskEngine.assess()`.

    Note the `when` signal does NOT itself contribute to the engine
    through this wrapper -- only `then`'s result surfaces. If you also
    want `when`'s own opinion counted (e.g. reputation's own override to
    still apply independently), add `when` to the engine's signal list
    separately too; the two compose cleanly.
    """

    def __init__(
        self,
        *,
        when: RiskSignal,
        then: RiskSignal,
        threshold: float = 0.5,
        name: str = "conditional",
        weight: float = 1.0,
        enabled: bool = True,
    ) -> None:
        self.when = when
        self.then = then
        self.threshold = threshold
        self.name = name
        self.weight = weight
        self.enabled = enabled

    async def assess(self, ctx: RiskContext) -> RiskContribution:
        try:
            gate = await self.when.assess(ctx)
        except Exception as exc:  # noqa: BLE001 -- fail open, see class docstring
            return RiskContribution(suspicion=None, detail=f"when-signal raised: {exc!r}")

        if not _signal_flags(gate, self.threshold):
            return RiskContribution(
                suspicion=None, detail=f"when-signal ({self.when.name}) did not flag"
            )

        try:
            return await self.then.assess(ctx)
        except Exception as exc:  # noqa: BLE001 -- fail open, see class docstring
            return RiskContribution(suspicion=None, detail=f"then-signal raised: {exc!r}")


class ReplayRiskSignal:
    """Bridges the existing replay-detection primitives
    (`webapi_captcha.replay_guard`) into a `RiskSignal`, so a detected
    replay contributes to `RiskLevel` alongside IP reputation and
    behavior score, not just as its own separate `VerificationCheck`.

    **Read-only, on purpose -- never calls `store.record()`.**
    `RiskEngine.assess()` (via `AdaptiveCaptchaGate.assess_risk()`) runs
    far more often than a real verification completes -- every
    `PageGuard.require_human()` call, every widget `get_info()` poll --
    so if `assess()` also recorded the fingerprint, a page load that
    never leads to a real solve would "burn" it as seen, poisoning the
    store against a later *legitimate* first-time verification with a
    naturally continuing trajectory shape, and flooding a shared global
    store with harmless everyday-browsing fingerprints. Recording stays
    exclusively `RepeatedMovementCheck.run()`'s job -- wire that in as an
    `extra_check` against the SAME `TrajectoryFingerprintStore` instance,
    or this signal will never have anything to flag. This is not a race
    or a gap: a later, unrelated interaction (a different account/IP/
    token -- exactly the cross-identity replay this module targets)
    whose trajectory hashes to a fingerprint `RepeatedMovementCheck`
    already recorded will correctly show up here as `seen_recently() ==
    True`, and can escalate risk *before* that second interaction ever
    reaches its own `verify()` call.

    `override_level` defaults to `RiskLevel.HIGH` -- comparable
    "outright bad" evidence to `ReputationRiskSignal`'s default, since a
    replay match isn't a noisy heuristic, it's a cryptographic hash
    match against something that has already, factually, been used once.
    Pass `override_level=None` to get a graded `suspicion=1.0`
    contribution instead, with no forced override -- e.g. to wrap this
    signal in `CorroboratedRiskSignal` too, if you want even a detected
    replay to need a second signal's agreement before forcing the top
    tier."""

    def __init__(
        self,
        store: TrajectoryFingerprintStore,
        *,
        override_level: RiskLevel | None = RiskLevel.HIGH,
        name: str = "replay",
        weight: float = 3.0,
        enabled: bool = True,
        grid_px: float = DEFAULT_GRID_PX,
        grid_ms: float = DEFAULT_GRID_MS,
        max_fingerprint_points: int = DEFAULT_MAX_FINGERPRINT_POINTS,
        min_fingerprint_points: int = DEFAULT_MIN_FINGERPRINT_POINTS,
    ) -> None:
        self.store = store
        self.override_level = override_level
        self.name = name
        self.weight = weight
        self.enabled = enabled
        self.grid_px = grid_px
        self.grid_ms = grid_ms
        self.max_fingerprint_points = max_fingerprint_points
        self.min_fingerprint_points = min_fingerprint_points

    async def assess(self, ctx: RiskContext) -> RiskContribution:
        if ctx.signals.get("pointer_type") in ("touch", "pen"):
            return RiskContribution(suspicion=None, detail="touch/pen -- no trajectory to check")
        fingerprint = fingerprint_trajectory(
            ctx.signals.get("mouse_trajectory"),
            grid_px=self.grid_px,
            grid_ms=self.grid_ms,
            max_points=self.max_fingerprint_points,
            min_points=self.min_fingerprint_points,
        )
        if fingerprint is None:
            return RiskContribution(suspicion=None, detail="no usable trajectory")
        if await self.store.seen_recently(fingerprint):
            return RiskContribution(
                suspicion=1.0,
                hard_override=self.override_level,
                detail="this movement pattern was already used for a verification recently",
            )
        return RiskContribution(suspicion=0.0)


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
