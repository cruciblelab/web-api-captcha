"""Behavioral risk scoring -- the "score board" for the invisible layer.

The idea you described: don't just ask a yes/no question, watch *how* the
interaction happened and build a score out of many weak signals. A human
moving a mouse toward the widget leaves a trail; a human tap never lands on
the mathematical dead-center of a button; a real browser reports a
language and a timezone. None of these alone means anything -- together
they're a soft signal.

`SignalScoreCheck` runs a set of weighted heuristics over the
client-submitted `signals` bag and passes if the weighted average clears a
threshold. It ships with a sensible default set, but every heuristic and
weight is yours to change -- add your own, drop ours, reweight (the same
"use ours, mix, bring your own" philosophy as the checks themselves).

**Read this before you rely on it.** Every input here is submitted by the
client's JavaScript, which the client controls and can forge. This is a
*transparent heuristic* score, not a bot detector and not machine
learning: a determined bot that knows these rules can send signals that
score as human. Its honest value is raising the cost of *low-effort*
automation and giving you a tunable knob -- it is meant to run *alongside*
proof-of-work (real, unspoofable cost) and account binding (real
identity), never as the only gate. Anyone selling you a server-side
"is-a-human" verdict from client-submitted signals is overselling it; this
module is deliberately honest about being a speed bump.

What the client should collect and put in `signals` (all optional -- a
missing signal just abstains or counts against, per heuristic):

- `webdriver` (bool): `navigator.webdriver`.
- `language` (str): `navigator.language`.
- `timezone` (str): `Intl.DateTimeFormat().resolvedOptions().timeZone`.
- `pointer_type` ("mouse"|"touch"|"pen"): from the PointerEvent.
- `pointer_moves` (int): how many pointer-move samples were seen *before*
  the click/tap -- start collecting when the pointer approaches the
  widget, not when it's clicked, so a click with zero prior movement (a
  scripted synthetic click) stands out.
- `click_offset` (number): pixels between the tap/click and the exact
  center of the target -- a dead-center (offset ~0) hit is suspiciously
  precise for a human finger/mouse.
- `interaction_ms` (number): time from the widget appearing to submit.
- `mouse_trajectory` (list of `[x, y, t_ms]`): raw pointer-move samples
  captured from the moment the pointer approaches the widget (same
  "start before the click" rule as `pointer_moves` -- collect on
  `pointermove`, not just at the final click). `t_ms` should be a
  monotonic clock (`performance.now()`), not wall-clock time. Feeds the
  three kinematics heuristics below; omit it (or send it on touch/pen,
  where it's ignored) and those heuristics simply abstain.

**On the mouse-kinematics heuristics specifically.** The underlying
science is real: human reaching movements follow a well-established
bell-shaped velocity profile (the minimum-jerk model of human motor
control -- Flash & Hogan, 1985) with natural path curvature and irregular
sampling, while naive automation (constant-speed linear interpolation at
fixed time steps, the overwhelmingly common pattern in scripted
browser-automation) produces a suspiciously straight path, a flat
velocity profile, and perfectly even timing. A synthetic comparison of a
minimum-jerk trajectory against a linear-interpolation one shows clean
separation on all three statistics used below (path curvature, velocity
variance, timing variance) with no overlap in a 20-trial sample.

That said: **this cannot be turned into a "near-impossible to mistake a
human for a bot" guarantee, and the reason is structural, not a matter of
tuning better thresholds.** A bot can *replay* a real, previously recorded
human mouse trajectory (its operator's own, or one scraped/purchased
elsewhere) instead of synthesizing one from scratch. A replayed genuine
human trajectory passes every check in this file perfectly, because it
*is* one -- no analysis of a single submitted sample can distinguish "a
human moved the mouse just now" from "a recording of a human moving the
mouse is being replayed right now." Purpose-built "human-like" mouse-path
generators (Bezier-curve-plus-jitter tools) already circulate specifically
to defeat this class of check, for anyone who doesn't want to bother with
replay. So: yes, worth adding -- it meaningfully raises the cost of
*naive*, unmodified automation, which is most of what actually shows up --
but it stays in the same honest bucket as everything else here, layered
under proof-of-work (real cost) and account binding (real identity), never
sold as a standalone "is-a-human" verdict.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from webapi_captcha.checks import CheckOutcome, VerificationContext

# A heuristic returns a human-likeness score in [0, 1] (1 = looks human,
# 0 = looks like a bot), or None to *abstain* (the signal it needs isn't
# present or doesn't apply -- e.g. mouse-movement on a touch device).
HeuristicFn = Callable[[dict[str, Any]], float | None]


@dataclass
class ScoringHeuristic:
    name: str
    weight: float
    score: HeuristicFn


def _webdriver_absent(signals: dict[str, Any]) -> float:
    return 0.0 if signals.get("webdriver") is True else 1.0


def _has_language(signals: dict[str, Any]) -> float:
    return 1.0 if isinstance(signals.get("language"), str) and signals["language"] else 0.0


def _has_timezone(signals: dict[str, Any]) -> float:
    return 1.0 if isinstance(signals.get("timezone"), str) and signals["timezone"] else 0.0


def _pointer_movement(signals: dict[str, Any]) -> float | None:
    # On touch/pen there's no "approach" movement to expect -- abstain
    # rather than punish a legitimate mobile tap.
    if signals.get("pointer_type") in ("touch", "pen"):
        return None
    moves = signals.get("pointer_moves")
    if not isinstance(moves, int | float):
        return 0.0  # a mouse interaction that reported no movement at all
    return 1.0 if moves >= 3 else 0.0


def _click_not_dead_center(signals: dict[str, Any]) -> float | None:
    offset = signals.get("click_offset")
    if not isinstance(offset, int | float):
        return None
    # A real finger/mouse never lands on the exact mathematical center; an
    # offset under ~2px is more precise than a human, i.e. bot-like.
    return 1.0 if offset >= 2 else 0.0


def _plausible_interaction_time(signals: dict[str, Any]) -> float:
    value = signals.get("interaction_ms")
    if not isinstance(value, int | float):
        return 0.0  # a submit with no reported interaction time is suspicious
    return 1.0 if value >= 400 else 0.0


# -- Mouse kinematics -------------------------------------------------
#
# Tuned against a minimum-jerk-model human simulation vs. a naive
# constant-speed/constant-interval bot simulation (20 trials each): the
# human trials landed at curvature ratio 1.011-1.051, velocity CV
# 0.591-0.658, timing CV 0.071-0.099; the naive-bot trials landed at
# exactly 1.000/0.000/0.000 on all three. The _SPAN constants below are
# set well inside the human range (not at its edge) precisely so that a
# human sample noisier or sparser than the simulation doesn't get
# unfairly zeroed out -- these are soft, graded scores, not hard cutoffs.
_MIN_TRAJECTORY_POINTS = 5
_MAX_TRAJECTORY_POINTS = 2000  # ignore anything past this rather than pay to process it
_MIN_SEGMENTS = 4
_MIN_STRAIGHT_LINE_PX = 20.0  # too short a move for "path shape" to mean anything
_CURVATURE_SPAN = 0.02
_VELOCITY_CV_SPAN = 0.15
_TIMING_CV_SPAN = 0.03


def _parse_trajectory(signals: dict[str, Any]) -> list[tuple[float, float, float]] | None:
    """Shared parsing for the kinematics heuristics below. `None` means
    abstain: no `mouse_trajectory` reported (an older/simpler frontend, or
    this heuristic set simply isn't wired up yet), a touch/pen pointer
    (no continuous mouse path to speak of), too few samples for a
    variance statistic to mean anything, or malformed data -- all treated
    the same as "nothing to go on" rather than counted against the user,
    since this is an optional, best-effort signal."""
    if signals.get("pointer_type") in ("touch", "pen"):
        return None
    raw = signals.get("mouse_trajectory")
    if not isinstance(raw, list) or len(raw) < _MIN_TRAJECTORY_POINTS:
        return None
    points: list[tuple[float, float, float]] = []
    for sample in raw[:_MAX_TRAJECTORY_POINTS]:
        if not isinstance(sample, list | tuple) or len(sample) != 3:
            return None
        try:
            x, y, t = float(sample[0]), float(sample[1]), float(sample[2])
        except (TypeError, ValueError):
            return None
        if not (math.isfinite(x) and math.isfinite(y) and math.isfinite(t)):
            # `float()` (and `json.loads`, by default) happily accepts
            # NaN/Infinity -- without this check, a single smuggled NaN
            # coordinate silently corrupted every downstream heuristic
            # instead of triggering the malformed-data abstain path
            # above: Python's own `min`/`max` treat a NaN comparison as
            # always False, so `max(0.0, min(1.0, nan))` evaluates to
            # `1.0` (the first argument wins when `<` is False) -- a
            # degenerate trajectory scored as confidently human by the
            # two heaviest-weighted heuristics in
            # `default_behavior_heuristics()` instead of being rejected.
            return None
        points.append((x, y, t))
    return points


def _segment_velocities(points: list[tuple[float, float, float]]) -> list[float]:
    velocities = []
    for (x0, y0, t0), (x1, y1, t1) in zip(points, points[1:], strict=False):
        dt = t1 - t0
        if dt > 0:
            velocities.append(math.hypot(x1 - x0, y1 - y0) / dt)
    return velocities


def _coefficient_of_variation(values: list[float]) -> float | None:
    if len(values) < _MIN_SEGMENTS:
        return None
    mean = sum(values) / len(values)
    if mean == 0:
        return None
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    cv = math.sqrt(variance) / mean
    # Defense in depth alongside `_parse_trajectory`'s isfinite check --
    # a non-finite result here must abstain, never silently score as
    # "maximally human" the way an un-guarded `min(1.0, nan)` would (see
    # `_parse_trajectory`'s comment for why that specific expression is
    # the actual bug mechanism).
    return cv if math.isfinite(cv) else None


def _mouse_path_curvature(signals: dict[str, Any]) -> float | None:
    """Human reaches rarely travel in a mathematically straight line; a
    linear-interpolation bot's path is exactly straight. Scores the ratio
    of actual path length to straight-line start->end distance, scaled so
    a dead-straight path (ratio 1.0, the bot signature) is 0 and a ratio
    at or beyond `_CURVATURE_SPAN` above straight is a full 1."""
    points = _parse_trajectory(signals)
    if points is None:
        return None
    (x0, y0, _), (x1, y1, _) = points[0], points[-1]
    straight = math.hypot(x1 - x0, y1 - y0)
    if straight < _MIN_STRAIGHT_LINE_PX:
        return None
    path_length = sum(
        math.hypot(b[0] - a[0], b[1] - a[1]) for a, b in zip(points, points[1:], strict=False)
    )
    ratio = path_length / straight
    return max(0.0, min(1.0, (ratio - 1.0) / _CURVATURE_SPAN))


def _mouse_velocity_variance(signals: dict[str, Any]) -> float | None:
    """Human movement follows a bell-shaped velocity profile (slow-fast-slow,
    the minimum-jerk model) -- lots of speed variance across the path. A
    linear-interpolation bot moves at one constant speed -- zero variance.
    Scores the velocity coefficient of variation, scaled the same way as
    the curvature heuristic above."""
    points = _parse_trajectory(signals)
    if points is None:
        return None
    cv = _coefficient_of_variation(_segment_velocities(points))
    if cv is None:
        return None
    return max(0.0, min(1.0, cv / _VELOCITY_CV_SPAN))


def _mouse_timing_variance(signals: dict[str, Any]) -> float | None:
    """A real browser's pointer-move sampling (tied to the display's
    refresh/event loop) is never perfectly even; a bot that steps through
    fixed time increments is. Scores the coefficient of variation of the
    inter-sample intervals. The weakest of the three kinematics heuristics
    -- trivial for a bot to defeat by adding a little timing jitter -- so
    it carries the lowest weight of the three by default."""
    points = _parse_trajectory(signals)
    if points is None:
        return None
    dts = [t1 - t0 for (_, _, t0), (_, _, t1) in zip(points, points[1:], strict=False) if t1 > t0]
    cv = _coefficient_of_variation(dts)
    if cv is None:
        return None
    return max(0.0, min(1.0, cv / _TIMING_CV_SPAN))


_HOMING_NOISE_FLOOR = 1.0  # px -- ignore float/sampling noise, only count a real step back


def _mouse_homing_correction(signals: dict[str, Any]) -> float | None:
    """Looks for at least one "overshoot and correct" moment: the distance
    to the final (click) point briefly *increasing* before it keeps
    shrinking -- a signature of ballistic human reaching. Tested against a
    hand-built minimum-jerk trajectory that never overshoots (a real,
    common human pattern for slow/precise movements) and it abstains
    rather than penalizing, on purpose: overshoot is bonus evidence when
    present, but its *absence* proves nothing (plenty of genuine human
    movement never overshoots), so this can only ever help a score, never
    hurt one. Weighted low by default precisely because it's a weaker,
    situational signal, not because it's unreliable when it does fire."""
    points = _parse_trajectory(signals)
    if points is None:
        return None
    tx, ty, _ = points[-1]
    if math.hypot(points[0][0] - tx, points[0][1] - ty) < _MIN_STRAIGHT_LINE_PX:
        return None
    distances = [math.hypot(x - tx, y - ty) for x, y, _ in points]
    overshoots = sum(
        1 for a, b in zip(distances, distances[1:], strict=False) if b > a + _HOMING_NOISE_FLOOR
    )
    return 1.0 if overshoots > 0 else None


def default_behavior_heuristics() -> list[ScoringHeuristic]:
    """The built-in heuristic set. Copy and edit it (drop entries,
    reweight, append your own `ScoringHeuristic`) to tune the score to your
    own tolerance -- e.g. weight `webdriver` higher, or add a heuristic
    reading your own custom signal."""
    return [
        ScoringHeuristic("webdriver-absent", 3.0, _webdriver_absent),
        ScoringHeuristic("pointer-movement", 2.0, _pointer_movement),
        ScoringHeuristic("click-not-dead-center", 2.0, _click_not_dead_center),
        ScoringHeuristic("has-language", 1.0, _has_language),
        ScoringHeuristic("has-timezone", 1.0, _has_timezone),
        ScoringHeuristic("interaction-time", 1.5, _plausible_interaction_time),
        ScoringHeuristic("mouse-curvature", 2.0, _mouse_path_curvature),
        ScoringHeuristic("mouse-velocity-variance", 2.5, _mouse_velocity_variance),
        ScoringHeuristic("mouse-timing-variance", 1.0, _mouse_timing_variance),
        ScoringHeuristic("mouse-homing-correction", 1.0, _mouse_homing_correction),
    ]


class SignalScoreCheck:
    """`VerificationCheck` that scores the client's `signals` with a set of
    weighted heuristics and passes if the weighted average is at least
    `threshold`. Heuristics that abstain (return `None`) are left out of
    the average, so a touch device isn't penalized for having no mouse
    trail. The computed score and per-heuristic breakdown go into the
    outcome's `detail` for transparency/logging."""

    name = "behavior-score"

    def __init__(
        self,
        *,
        threshold: float = 0.6,
        heuristics: list[ScoringHeuristic] | None = None,
    ) -> None:
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("threshold must be between 0 and 1")
        self.threshold = threshold
        self.heuristics = heuristics if heuristics is not None else default_behavior_heuristics()

    def compute(self, signals: dict[str, Any]) -> tuple[float, dict[str, float]]:
        """Returns `(score, breakdown)` without deciding pass/fail -- handy
        for logging or tuning your threshold against real traffic. `score`
        is 1.0 (nothing to go on -> benefit of the doubt) when every
        heuristic abstains."""
        breakdown: dict[str, float] = {}
        weighted_sum = 0.0
        total_weight = 0.0
        for heuristic in self.heuristics:
            value = heuristic.score(signals)
            if value is None:
                continue
            breakdown[heuristic.name] = value
            weighted_sum += value * heuristic.weight
            total_weight += heuristic.weight
        score = 1.0 if total_weight == 0 else weighted_sum / total_weight
        return score, breakdown

    async def run(self, ctx: VerificationContext) -> CheckOutcome:
        score, breakdown = self.compute(ctx.signals)
        passed = score >= self.threshold
        parts = ", ".join(f"{name}={value:.2f}" for name, value in breakdown.items())
        detail = f"score={score:.2f} (threshold {self.threshold:.2f}) [{parts}]"
        return CheckOutcome(passed, detail)
