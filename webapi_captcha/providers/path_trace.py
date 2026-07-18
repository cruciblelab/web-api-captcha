"""Path-trace captcha -- draw a thick line and ask the user to trace it
with a mouse or a finger. The frontend renders the line from the point
list in `params`, captures the pointer path, and posts it back; the server
checks the traced points stay within tolerance of the line and cover it
end to end.

Threat model, honestly: this is an *interaction* challenge, harder to
automate than reading a static distorted image (which modern OCR/vision
models solve trivially) because a bot has to synthesize a plausible
pointer path. It is **not** a cryptographic guarantee -- the line itself
is delivered to the client so it can be drawn, which means a determined
script can read it and submit a matching trace. Treat it as UX-level
friction and layer it with proof-of-work (cost) and account binding
(identity); don't rely on it alone. Needs no extra dependency (stdlib
`math`/`json`).
"""

from __future__ import annotations

import json
import math
import random
import secrets
from datetime import UTC, datetime, timedelta

from webapi_captcha._shared import check_pending_challenge
from webapi_captcha.base import CaptchaStore
from webapi_captcha.models import CaptchaChallenge, PendingCaptcha

_WIDTH = 320
_HEIGHT = 160
_MAX_TRACE_POINTS = 5000  # reject an implausibly huge payload rather than chew on it
# A hard cap on the raw string BEFORE json.loads, so a multi-megabyte body
# can't force us to parse it just to then reject it on point count. 5000
# points of "[123.4,56.7]," is well under this.
_MAX_RESPONSE_CHARS = 200_000


def _dist_point_to_segment(
    p: tuple[float, float], a: tuple[float, float], b: tuple[float, float]
) -> float:
    ax, ay = a
    bx, by = b
    px, py = p
    dx, dy = bx - ax, by - ay
    if dx == 0 and dy == 0:
        return math.hypot(px - ax, py - ay)
    t = ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)
    t = max(0.0, min(1.0, t))
    cx, cy = ax + t * dx, ay + t * dy
    return math.hypot(px - cx, py - cy)


def _dist_point_to_polyline(p: tuple[float, float], polyline: list[tuple[float, float]]) -> float:
    return min(
        _dist_point_to_segment(p, polyline[i], polyline[i + 1])
        for i in range(len(polyline) - 1)
    )


def _chord_bulge(path: list[list[float]]) -> float:
    """How far the wave's vertices stray from the straight line between its
    own start and end points -- i.e. how much "curve" there is to trace. A
    dead-straight diagonal has a bulge of ~0."""
    start = (path[0][0], path[0][1])
    end = (path[-1][0], path[-1][1])
    return max(_dist_point_to_segment((x, y), start, end) for x, y in path)


_MIN_KINEMATIC_SAMPLES = 6
# Below this coefficient-of-variation, speed/timing reads as "too
# constant to be a hand" -- see `_looks_suspiciously_uniform`'s docstring
# for the reasoning and honest limits.
_SUSPICIOUS_VELOCITY_CV = 0.05
_SUSPICIOUS_TIMING_CV = 0.05


def _coefficient_of_variation(values: list[float]) -> float | None:
    if len(values) < 3:
        return None
    mean = sum(values) / len(values)
    if mean == 0:
        return None
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(variance) / mean


def _looks_suspiciously_uniform(trace: list[tuple[float, float, float]]) -> bool:
    """Geometry alone (staying near the line, covering every vertex) says
    nothing about *how* the trace was produced -- a script that knows the
    path can hit those same points with mathematically constant speed and
    perfectly even timing, something a real hand essentially never does
    (the same minimum-jerk-vs-linear-interpolation distinction
    `captcha/scoring.py`'s mouse-kinematics heuristics are built on,
    applied here to a dragged trace instead of a reach-then-click).
    Returns `True` only when there are enough timestamped samples *and*
    both the segment-velocity and inter-sample-timing coefficients of
    variation are near zero -- i.e. suspiciously constant on both axes at
    once, not just one (a slow, very deliberate but still human trace can
    legitimately have low variance on one axis).

    Honest limit, same as `scoring.py`'s: this is a soft heuristic, not a
    detector. It flags naive constant-speed synthesis; it cannot catch a
    literal replay of a previously recorded genuine human trace (that
    recording *is* a real trace, timestamps and all) -- see this module's
    top-level docstring on why the line being visible to the client caps
    what any client-side interaction challenge can prove."""
    if len(trace) < _MIN_KINEMATIC_SAMPLES:
        return False
    velocities: list[float] = []
    intervals: list[float] = []
    for (x0, y0, t0), (x1, y1, t1) in zip(trace, trace[1:], strict=False):
        dt = t1 - t0
        if dt <= 0:
            continue
        velocities.append(math.hypot(x1 - x0, y1 - y0) / dt)
        intervals.append(dt)
    velocity_cv = _coefficient_of_variation(velocities)
    timing_cv = _coefficient_of_variation(intervals)
    if velocity_cv is None or timing_cv is None:
        return False
    return velocity_cv < _SUSPICIOUS_VELOCITY_CV and timing_cv < _SUSPICIOUS_TIMING_CV


class PathTraceProvider:
    """`CaptchaProvider` that issues a wavy line and passes if the pointer
    trace (a) never strays further than `tolerance` from the line and (b)
    passes within `tolerance` of every vertex (so the user traced the whole
    line, not just a piece).

    For (a)+(b) to actually force *tracing the curve* rather than cutting a
    straight diagonal between the endpoints, the issued wave has to bulge
    away from its own start->end chord by comfortably more than `tolerance`
    -- otherwise a dead-straight trace stays within `tolerance` of every
    vertex and passes both checks without following the wave at all. A
    purely random sine can land as flat as ~17px of bulge for the 24px
    default tolerance, so `_make_path` regenerates until the bulge clears
    `tolerance * 1.5`; with that guarantee, the peak vertices sit far
    enough from the chord that check (b) inherently rejects a straight
    shortcut.

    (a)/(b) alone say nothing about *how* the trace was drawn -- a script
    that knows the path can hit the same points with mathematically
    constant speed and perfectly even timing, which a real hand
    essentially never does. When the bundled widget's timestamped samples
    show that (`_looks_suspiciously_uniform`), `tolerance` is halved for
    (a)/(b) rather than rejecting on kinematics alone -- a genuinely very
    steady trace that's *also* that geometrically precise still passes; a
    script that nailed constant speed/timing but wasn't pixel-perfect on
    the curve itself gets caught. Same honest limit as everywhere else in
    this package: a soft heuristic, not a detector, and it cannot catch a
    literal replay of a real recorded human trace."""

    kind = "path-trace"

    def __init__(
        self,
        store: CaptchaStore,
        *,
        tolerance: float = 24.0,
        vertices: int = 6,
        ttl: timedelta = timedelta(minutes=10),
        max_attempts: int = 5,
    ) -> None:
        self.store = store
        self.tolerance = tolerance
        self.vertices = max(3, vertices)
        self.ttl = ttl
        self.max_attempts = max_attempts

    def _random_wave(self) -> list[list[float]]:
        # A smooth-ish sine curve across the width, randomized per issue so
        # the same-looking line isn't served twice.
        phase = random.uniform(0, 2 * math.pi)
        amplitude = random.uniform(30, 50)
        mid = _HEIGHT / 2
        left, right = 20.0, _WIDTH - 20.0
        path: list[list[float]] = []
        for i in range(self.vertices):
            frac = i / (self.vertices - 1)
            x = left + frac * (right - left)
            y = mid + amplitude * math.sin(phase + frac * math.pi * 1.5)
            path.append([round(x, 1), round(y, 1)])
        return path

    def _make_path(self) -> list[list[float]]:
        # Regenerate until the wave bulges away from its own start->end chord
        # by comfortably more than `tolerance` (see the class docstring for
        # why a flat wave lets a straight shortcut pass). A random wave
        # clears this most of the time, so the loop almost always returns on
        # the first try; 50 is astronomically more than enough headroom.
        min_bulge = self.tolerance * 1.5
        path = self._random_wave()
        for _ in range(50):
            if _chord_bulge(path) >= min_bulge:
                break
            path = self._random_wave()
        return path

    async def issue(self) -> CaptchaChallenge:
        path = self._make_path()
        challenge_id = secrets.token_urlsafe(16)
        now = datetime.now(UTC)
        await self.store.create(
            PendingCaptcha(
                challenge_id=challenge_id,
                kind=self.kind,
                answer=json.dumps({"path": path, "tolerance": self.tolerance}),
                created_at=now,
                expires_at=now + self.ttl,
            )
        )
        return CaptchaChallenge(
            challenge_id=challenge_id,
            kind=self.kind,
            prompt="Trace the line from start to end with your mouse or finger.",
            params={
                "path": path,
                "tolerance": self.tolerance,
                "line_width": 20,
                "width": _WIDTH,
                "height": _HEIGHT,
            },
            expires_at=now + self.ttl,
        )

    async def verify(self, challenge_id: str, response: str) -> bool:
        """`response` is a JSON array of pointer samples, each `[x, y]` or
        `[x, y, t_ms]` (the bundled widget always sends the timestamped
        form; a 2-element sample just skips the kinematics check below,
        same "abstain on missing optional data" policy as `scoring.py`)."""

        def _verifier(pending: PendingCaptcha) -> bool:
            if len(response) > _MAX_RESPONSE_CHARS:
                return False
            try:
                trace_raw = json.loads(response)
            except (TypeError, ValueError):
                return False
            if not isinstance(trace_raw, list) or not (2 <= len(trace_raw) <= _MAX_TRACE_POINTS):
                return False
            try:
                trace = [(float(pt[0]), float(pt[1])) for pt in trace_raw]
            except (TypeError, ValueError, IndexError):
                return False
            timed_trace: list[tuple[float, float, float]] | None = None
            try:
                if all(isinstance(pt, list | tuple) and len(pt) >= 3 for pt in trace_raw):
                    timed_trace = [(float(pt[0]), float(pt[1]), float(pt[2])) for pt in trace_raw]
            except (TypeError, ValueError):
                timed_trace = None

            spec = json.loads(pending.answer)
            tolerance = spec["tolerance"]
            path = [(float(x), float(y)) for x, y in spec["path"]]

            # (a) no wild excursions: every sample is near the line
            # (b) full coverage: every vertex has a nearby sample. Because
            # the issued wave is guaranteed to bulge > tolerance from its
            # own chord (see _make_path), covering every vertex here is
            # exactly what a dead-straight shortcut cannot do -- its nearest
            # point to the peak vertices sits a full bulge (> tolerance)
            # away. So (a)+(b) together already force tracing the curve; no
            # separate "did it bulge enough" check is needed (and an earlier
            # attempt at one was dead code -- (b) passing already implies it).
            #
            # The tolerance used for both is normally `tolerance`, but
            # halved when the motion that produced the trace looks
            # suspiciously machine-uniform (see _looks_suspiciously_
            # uniform) -- not an outright rejection on kinematics alone
            # (a soft heuristic shouldn't hard-fail by itself), but a
            # demand for tighter geometric proof before trusting it: a
            # genuinely careful, very steady hand that's *also* that
            # precise on the actual line still passes; a script that
            # nailed constant speed/timing but wasn't pixel-perfect on the
            # curve itself gets caught here.
            effective_tolerance = tolerance
            if timed_trace is not None and _looks_suspiciously_uniform(timed_trace):
                effective_tolerance = tolerance / 2

            if any(_dist_point_to_polyline(pt, path) > effective_tolerance for pt in trace):
                return False
            for vertex in path:
                if (
                    min(math.hypot(vertex[0] - t[0], vertex[1] - t[1]) for t in trace)
                    > effective_tolerance
                ):
                    return False
            return True

        return await check_pending_challenge(
            self.store, challenge_id, max_attempts=self.max_attempts, verifier=_verifier
        )
