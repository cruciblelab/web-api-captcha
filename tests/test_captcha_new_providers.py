"""Exercises the proof-of-work and path-trace providers against their real
verification logic -- a genuine hashcash search for PoW, real geometry for
path-trace, no mocks."""

import hashlib
import json
import math

import pytest

from webapi_captcha.memory import MemoryCaptchaStore
from webapi_captcha.providers.path_trace import PathTraceProvider
from webapi_captcha.providers.proof_of_work import (
    LoadAdaptiveDifficulty,
    ProofOfWorkProvider,
    _leading_zero_bits,
)

# -- proof of work --


def test_leading_zero_bits_counts_correctly() -> None:
    assert _leading_zero_bits(bytes([0x00, 0xFF])) == 8
    assert _leading_zero_bits(bytes([0x0F])) == 4
    assert _leading_zero_bits(bytes([0x00, 0x00, 0x80])) == 16
    assert _leading_zero_bits(bytes([0xFF])) == 0


def _solve_pow(prefix: str, difficulty: int) -> str:
    nonce = 0
    while True:
        digest = hashlib.sha256(f"{prefix}{nonce}".encode()).digest()
        if _leading_zero_bits(digest) >= difficulty:
            return str(nonce)
        nonce += 1


async def test_pow_accepts_a_real_solution() -> None:
    store = MemoryCaptchaStore()
    provider = ProofOfWorkProvider(store, difficulty=8)
    challenge = await provider.issue()

    assert challenge.kind == "pow"
    assert challenge.image_data_uri is None
    assert challenge.params["algorithm"] == "sha256-leading-zero-bits"

    nonce = _solve_pow(challenge.params["prefix"], challenge.params["difficulty"])
    assert await provider.verify(challenge.challenge_id, nonce) is True


async def test_pow_rejects_a_nonce_that_does_not_clear_the_difficulty() -> None:
    store = MemoryCaptchaStore()
    provider = ProofOfWorkProvider(store, difficulty=20)  # a random nonce won't clear this
    challenge = await provider.issue()

    assert await provider.verify(challenge.challenge_id, "0") is False


def test_load_adaptive_difficulty_stays_at_base_under_low_load() -> None:
    adaptive = LoadAdaptiveDifficulty(
        base_difficulty=16, max_difficulty=24, window_seconds=10.0, requests_per_second_at_max=20.0
    )
    assert adaptive() == 16


def test_load_adaptive_difficulty_climbs_towards_max_under_burst_load() -> None:
    adaptive = LoadAdaptiveDifficulty(
        base_difficulty=16, max_difficulty=24, window_seconds=10.0, requests_per_second_at_max=20.0
    )
    difficulties = [adaptive() for _ in range(200)]
    assert difficulties[0] == 16
    assert difficulties[-1] == 24


async def test_pow_provider_accepts_a_difficulty_callable() -> None:
    store = MemoryCaptchaStore()
    provider = ProofOfWorkProvider(store, difficulty=lambda: 8)
    challenge = await provider.issue()

    assert challenge.params["difficulty"] == 8
    nonce = _solve_pow(challenge.params["prefix"], challenge.params["difficulty"])
    assert await provider.verify(challenge.challenge_id, nonce) is True


async def test_pow_solution_is_one_time_use() -> None:
    store = MemoryCaptchaStore()
    provider = ProofOfWorkProvider(store, difficulty=8)
    challenge = await provider.issue()
    nonce = _solve_pow(challenge.params["prefix"], challenge.params["difficulty"])

    assert await provider.verify(challenge.challenge_id, nonce) is True
    assert await provider.verify(challenge.challenge_id, nonce) is False  # replay


def test_pow_rejects_a_zero_difficulty() -> None:
    with pytest.raises(ValueError, match="difficulty"):
        ProofOfWorkProvider(MemoryCaptchaStore(), difficulty=0)


# -- path trace --


def _sample_along(path: list[list[float]], per_segment: int = 6) -> list[list[float]]:
    points: list[list[float]] = []
    for i in range(len(path) - 1):
        ax, ay = path[i]
        bx, by = path[i + 1]
        for k in range(per_segment + 1):
            t = k / per_segment
            points.append([ax + (bx - ax) * t, ay + (by - ay) * t])
    return points


async def test_path_trace_accepts_a_faithful_trace() -> None:
    store = MemoryCaptchaStore()
    provider = PathTraceProvider(store)
    challenge = await provider.issue()

    assert challenge.kind == "path-trace"
    trace = json.dumps(_sample_along(challenge.params["path"]))
    assert await provider.verify(challenge.challenge_id, trace) is True


async def test_path_trace_rejects_a_line_far_from_the_path() -> None:
    store = MemoryCaptchaStore()
    provider = PathTraceProvider(store)
    challenge = await provider.issue()

    straight = json.dumps([[20, 5], [300, 5]])  # nowhere near the wavy line
    assert await provider.verify(challenge.challenge_id, straight) is False


async def test_path_trace_rejects_tracing_only_part_of_the_line() -> None:
    store = MemoryCaptchaStore()
    provider = PathTraceProvider(store)
    challenge = await provider.issue()
    path = challenge.params["path"]

    half = json.dumps(_sample_along(path[: len(path) // 2]))
    assert await provider.verify(challenge.challenge_id, half) is False


async def test_path_trace_handles_malformed_input_without_crashing() -> None:
    store = MemoryCaptchaStore()
    provider = PathTraceProvider(store)
    challenge = await provider.issue()

    assert await provider.verify(challenge.challenge_id, "not json") is False


async def test_path_trace_is_one_time_use() -> None:
    store = MemoryCaptchaStore()
    provider = PathTraceProvider(store)
    challenge = await provider.issue()
    trace = json.dumps(_sample_along(challenge.params["path"]))

    assert await provider.verify(challenge.challenge_id, trace) is True
    assert await provider.verify(challenge.challenge_id, trace) is False


async def test_path_trace_rejects_a_straight_shortcut_across_many_issues() -> None:
    # Regression check for a real bug: with only "every sample within
    # `tolerance` of the polyline" + "every vertex has a nearby sample", a
    # dead-straight diagonal between the endpoints passes both whenever the
    # issued wave's bulge from its own chord happens to be <= tolerance --
    # which a purely random sine hit for a real fraction of issues (~4-5%
    # of them landed a bulge below the 24px default tolerance). The first
    # fix attempt added a "did the trace bulge enough" check that was dead
    # code (vertex-coverage already implies it), so it did nothing for the
    # small-bulge case; the real fix guarantees _make_path bulges >
    # tolerance. Loop many issues so a lucky flat wave can't hide the bug.
    store = MemoryCaptchaStore()
    provider = PathTraceProvider(store)
    for _ in range(200):
        challenge = await provider.issue()
        path = challenge.params["path"]
        start, end = path[0], path[-1]
        straight_chord = json.dumps(_sample_along([start, end], per_segment=20))
        assert await provider.verify(challenge.challenge_id, straight_chord) is False


async def test_path_trace_issued_wave_always_bulges_past_tolerance() -> None:
    # The generation-side guarantee the straight-shortcut rejection relies
    # on: no matter what the random sine does, the issued wave strays from
    # its own start->end chord by more than `tolerance`.
    from webapi_captcha.providers.path_trace import _chord_bulge

    store = MemoryCaptchaStore()
    provider = PathTraceProvider(store)
    for _ in range(200):
        challenge = await provider.issue()
        assert _chord_bulge(challenge.params["path"]) > provider.tolerance


async def test_path_trace_rejects_an_oversized_payload() -> None:
    store = MemoryCaptchaStore()
    provider = PathTraceProvider(store)
    challenge = await provider.issue()

    huge = "[" + ",".join("[0,0]" for _ in range(60_000)) + "]"  # > 200k chars
    assert await provider.verify(challenge.challenge_id, huge) is False


# -- kinematics: suspiciously-constant speed/timing demands tighter tolerance --


def _resample_equal_arc_length(path: list[list[float]], n: int) -> list[list[float]]:
    """Points spaced at equal ARC-LENGTH intervals along the polyline --
    unlike `_sample_along` (equal per-*segment* subdivisions, which can
    still bunch up on short segments and spread out on long ones), this
    gives genuinely uniform per-step distance, a prerequisite for
    constructing a synthetic "constant speed" trace."""
    segment_lengths = [
        math.hypot(path[i + 1][0] - path[i][0], path[i + 1][1] - path[i][1])
        for i in range(len(path) - 1)
    ]
    total = sum(segment_lengths)
    points = []
    for k in range(n):
        target = total * k / (n - 1)
        covered = 0.0
        for i, seg_len in enumerate(segment_lengths):
            if covered + seg_len >= target or i == len(segment_lengths) - 1:
                t = 0.0 if seg_len == 0 else (target - covered) / seg_len
                ax, ay = path[i]
                bx, by = path[i + 1]
                points.append([ax + (bx - ax) * t, ay + (by - ay) * t])
                break
            covered += seg_len
    return points


def _offset_perpendicular_ish(points: list[list[float]], offset: float) -> list[list[float]]:
    """Nudges every point by a constant amount in y -- enough to be off
    the true line by `offset` px without changing the path's shape, so
    the resulting trace is uniformly imprecise rather than off in a way
    that would fail vertex-coverage outright."""
    return [[x, y + offset] for x, y in points]


def _with_constant_velocity_and_timing(points: list[list[float]], dt_ms: float) -> str:
    """A trace with a fixed time step between equally-arc-length-spaced
    points -- constant distance-per-sample AND constant time-per-sample,
    i.e. exactly the "mathematically steady speed, perfectly even
    timing" signature `_looks_suspiciously_uniform` is built to catch."""
    return json.dumps([[x, y, i * dt_ms] for i, (x, y) in enumerate(points)])


def _with_natural_jitter_timing(points: list[list[float]], dt_ms: float) -> str:
    """Same spatial points, but with human-like irregular timing (jitter
    on each interval) -- should NOT trigger the "too uniform" escalation,
    so the same geometric imprecision that a too-perfect trace gets
    rejected for should still pass here."""
    t = 0.0
    out = []
    for i, (x, y) in enumerate(points):
        out.append([x, y, t])
        # Alternate a bit fast, a bit slow -- never a fixed interval twice
        # in a row, which is all it takes to clear the CV threshold.
        t += dt_ms * (1.6 if i % 2 == 0 else 0.5)
    return json.dumps(out)


async def test_path_trace_demands_tighter_tolerance_when_motion_looks_too_uniform() -> None:
    store = MemoryCaptchaStore()
    provider = PathTraceProvider(store)
    challenge = await provider.issue()
    path = challenge.params["path"]
    tolerance = challenge.params["tolerance"]

    # Offset comfortably inside the FULL tolerance but past HALF of it --
    # a trace here should pass under normal geometry, but the halved
    # tolerance a "too perfect" trace gets held to should reject it.
    offset = tolerance * 0.7
    points = _offset_perpendicular_ish(_resample_equal_arc_length(path, 30), offset)

    too_perfect = _with_constant_velocity_and_timing(points, dt_ms=16.0)
    assert await provider.verify(challenge.challenge_id, too_perfect) is False


async def test_path_trace_same_imprecision_passes_with_natural_timing() -> None:
    store = MemoryCaptchaStore()
    provider = PathTraceProvider(store)
    challenge = await provider.issue()
    path = challenge.params["path"]
    tolerance = challenge.params["tolerance"]

    offset = tolerance * 0.7
    points = _offset_perpendicular_ish(_resample_equal_arc_length(path, 30), offset)

    natural = _with_natural_jitter_timing(points, dt_ms=16.0)
    assert await provider.verify(challenge.challenge_id, natural) is True


async def test_path_trace_accepts_uniform_motion_when_it_is_also_precise() -> None:
    # Being "too perfect" only demands tighter geometry, it doesn't
    # reject outright -- a trace that's suspiciously uniform in speed and
    # timing but ALSO stays within the tighter (halved) tolerance still
    # passes, e.g. a very steady hand, a stylus, or an assistive device.
    store = MemoryCaptchaStore()
    provider = PathTraceProvider(store)
    challenge = await provider.issue()
    path = challenge.params["path"]

    points = _resample_equal_arc_length(path, 30)  # right on the line, no offset at all
    too_perfect_but_precise = _with_constant_velocity_and_timing(points, dt_ms=16.0)
    assert await provider.verify(challenge.challenge_id, too_perfect_but_precise) is True


def test_looks_suspiciously_uniform_abstains_without_enough_timed_samples() -> None:
    from webapi_captcha.providers.path_trace import _looks_suspiciously_uniform

    assert _looks_suspiciously_uniform([(0.0, 0.0, 0.0), (1.0, 1.0, 16.0)]) is False
