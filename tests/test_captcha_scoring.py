"""Exercises the behavioral SignalScoreCheck -- the transparent weighted
heuristic score over client-submitted signals."""

import math
from datetime import UTC, datetime, timedelta

import pytest

from webapi_captcha.checks import VerificationContext
from webapi_captcha.models import VerificationRequest
from webapi_captcha.scoring import ScoringHeuristic, SignalScoreCheck


def _ctx(signals: dict) -> VerificationContext:
    now = datetime.now(UTC)
    request = VerificationRequest(
        token="t1",
        user_id=100,
        purpose="test",
        created_at=now,
        expires_at=now + timedelta(minutes=10),
    )
    return VerificationContext(request=request, signals=signals)


_HUMAN = {
    "webdriver": False,
    "language": "tr-TR",
    "timezone": "Europe/Istanbul",
    "pointer_type": "mouse",
    "pointer_moves": 25,
    "click_offset": 7,
    "interaction_ms": 1500,
}
_BOT = {
    "webdriver": True,
    "pointer_type": "mouse",
    "pointer_moves": 0,
    "click_offset": 0,
    "interaction_ms": 2,
}


async def test_human_like_signals_pass() -> None:
    outcome = await SignalScoreCheck(threshold=0.6).run(_ctx(_HUMAN))

    assert outcome.passed is True
    assert "score=1.00" in (outcome.detail or "")


async def test_bot_like_signals_fail() -> None:
    outcome = await SignalScoreCheck(threshold=0.6).run(_ctx(_BOT))

    assert outcome.passed is False
    assert "score=0.00" in (outcome.detail or "")


async def test_mobile_touch_is_not_penalized_for_lacking_a_mouse_trail() -> None:
    """On a touch device there's no mouse-approach to expect, so the
    pointer-movement heuristic abstains instead of failing the tap."""
    mobile = {
        "webdriver": False,
        "language": "en-US",
        "timezone": "America/New_York",
        "pointer_type": "touch",
        "click_offset": 12,
        "interaction_ms": 900,
    }

    outcome = await SignalScoreCheck(threshold=0.6).run(_ctx(mobile))

    assert outcome.passed is True


async def test_dead_center_click_counts_against_the_score() -> None:
    """A click landing on the exact center (offset 0) is more precise than
    a human -- the click-not-dead-center heuristic scores it 0."""
    check = SignalScoreCheck()
    off_center = dict(_HUMAN, click_offset=9)
    dead_center = dict(_HUMAN, click_offset=0)

    off_score, _ = check.compute(off_center)
    dead_score, breakdown = check.compute(dead_center)

    assert off_score > dead_score
    assert breakdown["click-not-dead-center"] == 0.0


async def test_empty_signals_fall_below_the_threshold() -> None:
    outcome = await SignalScoreCheck(threshold=0.6).run(_ctx({}))

    assert outcome.passed is False


def test_compute_gives_benefit_of_the_doubt_when_everything_abstains() -> None:
    """With a heuristic set where every entry abstains on this input, there's
    nothing to hold against the user -> score 1.0 rather than 0."""
    only_pointer = SignalScoreCheck(
        heuristics=[
            ScoringHeuristic(
                "pointer",
                1.0,
                lambda s: None if s.get("pointer_type") == "touch" else 1.0,
            )
        ]
    )

    score, breakdown = only_pointer.compute({"pointer_type": "touch"})

    assert score == 1.0
    assert breakdown == {}


async def test_custom_heuristics_and_weights_are_honored() -> None:
    """The score board is fully tunable -- swap in your own heuristics."""
    always_bot = SignalScoreCheck(
        threshold=0.5,
        heuristics=[ScoringHeuristic("nope", 1.0, lambda s: 0.0)],
    )
    always_human = SignalScoreCheck(
        threshold=0.5,
        heuristics=[ScoringHeuristic("yep", 1.0, lambda s: 1.0)],
    )

    assert (await always_bot.run(_ctx(_HUMAN))).passed is False
    assert (await always_human.run(_ctx(_BOT))).passed is True


def test_threshold_out_of_range_raises() -> None:
    with pytest.raises(ValueError, match="threshold"):
        SignalScoreCheck(threshold=1.5)


# -- Mouse kinematics --------------------------------------------------
#
# A hand-built "human" trajectory (curved path, uneven step sizes, uneven
# timing -- the minimum-jerk-model shape) vs. a "bot" trajectory (an exact
# straight line, constant step size, constant time interval -- what naive
# linear-interpolation automation produces). Values confirmed empirically
# (see NOTES.md): the human one saturates all three heuristics at the
# maximum score, the bot one lands at exactly zero on all three.
_HUMAN_TRAJECTORY = [
    [0, 0, 0],
    [15, 8, 40],
    [35, 20, 75],
    [70, 28, 100],
    [110, 30, 160],
    [140, 26, 190],
    [165, 18, 230],
    [185, 9, 270],
    [196, 3, 320],
    [200, 0, 380],
]
_BOT_TRAJECTORY = [[20 * i, 0, 100 * i] for i in range(10)]


def test_mouse_curvature_separates_human_from_linear_bot() -> None:
    from webapi_captcha.scoring import _mouse_path_curvature

    human = _mouse_path_curvature({"pointer_type": "mouse", "mouse_trajectory": _HUMAN_TRAJECTORY})
    bot = _mouse_path_curvature({"pointer_type": "mouse", "mouse_trajectory": _BOT_TRAJECTORY})

    assert human == 1.0
    assert bot == pytest.approx(0.0, abs=1e-9)


def test_mouse_velocity_variance_separates_human_from_linear_bot() -> None:
    from webapi_captcha.scoring import _mouse_velocity_variance

    human = _mouse_velocity_variance(
        {"pointer_type": "mouse", "mouse_trajectory": _HUMAN_TRAJECTORY}
    )
    bot = _mouse_velocity_variance({"pointer_type": "mouse", "mouse_trajectory": _BOT_TRAJECTORY})

    assert human == 1.0
    assert bot == pytest.approx(0.0, abs=1e-9)


def test_mouse_timing_variance_separates_human_from_linear_bot() -> None:
    from webapi_captcha.scoring import _mouse_timing_variance

    human = _mouse_timing_variance({"pointer_type": "mouse", "mouse_trajectory": _HUMAN_TRAJECTORY})
    bot = _mouse_timing_variance({"pointer_type": "mouse", "mouse_trajectory": _BOT_TRAJECTORY})

    assert human == 1.0
    assert bot == pytest.approx(0.0, abs=1e-9)


def test_kinematics_are_graded_not_binary() -> None:
    """A path with only a slight curve scores somewhere in between -- these
    are soft signals scaled by how pronounced the effect is, not a hard
    pass/fail on their own."""
    from webapi_captcha.scoring import _mouse_path_curvature

    slight_curve = [[10 * i, 2 * math.sin(i / 9 * math.pi), 50 * i] for i in range(10)]
    score = _mouse_path_curvature({"pointer_type": "mouse", "mouse_trajectory": slight_curve})

    assert score is not None
    assert 0.0 < score < 1.0


def test_kinematics_abstain_on_touch_pointer() -> None:
    """No continuous mouse path exists on a tap -- abstain rather than
    penalize a legitimate mobile user."""
    from webapi_captcha.scoring import _mouse_path_curvature

    score = _mouse_path_curvature({"pointer_type": "touch", "mouse_trajectory": _HUMAN_TRAJECTORY})

    assert score is None


def test_kinematics_abstain_when_trajectory_missing() -> None:
    from webapi_captcha.scoring import _mouse_velocity_variance

    assert _mouse_velocity_variance({"pointer_type": "mouse"}) is None


def test_kinematics_abstain_on_too_few_points() -> None:
    from webapi_captcha.scoring import _mouse_timing_variance

    score = _mouse_timing_variance(
        {"pointer_type": "mouse", "mouse_trajectory": [[0, 0, 0], [1, 1, 10]]}
    )

    assert score is None


def test_kinematics_abstain_on_malformed_samples() -> None:
    from webapi_captcha.scoring import _mouse_path_curvature

    malformed = [[0, 0], [1, 1], [2, 2], [3, 3], [4, 4]]  # missing the t component
    score = _mouse_path_curvature({"pointer_type": "mouse", "mouse_trajectory": malformed})

    assert score is None


def test_kinematics_abstain_on_a_nan_coordinate_instead_of_scoring_maximally_human() -> None:
    """Regression test: `float()` (and `json.loads` by default) happily
    accepts NaN/Infinity literals -- an attacker who can't be bothered
    synthesizing a fake human-like curve could smuggle a NaN coordinate
    into `mouse_trajectory` and get FULL MARKS instead of the reject
    these heuristics are supposed to give for nonsense input: Python's
    `min`/`max` treat any NaN comparison as False, so an unguarded
    `max(0.0, min(1.0, nan))` evaluates to 1.0 (the first argument wins
    once `<` stops being decisive) -- scoring a degenerate, all-NaN-x
    trajectory as confidently human on the two heaviest-weighted
    heuristics in `default_behavior_heuristics()` (curvature and
    velocity variance, weight 2.0 and 2.5 -- more combined weight than
    any other single heuristic)."""
    from webapi_captcha.scoring import _mouse_path_curvature, _mouse_velocity_variance

    nan_trajectory = [[float("nan"), 0.0, i * 20.0] for i in range(10)]
    signals = {"pointer_type": "mouse", "mouse_trajectory": nan_trajectory}

    assert _mouse_path_curvature(signals) is None
    assert _mouse_velocity_variance(signals) is None


def test_kinematics_abstain_on_an_infinite_coordinate() -> None:
    from webapi_captcha.scoring import _mouse_path_curvature

    inf_trajectory = [[float("inf"), 0.0, i * 20.0] for i in range(10)]
    score = _mouse_path_curvature(
        {"pointer_type": "mouse", "mouse_trajectory": inf_trajectory}
    )

    assert score is None


def test_full_score_does_not_reward_a_nan_smuggled_trajectory() -> None:
    """End-to-end version of the regression above, through the real
    scoring pipeline a client's submitted `signals` actually go through."""
    from webapi_captcha.scoring import SignalScoreCheck

    check = SignalScoreCheck()
    nan_trajectory = [[float("nan"), 0.0, i * 20.0] for i in range(10)]
    signals = {
        "webdriver": False,
        "language": "en-US",
        "timezone": "UTC",
        "pointer_type": "mouse",
        "pointer_moves": 40,
        "mouse_trajectory": nan_trajectory,
        "click_offset": 12,
        "interaction_ms": 1500,
    }

    _score, breakdown = check.compute(signals)

    # The NaN-tainted trajectory must make every kinematics heuristic that
    # reads it abstain (excluded from the breakdown entirely), not score
    # as confidently human -- the other, non-trajectory heuristics still
    # legitimately pass on their own (deliberately clean `signals` here),
    # so the overall score being high is correct; what matters is that
    # the *kinematics* ones aren't the reason.
    assert "mouse-curvature" not in breakdown
    assert "mouse-velocity-variance" not in breakdown
    assert "mouse-timing-variance" not in breakdown
    assert "mouse-homing-correction" not in breakdown


def test_kinematics_cap_an_oversized_trajectory_instead_of_choking_on_it() -> None:
    """A pathologically large payload gets truncated to the first N samples
    rather than processed in full -- this must stay fast."""
    from webapi_captcha.scoring import _mouse_path_curvature

    huge = [[i, 0, i] for i in range(200_000)]
    score = _mouse_path_curvature({"pointer_type": "mouse", "mouse_trajectory": huge})

    assert score == 0.0  # still a perfectly straight line either way


def test_curvature_abstains_on_too_short_a_move() -> None:
    from webapi_captcha.scoring import _mouse_path_curvature

    short = [[i, 0, 10 * i] for i in range(10)]  # 9px total, below the 20px floor
    score = _mouse_path_curvature({"pointer_type": "mouse", "mouse_trajectory": short})

    assert score is None


_OVERSHOOT_TRAJECTORY = [
    [0, 0, 0], [30, 10, 40], [70, 22, 80], [120, 26, 120], [160, 24, 160],
    [210, 12, 210], [222, 5, 250], [214, -2, 290], [204, 1, 330], [200, 0, 380],
]  # deliberately overshoots past the final point (x=200) then corrects back


def test_homing_correction_scores_a_genuine_overshoot() -> None:
    from webapi_captcha.scoring import _mouse_homing_correction

    score = _mouse_homing_correction(
        {"pointer_type": "mouse", "mouse_trajectory": _OVERSHOOT_TRAJECTORY}
    )

    assert score == 1.0


def test_homing_correction_abstains_rather_than_penalizes_a_smooth_approach() -> None:
    """The hand-built human trajectory used elsewhere in this file never
    overshoots (plenty of real human movement doesn't) -- this must abstain,
    not score it 0, or it would unfairly punish smooth, precise movement."""
    from webapi_captcha.scoring import _mouse_homing_correction

    score = _mouse_homing_correction(
        {"pointer_type": "mouse", "mouse_trajectory": _HUMAN_TRAJECTORY}
    )

    assert score is None


def test_homing_correction_abstains_for_a_linear_bot_too() -> None:
    from webapi_captcha.scoring import _mouse_homing_correction

    score = _mouse_homing_correction(
        {"pointer_type": "mouse", "mouse_trajectory": _BOT_TRAJECTORY}
    )

    assert score is None


def test_kinematics_heuristics_appear_in_the_breakdown() -> None:
    check = SignalScoreCheck()
    signals = dict(_HUMAN, mouse_trajectory=_HUMAN_TRAJECTORY)

    score, breakdown = check.compute(signals)

    assert breakdown["mouse-curvature"] == 1.0
    assert breakdown["mouse-velocity-variance"] == 1.0
    assert breakdown["mouse-timing-variance"] == 1.0
    assert score == 1.0


async def test_bot_trajectory_does_not_rescue_an_otherwise_bot_like_score() -> None:
    """A bot that also fakes a mouse trajectory, but naively (a straight
    line, constant speed/timing), doesn't buy it anything -- the kinematics
    heuristics score that exactly as badly as no trajectory at all."""
    signals = dict(_BOT, mouse_trajectory=_BOT_TRAJECTORY)
    outcome = await SignalScoreCheck(threshold=0.6).run(_ctx(signals))

    assert outcome.passed is False


async def test_scorer_composes_into_a_gate_as_an_extra_check() -> None:
    """The score board is just a VerificationCheck -- it drops into a
    gate's extra_checks alongside proof-of-work and account binding."""
    from webapi_captcha.gate import CaptchaGate
    from webapi_captcha.memory import MemoryVerificationStore
    from webapi_captcha.transport import InProcessTransport

    gate = CaptchaGate(
        InProcessTransport(),
        MemoryVerificationStore(),
        require_captcha=False,
        extra_checks=[SignalScoreCheck(threshold=0.6)],
    )
    request = await gate.create_verification(user_id=100, purpose="signup")

    bot = await gate.verify(request.token, signals=_BOT)
    assert bot.verified is False
    assert bot.failed_check == "behavior-score"

    request2 = await gate.create_verification(user_id=100, purpose="signup")
    human = await gate.verify(request2.token, signals=_HUMAN)
    assert human.verified is True
