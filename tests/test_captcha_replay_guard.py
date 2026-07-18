"""Exercises `fingerprint_trajectory` and `RepeatedMovementCheck` -- the
cross-request replay defense, deliberately global (not scoped per user)."""

from datetime import UTC, datetime, timedelta

from webapi_captcha.checks import VerificationContext
from webapi_captcha.memory import MemoryVerificationStore
from webapi_captcha.models import VerificationRequest
from webapi_captcha.replay_guard import (
    MemoryTrajectoryFingerprintStore,
    RepeatedMovementCheck,
    fingerprint_trajectory,
)

_TRAJECTORY_A = [[0, 0, 0], [10, 5, 20], [25, 12, 45], [40, 15, 70], [50, 15, 100]]
_TRAJECTORY_B = [[0, 0, 0], [3, 20, 15], [8, 45, 30], [5, 70, 60], [0, 90, 95]]


def _ctx(signals: dict, *, user_id: int = 100, token: str = "t1") -> VerificationContext:
    now = datetime.now(UTC)
    request = VerificationRequest(
        token=token, user_id=user_id, purpose="test", created_at=now,
        expires_at=now + timedelta(minutes=10),
    )
    return VerificationContext(request=request, signals=signals)


# -- fingerprint_trajectory --


def test_fingerprint_is_deterministic_for_the_same_trajectory() -> None:
    assert fingerprint_trajectory(_TRAJECTORY_A) == fingerprint_trajectory(_TRAJECTORY_A)


def test_fingerprint_is_translation_invariant() -> None:
    """The whole point: a replay against a different on-screen widget
    position/time should still collide, so shifting every sample by a
    constant offset must not change the fingerprint."""
    shifted = [[x + 500, y + 300, t + 9_000] for x, y, t in _TRAJECTORY_A]

    assert fingerprint_trajectory(_TRAJECTORY_A) == fingerprint_trajectory(shifted)


def test_different_shapes_get_different_fingerprints() -> None:
    assert fingerprint_trajectory(_TRAJECTORY_A) != fingerprint_trajectory(_TRAJECTORY_B)


def test_fingerprint_trajectory_accepts_custom_grid_params() -> None:
    """Regression guard: passing today's default values explicitly must
    equal the no-kwargs call -- confirms the rename from private module
    constants to public DEFAULT_* ones didn't change any behavior."""
    from webapi_captcha.replay_guard import (
        DEFAULT_GRID_MS,
        DEFAULT_GRID_PX,
        DEFAULT_MAX_FINGERPRINT_POINTS,
        DEFAULT_MIN_FINGERPRINT_POINTS,
    )

    explicit = fingerprint_trajectory(
        _TRAJECTORY_A,
        grid_px=DEFAULT_GRID_PX,
        grid_ms=DEFAULT_GRID_MS,
        max_points=DEFAULT_MAX_FINGERPRINT_POINTS,
        min_points=DEFAULT_MIN_FINGERPRINT_POINTS,
    )
    assert explicit == fingerprint_trajectory(_TRAJECTORY_A)


def test_coarser_grid_collapses_two_previously_distinct_trajectories() -> None:
    a = [[0, 0, 0], [10, 5, 20], [25, 12, 45], [40, 15, 70], [50, 15, 100]]
    a_jitter = [[0, 0, 0], [12, 5, 20], [25, 15, 45], [40, 15, 70], [53, 15, 100]]

    assert fingerprint_trajectory(a) != fingerprint_trajectory(a_jitter)
    assert fingerprint_trajectory(a, grid_px=50.0) == fingerprint_trajectory(a_jitter, grid_px=50.0)


def test_finer_grid_separates_two_previously_colliding_trajectories() -> None:
    b = [[0, 0, 0], [10, 5, 20], [25, 12, 45], [40, 15, 70], [50, 15, 100]]
    b_tiny_jitter = [[0, 0, 0], [11, 5, 20], [25, 12, 45], [40, 15, 70], [50, 15, 100]]

    assert fingerprint_trajectory(b) == fingerprint_trajectory(b_tiny_jitter)
    assert fingerprint_trajectory(b, grid_px=0.5) != fingerprint_trajectory(
        b_tiny_jitter, grid_px=0.5
    )


def test_fingerprint_none_when_missing_or_malformed() -> None:
    assert fingerprint_trajectory(None) is None
    assert fingerprint_trajectory("not-a-list") is None
    assert fingerprint_trajectory([[0, 0, 0], [1, 1, 1]]) is None  # too few points
    assert fingerprint_trajectory([[0, 0], [1, 1], [2, 2], [3, 3], [4, 4]]) is None  # bad shape


# -- MemoryTrajectoryFingerprintStore --


async def test_memory_fingerprint_store_records_and_sees() -> None:
    store = MemoryTrajectoryFingerprintStore()

    assert await store.seen_recently("fp1") is False

    await store.record("fp1", timedelta(hours=1))

    assert await store.seen_recently("fp1") is True


async def test_memory_fingerprint_store_sweeps_expired_entries() -> None:
    store = MemoryTrajectoryFingerprintStore()
    await store.record("fp1", timedelta(seconds=-1))  # already expired

    assert await store.seen_recently("fp1") is False
    assert store._seen == {}  # swept away, not just reported as absent


# -- RepeatedMovementCheck --


async def test_first_submission_of_a_trajectory_passes() -> None:
    check = RepeatedMovementCheck(MemoryTrajectoryFingerprintStore())

    outcome = await check.run(_ctx({"pointer_type": "mouse", "mouse_trajectory": _TRAJECTORY_A}))

    assert outcome.passed is True


async def test_replaying_the_same_trajectory_again_fails() -> None:
    store = MemoryTrajectoryFingerprintStore()
    check = RepeatedMovementCheck(store)
    signals = {"pointer_type": "mouse", "mouse_trajectory": _TRAJECTORY_A}

    first = await check.run(_ctx(signals, token="t1"))
    second = await check.run(_ctx(signals, token="t2"))

    assert first.passed is True
    assert second.passed is False


async def test_replay_is_caught_even_under_a_different_account() -> None:
    """The defining property: this is a global cache, not per-user -- the
    same recording surfacing under a *different* account is exactly the
    evasion this check exists to catch."""
    store = MemoryTrajectoryFingerprintStore()
    check = RepeatedMovementCheck(store)
    signals = {"pointer_type": "mouse", "mouse_trajectory": _TRAJECTORY_A}

    first = await check.run(_ctx(signals, user_id=100, token="t1"))
    second = await check.run(_ctx(signals, user_id=999, token="t2"))

    assert first.passed is True
    assert second.passed is False


async def test_replay_is_caught_even_when_translated() -> None:
    """A replay against a differently-positioned widget still collides,
    since the fingerprint is translation-invariant."""
    store = MemoryTrajectoryFingerprintStore()
    check = RepeatedMovementCheck(store)
    shifted = [[x + 400, y + 200, t + 5_000] for x, y, t in _TRAJECTORY_A]

    first = await check.run(
        _ctx({"pointer_type": "mouse", "mouse_trajectory": _TRAJECTORY_A}, token="t1")
    )
    second = await check.run(
        _ctx({"pointer_type": "mouse", "mouse_trajectory": shifted}, token="t2")
    )

    assert first.passed is True
    assert second.passed is False


async def test_two_different_genuine_trajectories_both_pass() -> None:
    store = MemoryTrajectoryFingerprintStore()
    check = RepeatedMovementCheck(store)

    first = await check.run(
        _ctx({"pointer_type": "mouse", "mouse_trajectory": _TRAJECTORY_A}, token="t1")
    )
    second = await check.run(
        _ctx({"pointer_type": "mouse", "mouse_trajectory": _TRAJECTORY_B}, token="t2")
    )

    assert first.passed is True
    assert second.passed is True


async def test_fails_open_when_there_is_no_trajectory() -> None:
    """No trajectory to fingerprint -- pass, don't block a client that
    hasn't wired this signal up."""
    check = RepeatedMovementCheck(MemoryTrajectoryFingerprintStore())

    outcome = await check.run(_ctx({"pointer_type": "mouse"}))

    assert outcome.passed is True


async def test_fails_open_for_touch_pointer() -> None:
    check = RepeatedMovementCheck(MemoryTrajectoryFingerprintStore())
    signals = {"pointer_type": "touch", "mouse_trajectory": _TRAJECTORY_A}

    first = await check.run(_ctx(signals, token="t1"))
    second = await check.run(_ctx(signals, token="t2"))

    assert first.passed is True
    assert second.passed is True  # never recorded, so never "replayed" either


async def test_repeated_movement_check_threads_custom_grid_params_through() -> None:
    """A pair that collides under the default grid but not under a much
    finer one -- constructing RepeatedMovementCheck with grid_px=0.5
    must make the second submission pass instead of fail."""
    b = [[0, 0, 0], [10, 5, 20], [25, 12, 45], [40, 15, 70], [50, 15, 100]]
    b_tiny_jitter = [[0, 0, 0], [11, 5, 20], [25, 12, 45], [40, 15, 70], [50, 15, 100]]

    store = MemoryTrajectoryFingerprintStore()
    check = RepeatedMovementCheck(store, grid_px=0.5)

    first = await check.run(_ctx({"pointer_type": "mouse", "mouse_trajectory": b}, token="t1"))
    second = await check.run(
        _ctx({"pointer_type": "mouse", "mouse_trajectory": b_tiny_jitter}, token="t2")
    )

    assert first.passed is True
    assert second.passed is True  # would have been False under the default grid


async def test_composes_into_a_gate_as_an_extra_check() -> None:
    from webapi_captcha.gate import CaptchaGate
    from webapi_captcha.transport import InProcessTransport

    store = MemoryTrajectoryFingerprintStore()
    gate = CaptchaGate(
        InProcessTransport(),
        MemoryVerificationStore(),
        require_captcha=False,
        extra_checks=[RepeatedMovementCheck(store)],
    )
    signals = {"pointer_type": "mouse", "mouse_trajectory": _TRAJECTORY_A}

    request1 = await gate.create_verification(user_id=100, purpose="signup")
    first = await gate.verify(request1.token, signals=signals)

    request2 = await gate.create_verification(user_id=200, purpose="signup")
    second = await gate.verify(request2.token, signals=signals)

    assert first.verified is True
    assert second.verified is False
    assert second.failed_check == "no-repeated-movement"
