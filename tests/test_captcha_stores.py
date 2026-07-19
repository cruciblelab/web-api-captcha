"""Exercises Memory/SQL CaptchaStore and VerificationStore -- CRUD only,
provider logic (issue/verify) is covered separately in
tests/unit/test_captcha_providers.py."""

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest_asyncio
from cryptography.fernet import Fernet
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import StaticPool

from webapi_captcha.adaptive import AdaptiveDecision
from webapi_captcha.memory import MemoryCaptchaStore, MemoryVerificationStore
from webapi_captcha.models import CaptchaChallenge, PendingCaptcha, VerificationRequest
from webapi_captcha.risk import RiskLevel
from webapi_captcha.sql import (
    PendingCaptchaRow,
    SQLAdaptiveDecisionStore,
    SQLCaptchaStore,
    SQLRunningRiskStore,
    SQLTrajectoryFingerprintStore,
    SQLTrustStore,
    SQLVerificationStore,
)


@pytest_asyncio.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    try:
        yield engine
    finally:
        # Without this, aiosqlite's background worker thread for this
        # engine's connection can still be tearing itself down (posting
        # back to this test's event loop) after pytest has already
        # closed that loop for the next test -- harmless in outcome, but
        # noisy (a stray PytestUnhandledThreadExceptionWarning) in a full
        # suite run. dispose() waits for the pool's connections to close
        # cleanly before this fixture (and its event loop) goes away.
        await engine.dispose()


def _pending(challenge_id: str = "c1", answer: str = "42") -> PendingCaptcha:
    now = datetime.now(UTC)
    return PendingCaptcha(
        challenge_id=challenge_id,
        kind="math",
        answer=answer,
        created_at=now,
        expires_at=now + timedelta(minutes=10),
    )


def _verification(token: str = "t1", user_id: int = 100) -> VerificationRequest:
    now = datetime.now(UTC)
    return VerificationRequest(
        token=token,
        user_id=user_id,
        guild_id=999,
        purpose="giveaway_entry",
        metadata={"giveaway_id": "abc"},
        challenge=CaptchaChallenge(challenge_id="c1", kind="math", prompt="1 + 1 = ?"),
        created_at=now,
        expires_at=now + timedelta(minutes=15),
    )


# -- MemoryCaptchaStore --


async def test_memory_captcha_store_create_and_get() -> None:
    store = MemoryCaptchaStore()
    await store.create(_pending())

    fetched = await store.get("c1")

    assert fetched is not None
    assert fetched.answer == "42"
    assert fetched.attempts == 0


async def test_memory_captcha_store_get_missing_returns_none() -> None:
    store = MemoryCaptchaStore()

    assert await store.get("nope") is None


async def test_memory_captcha_store_increment_attempts() -> None:
    store = MemoryCaptchaStore()
    await store.create(_pending())

    first = await store.increment_attempts("c1")
    second = await store.increment_attempts("c1")

    assert first == 1
    assert second == 2


async def test_memory_captcha_store_increment_attempts_on_missing_returns_zero() -> None:
    store = MemoryCaptchaStore()

    assert await store.increment_attempts("nope") == 0


async def test_memory_captcha_store_delete() -> None:
    store = MemoryCaptchaStore()
    await store.create(_pending())

    await store.delete("c1")

    assert await store.get("c1") is None


# -- MemoryVerificationStore --


async def test_memory_verification_store_create_and_get() -> None:
    store = MemoryVerificationStore()
    await store.create(_verification())

    fetched = await store.get("t1")

    assert fetched is not None
    assert fetched.user_id == 100
    assert fetched.verified is False


async def test_memory_verification_store_mark_verified() -> None:
    store = MemoryVerificationStore()
    await store.create(_verification())

    await store.mark_verified("t1")

    fetched = await store.get("t1")
    assert fetched is not None
    assert fetched.verified is True


async def test_memory_verification_store_delete() -> None:
    store = MemoryVerificationStore()
    await store.create(_verification())

    await store.delete("t1")

    assert await store.get("t1") is None


# -- SQLCaptchaStore --


async def test_sql_captcha_store_create_and_get(engine: AsyncEngine) -> None:
    store = SQLCaptchaStore(engine)
    await store.create_all()
    await store.create(_pending())

    fetched = await store.get("c1")

    assert fetched is not None
    assert fetched.answer == "42"
    assert fetched.kind == "math"


async def test_sql_captcha_store_increment_attempts(engine: AsyncEngine) -> None:
    store = SQLCaptchaStore(engine)
    await store.create_all()
    await store.create(_pending())

    count = await store.increment_attempts("c1")

    assert count == 1
    fetched = await store.get("c1")
    assert fetched is not None
    assert fetched.attempts == 1


async def test_sql_captcha_store_increment_attempts_is_atomic_under_concurrency(
    engine: AsyncEngine,
) -> None:
    """The real bug this guards against: increment_attempts used to be a
    SELECT-then-mutate-then-commit, which loses updates under concurrent
    calls (two transactions both read the same pre-increment count before
    either commits) -- exactly the race a captcha attempt-limit needs to
    be immune to. Firing many concurrent increments at the same
    challenge_id and checking the final count matches the number of
    calls (no lost updates) proves the atomic UPDATE closes it."""
    import asyncio

    store = SQLCaptchaStore(engine)
    await store.create_all()
    await store.create(_pending())

    await asyncio.gather(*(store.increment_attempts("c1") for _ in range(20)))

    fetched = await store.get("c1")
    assert fetched is not None
    assert fetched.attempts == 20


async def test_sql_captcha_store_delete(engine: AsyncEngine) -> None:
    store = SQLCaptchaStore(engine)
    await store.create_all()
    await store.create(_pending())

    await store.delete("c1")

    assert await store.get("c1") is None


# -- SQLVerificationStore --


async def test_sql_verification_store_create_and_get(engine: AsyncEngine) -> None:
    store = SQLVerificationStore(engine)
    await store.create_all()
    await store.create(_verification())

    fetched = await store.get("t1")

    assert fetched is not None
    assert fetched.user_id == 100
    assert fetched.guild_id == 999
    assert fetched.purpose == "giveaway_entry"
    assert fetched.metadata == {"giveaway_id": "abc"}
    assert fetched.challenge.challenge_id == "c1"
    assert fetched.verified is False


async def test_sql_verification_store_round_trips_a_none_challenge(engine: AsyncEngine) -> None:
    """An account-only / click-only gate stores a verification with no
    captcha challenge -- challenge_json is nullable and must round-trip."""
    store = SQLVerificationStore(engine)
    await store.create_all()
    now = datetime.now(UTC)
    request = VerificationRequest(
        token="t-no-captcha",
        user_id=100,
        purpose="account_only",
        challenge=None,
        created_at=now,
        expires_at=now + timedelta(minutes=15),
    )
    await store.create(request)

    fetched = await store.get("t-no-captcha")

    assert fetched is not None
    assert fetched.challenge is None


async def test_sql_verification_store_mark_verified(engine: AsyncEngine) -> None:
    store = SQLVerificationStore(engine)
    await store.create_all()
    await store.create(_verification())

    await store.mark_verified("t1")

    fetched = await store.get("t1")
    assert fetched is not None
    assert fetched.verified is True


async def test_sql_verification_store_delete(engine: AsyncEngine) -> None:
    store = SQLVerificationStore(engine)
    await store.create_all()
    await store.create(_verification())

    await store.delete("t1")

    assert await store.get("t1") is None


# -- SQLTrajectoryFingerprintStore --


async def test_sql_trajectory_fingerprint_store_records_and_sees(engine: AsyncEngine) -> None:
    store = SQLTrajectoryFingerprintStore(engine)
    await store.create_all()

    assert await store.seen_recently("fp1") is False

    await store.record("fp1", timedelta(hours=1))

    assert await store.seen_recently("fp1") is True


async def test_sql_trajectory_fingerprint_store_expires(engine: AsyncEngine) -> None:
    store = SQLTrajectoryFingerprintStore(engine)
    await store.create_all()

    await store.record("fp1", timedelta(seconds=-1))  # already expired

    assert await store.seen_recently("fp1") is False


async def test_sql_trajectory_fingerprint_store_concurrent_first_record_does_not_crash(
    tmp_path: object,
) -> None:
    """Regression test: `record()` used to be a plain SELECT-then-add()-
    or-mutate, the same lost-update/IntegrityError race already fixed
    for `SQLCaptchaStore.increment_attempts` elsewhere in this codebase.
    Two concurrent replayed-trajectory checks for the SAME fingerprint
    (a plausible real scenario -- replay_guard.py's own docstring
    describes checking the same recording "across different accounts/
    devices/IPs... even" at once) used to crash the loser with an
    unhandled IntegrityError. Uses a real file-backed SQLite engine, not
    `:memory:`+StaticPool -- that combination shares one physical
    connection across "concurrent" sessions and can mask or spuriously
    fail this exact class of race (noted independently while auditing
    this codebase's escalation store)."""
    import asyncio

    from sqlalchemy.ext.asyncio import create_async_engine

    file_engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/fp.sqlite3")  # type: ignore[arg-type]
    store = SQLTrajectoryFingerprintStore(file_engine)
    await store.create_all()

    await asyncio.gather(*(store.record("fp1", timedelta(hours=1)) for _ in range(10)))

    assert await store.seen_recently("fp1") is True
    await file_engine.dispose()


# -- SQLAdaptiveDecisionStore --


async def test_sql_adaptive_decision_store_records_and_reads(engine: AsyncEngine) -> None:
    store = SQLAdaptiveDecisionStore(engine)
    await store.create_all()

    assert await store.get("t1") is None

    decision = AdaptiveDecision(
        requires_captcha=True,
        challenge=CaptchaChallenge(challenge_id="c1", kind="math", prompt="1 + 1 = ?"),
    )
    await store.set("t1", decision)

    fetched = await store.get("t1")
    assert fetched is not None
    assert fetched.requires_captcha is True
    assert fetched.challenge is not None
    assert fetched.challenge.challenge_id == "c1"


async def test_sql_adaptive_decision_store_round_trips_no_challenge(engine: AsyncEngine) -> None:
    store = SQLAdaptiveDecisionStore(engine)
    await store.create_all()

    await store.set("t1", AdaptiveDecision(requires_captcha=False, challenge=None))

    fetched = await store.get("t1")
    assert fetched is not None
    assert fetched.requires_captcha is False
    assert fetched.challenge is None


async def test_sql_adaptive_decision_store_delete(engine: AsyncEngine) -> None:
    store = SQLAdaptiveDecisionStore(engine)
    await store.create_all()
    await store.set("t1", AdaptiveDecision(requires_captcha=False))

    await store.delete("t1")

    assert await store.get("t1") is None


async def test_sql_adaptive_decision_store_concurrent_first_set_does_not_crash(
    tmp_path: object,
) -> None:
    """Regression test: two concurrent `AdaptiveCaptchaGate`s (across web
    replicas) racing to resolve the same token's decision both used to
    call `set()` with no protection -- the loser crashed with an
    unhandled IntegrityError instead of the first-writer-wins behavior
    every other race fix in this codebase settled on. Real file-backed
    engine, not `:memory:`+StaticPool -- see the fingerprint-store test
    above for why."""
    import asyncio

    from sqlalchemy.ext.asyncio import create_async_engine

    file_engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/decisions.sqlite3")  # type: ignore[arg-type]
    store = SQLAdaptiveDecisionStore(file_engine)
    await store.create_all()

    decisions = [
        AdaptiveDecision(
            requires_captcha=True,
            challenge=CaptchaChallenge(challenge_id=f"c{i}", kind="math", prompt=f"{i} + 1 = ?"),
        )
        for i in range(10)
    ]
    await asyncio.gather(*(store.set("t1", d) for d in decisions))

    # Whichever decision won, every subsequent read must agree on the
    # SAME one -- not crash, and not silently vary between reads.
    winner = await store.get("t1")
    assert winner is not None
    for _ in range(5):
        assert (await store.get("t1")) == winner
    await file_engine.dispose()


# -- SQLTrustStore --


async def test_sql_trust_store_records_and_checks(engine: AsyncEngine) -> None:
    store = SQLTrustStore(engine)
    await store.create_all()

    assert await store.is_trusted(100) is False

    await store.trust(100, ttl=timedelta(hours=1))

    assert await store.is_trusted(100) is True


async def test_sql_trust_store_ip_binding(engine: AsyncEngine) -> None:
    store = SQLTrustStore(engine)
    await store.create_all()

    await store.trust(100, ttl=timedelta(hours=1), ip="1.2.3.4")

    assert await store.is_trusted(100, ip="1.2.3.4") is True
    assert await store.is_trusted(100, ip="6.6.6.6") is False
    assert await store.is_trusted(100) is True  # no ip check requested -- unaffected


async def test_sql_trust_store_expires(engine: AsyncEngine) -> None:
    store = SQLTrustStore(engine)
    await store.create_all()

    await store.trust(100, ttl=timedelta(seconds=-1))  # already expired

    assert await store.is_trusted(100) is False


async def test_sql_trust_store_concurrent_first_trust_does_not_crash(tmp_path: object) -> None:
    """Regression test: `trust()` used to be a plain SELECT-then-add()-
    or-mutate -- two concurrent `verify()` successes for the same
    user_id (plausible: two different gates/purposes sharing one
    TrustStore, both completed around the same time) both calling
    `trust()` used to crash the loser with an unhandled IntegrityError.
    Real file-backed engine, not `:memory:`+StaticPool -- see the
    fingerprint-store test above for why."""
    import asyncio

    from sqlalchemy.ext.asyncio import create_async_engine

    file_engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/trust.sqlite3")  # type: ignore[arg-type]
    store = SQLTrustStore(file_engine)
    await store.create_all()

    await asyncio.gather(*(store.trust(100, ttl=timedelta(hours=1)) for _ in range(10)))

    assert await store.is_trusted(100) is True
    await file_engine.dispose()


# -- SQLCaptchaStore: optional at-rest encryption --


async def test_sql_captcha_store_without_encryption_keys_round_trips_plaintext(
    engine: AsyncEngine,
) -> None:
    """Backward compatibility: no encryption_keys (the default) behaves
    exactly as before this feature existed."""
    store = SQLCaptchaStore(engine)
    await store.create_all()
    await store.create(_pending(answer="42"))

    fetched = await store.get("c1")

    assert fetched is not None
    assert fetched.answer == "42"


async def test_sql_captcha_store_with_encryption_keys_round_trips_the_answer(
    engine: AsyncEngine,
) -> None:
    store = SQLCaptchaStore(engine, encryption_keys=Fernet.generate_key())
    await store.create_all()
    await store.create(_pending(answer="42"))

    fetched = await store.get("c1")

    assert fetched is not None
    assert fetched.answer == "42"


async def test_sql_captcha_store_with_encryption_keys_does_not_store_plaintext(
    engine: AsyncEngine,
) -> None:
    """Confirms the encryption is real, not just round-tripping through
    get() -- reads the raw row directly, bypassing the store's own
    decryption, and checks the stored value isn't the plaintext answer."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    store = SQLCaptchaStore(engine, encryption_keys=Fernet.generate_key())
    await store.create_all()
    await store.create(_pending(answer="super-secret-answer"))

    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as db:
        row = await db.get(PendingCaptchaRow, "c1")
        assert row is not None
        assert row.answer != "super-secret-answer"


async def test_sql_captcha_store_encryption_key_mismatch_treats_answer_as_gone(
    engine: AsyncEngine,
) -> None:
    """A row encrypted under one key (or never encrypted at all) can't be
    read back by a store configured with a different key -- treated the
    same as "this pending challenge doesn't exist" (None), not a raised
    exception, matching the fail-closed philosophy the rest of this
    package follows."""
    writer = SQLCaptchaStore(engine, encryption_keys=Fernet.generate_key())
    await writer.create_all()
    await writer.create(_pending(answer="42"))

    reader = SQLCaptchaStore(engine, encryption_keys=Fernet.generate_key())
    assert await reader.get("c1") is None


async def test_sql_captcha_store_purge_expired(engine: AsyncEngine) -> None:
    store = SQLCaptchaStore(engine)
    await store.create_all()
    now = datetime.now(UTC)
    await store.create(
        PendingCaptcha(
            challenge_id="expired",
            kind="math",
            answer="1",
            created_at=now - timedelta(minutes=20),
            expires_at=now - timedelta(minutes=10),
        )
    )
    await store.create(_pending(challenge_id="still-live"))

    deleted = await store.purge_expired()

    assert deleted == 1
    assert await store.get("still-live") is not None


# -- purge_expired() for the other SQL stores --


async def test_sql_verification_store_purge_expired(engine: AsyncEngine) -> None:
    store = SQLVerificationStore(engine)
    await store.create_all()
    now = datetime.now(UTC)
    await store.create(
        VerificationRequest(
            token="expired",
            user_id=1,
            purpose="x",
            created_at=now - timedelta(minutes=20),
            expires_at=now - timedelta(minutes=10),
        )
    )
    await store.create(_verification(token="still-live"))

    deleted = await store.purge_expired()

    assert deleted == 1
    assert await store.get("still-live") is not None


async def test_sql_trajectory_fingerprint_store_purge_expired(engine: AsyncEngine) -> None:
    store = SQLTrajectoryFingerprintStore(engine)
    await store.create_all()
    await store.record("expired", timedelta(seconds=-1))
    await store.record("still-live", timedelta(hours=1))

    deleted = await store.purge_expired()

    assert deleted == 1
    assert await store.seen_recently("still-live") is True


async def test_sql_trust_store_purge_expired(engine: AsyncEngine) -> None:
    store = SQLTrustStore(engine)
    await store.create_all()
    await store.trust(1, ttl=timedelta(seconds=-1))
    await store.trust(2, ttl=timedelta(hours=1))

    deleted = await store.purge_expired()

    assert deleted == 1
    assert await store.is_trusted(2) is True


# -- SQLRunningRiskStore --


async def test_sql_running_risk_store_unseen_visitor_returns_none(engine: AsyncEngine) -> None:
    store = SQLRunningRiskStore(engine)
    await store.create_all()

    assert await store.get(1) is None


async def test_sql_running_risk_store_bump_raises_but_never_lowers(engine: AsyncEngine) -> None:
    store = SQLRunningRiskStore(engine)
    await store.create_all()

    result = await store.bump(1, RiskLevel.ELEVATED, ttl=timedelta(minutes=5))
    assert result == RiskLevel.ELEVATED
    assert await store.get(1) == RiskLevel.ELEVATED

    result = await store.bump(1, RiskLevel.LOW, ttl=timedelta(minutes=5))
    assert result == RiskLevel.ELEVATED

    result = await store.bump(1, RiskLevel.HIGH, ttl=timedelta(minutes=5))
    assert result == RiskLevel.HIGH


async def test_sql_running_risk_store_expires(engine: AsyncEngine) -> None:
    store = SQLRunningRiskStore(engine)
    await store.create_all()

    await store.bump(1, RiskLevel.HIGH, ttl=timedelta(seconds=-1))

    assert await store.get(1) is None
    # Bumping again after expiry starts fresh rather than maxing against
    # the stale value.
    result = await store.bump(1, RiskLevel.LOW, ttl=timedelta(minutes=5))
    assert result == RiskLevel.LOW


async def test_sql_running_risk_store_purge_expired(engine: AsyncEngine) -> None:
    store = SQLRunningRiskStore(engine)
    await store.create_all()
    await store.bump(1, RiskLevel.HIGH, ttl=timedelta(seconds=-1))
    await store.bump(2, RiskLevel.HIGH, ttl=timedelta(hours=1))

    deleted = await store.purge_expired()

    assert deleted == 1
    assert await store.get(2) == RiskLevel.HIGH


async def test_sql_running_risk_store_concurrent_first_bump_does_not_crash(
    tmp_path: object,
) -> None:
    """Same first-write-wins race as `SQLTrustStore`'s equivalent test --
    real file-backed engine, not `:memory:`+StaticPool."""
    import asyncio

    from sqlalchemy.ext.asyncio import create_async_engine

    file_engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/running_risk.sqlite3")  # type: ignore[arg-type]
    store = SQLRunningRiskStore(file_engine)
    await store.create_all()

    await asyncio.gather(
        *(store.bump(1, RiskLevel.ELEVATED, ttl=timedelta(hours=1)) for _ in range(10))
    )

    assert await store.get(1) == RiskLevel.ELEVATED
    await file_engine.dispose()
