"""CaptchaStore / VerificationStore backed by SQLAlchemy 2.0 async.

Requires the `webapi-captcha[sql]` extra. **Own independent tables** --
importing this module never creates a table for someone who only uses
the in-memory stores.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any, TypeVar, cast

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CursorResult,
    DateTime,
    Integer,
    String,
    Text,
    delete,
    update,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from webapi_captcha.adaptive import AdaptiveDecision
from webapi_captcha.models import CaptchaChallenge, PendingCaptcha, VerificationRequest

_TIMESTAMP = DateTime(timezone=True)


def _normalize_encryption_keys(keys: bytes | list[bytes]) -> list[bytes]:
    # A single key, or a list for MultiFernet key rotation (old key still
    # decrypts, only the newest encrypts).
    return [keys] if isinstance(keys, bytes) else list(keys)


_Row = TypeVar("_Row")


async def _commit_upsert(
    db: AsyncSession,
    *,
    is_new: bool,
    get_existing: Callable[[], Awaitable[_Row | None]],
    apply_fields: Callable[[_Row], None],
) -> None:
    """Guards against the same first-write-wins race in every store below:
    each first-write-wins row in this module (a token's adaptive
    decision, a replayed-trajectory fingerprint, a trusted user) used to
    do a plain read-then-insert with no protection: two concurrent
    callers for the same key (a double page load, two web replicas
    handling the same request at once) could both see no row yet and
    both `db.add()` the same primary key, and the loser's commit raised
    an unhandled `IntegrityError` -- a 500 for what should just be
    "someone already wrote this, I'm done too." Only relevant for
    genuinely new rows."""
    if not is_new:
        await db.commit()
        return
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        existing = await get_existing()
        assert existing is not None, "IntegrityError implies the row now exists"
        apply_fields(existing)
        await db.commit()


class Base(DeclarativeBase):
    pass


class PendingCaptchaRow(Base):
    __tablename__ = "wac_captcha_pending"

    challenge_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32))
    # Text, not a bounded String: the path-trace provider stores a
    # JSON-encoded expected answer here that's larger than a plain math
    # result.
    answer: Mapped[str] = mapped_column(Text)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(_TIMESTAMP)
    expires_at: Mapped[datetime] = mapped_column(_TIMESTAMP)


class VerificationRequestRow(Base):
    __tablename__ = "wac_captcha_verifications"

    token: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(BigInteger)
    guild_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    purpose: Mapped[str] = mapped_column(String(128))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    challenge_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(_TIMESTAMP)
    expires_at: Mapped[datetime] = mapped_column(_TIMESTAMP)


class TrajectoryFingerprintRow(Base):
    __tablename__ = "wac_captcha_trajectory_fingerprints"

    fingerprint: Mapped[str] = mapped_column(String(64), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(_TIMESTAMP)


def _as_utc(value: datetime) -> datetime:
    # SQLite doesn't preserve tzinfo across a round-trip.
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


class SQLCaptchaStore:
    """CaptchaStore backed by SQLAlchemy 2.0 async. Call `create_all()`
    once at startup (or manage the tables via Alembic).

    `encryption_keys`: optional (default `None` -- plaintext, the
    original behavior, fully backward compatible with existing rows and
    deployments that never pass this). When set, `PendingCaptcha.answer`
    -- the expected solution to a not-yet-solved challenge -- is
    encrypted at rest (Fernet, with `MultiFernet` key-rotation support):
    read access to the database alone then isn't enough to read off
    every currently-pending challenge's answer and auto-solve it.
    `challenge_id`/`kind`/`attempts`/timestamps
    stay in plaintext -- none of those reveal the answer itself, and
    `increment_attempts()`'s atomic `UPDATE ... SET attempts = attempts +
    1` needs to keep working as a bare column operation, which an
    encrypted value can't support.
    """

    def __init__(
        self, engine: AsyncEngine, *, encryption_keys: bytes | list[bytes] | None = None
    ) -> None:
        self._engine = engine
        self._sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
        self._fernet = (
            MultiFernet([Fernet(key) for key in _normalize_encryption_keys(encryption_keys)])
            if encryption_keys is not None
            else None
        )

    async def create_all(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    def _encrypt_answer(self, answer: str) -> str:
        if self._fernet is None:
            return answer
        return self._fernet.encrypt(answer.encode()).decode("ascii")

    def _decrypt_answer(self, answer: str) -> str | None:
        """`None` (not a raised exception) when the stored value isn't a
        valid Fernet token for the configured key(s) -- e.g. a plaintext
        row left over from before `encryption_keys` was turned on
        mid-deployment. Treated the same as "this pending challenge
        doesn't exist" by `get()`, matching the fail-closed philosophy
        `_shared.check_pending_challenge` already relies on elsewhere
        (an unreadable answer can never be verified against, so there's
        nothing a caller could usefully do with it anyway)."""
        if self._fernet is None:
            return answer
        try:
            return self._fernet.decrypt(answer.encode("ascii")).decode()
        except InvalidToken:
            return None

    async def create(self, pending: PendingCaptcha) -> None:
        async with self._sessionmaker() as db:
            db.add(
                PendingCaptchaRow(
                    challenge_id=pending.challenge_id,
                    kind=pending.kind,
                    answer=self._encrypt_answer(pending.answer),
                    attempts=pending.attempts,
                    created_at=pending.created_at,
                    expires_at=pending.expires_at,
                )
            )
            await db.commit()

    async def get(self, challenge_id: str) -> PendingCaptcha | None:
        async with self._sessionmaker() as db:
            row = await db.get(PendingCaptchaRow, challenge_id)
            if row is None:
                return None
            answer = self._decrypt_answer(row.answer)
            if answer is None:
                return None
            return PendingCaptcha(
                challenge_id=row.challenge_id,
                kind=row.kind,
                answer=answer,
                attempts=row.attempts,
                created_at=_as_utc(row.created_at),
                expires_at=_as_utc(row.expires_at),
            )

    async def purge_expired(self) -> int:
        """Bulk-deletes every pending challenge past its `expires_at`.
        `get()`/`_shared.check_pending_challenge` already treat an
        expired row as gone on read (lazy expiry), so this is purely
        storage hygiene for rows nobody ever looks at again -- wire it
        into your own periodic task (a cron job, an APScheduler job,
        whatever you already use); this library runs no background
        scheduler of its own. Returns how many rows were deleted."""
        async with self._sessionmaker() as db:
            result = cast(
                CursorResult[Any],
                await db.execute(
                    delete(PendingCaptchaRow).where(
                        PendingCaptchaRow.expires_at <= datetime.now(UTC)
                    )
                ),
            )
            await db.commit()
            return result.rowcount or 0

    async def increment_attempts(self, challenge_id: str) -> int:
        # A single atomic `UPDATE ... SET attempts = attempts + 1`, not a
        # SELECT-then-mutate-then-commit -- the latter has a real lost-
        # update race under concurrent guesses against the same
        # challenge_id (two transactions both read the same pre-increment
        # count before either commits, e.g. under READ COMMITTED), which
        # is exactly the kind of race `_shared.check_pending_challenge`
        # relies on this being immune to for its attempt-limit check to
        # be trustworthy under concurrency. No `.returning()` here --
        # MySQL's dialect doesn't support it, and this needs to work
        # across sqlite/postgres/mysql -- so the atomic UPDATE commits
        # first, then a plain read-back reports the (already-consistent,
        # already-committed) new value.
        async with self._sessionmaker() as db:
            await db.execute(
                update(PendingCaptchaRow)
                .where(PendingCaptchaRow.challenge_id == challenge_id)
                .values(attempts=PendingCaptchaRow.attempts + 1)
            )
            await db.commit()
            row = await db.get(PendingCaptchaRow, challenge_id)
            return row.attempts if row is not None else 0

    async def delete(self, challenge_id: str) -> None:
        async with self._sessionmaker() as db:
            row = await db.get(PendingCaptchaRow, challenge_id)
            if row is not None:
                await db.delete(row)
                await db.commit()


class SQLVerificationStore:
    """VerificationStore backed by SQLAlchemy 2.0 async. Call
    `create_all()` once at startup (or manage the tables via Alembic)."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._sessionmaker = async_sessionmaker(engine, expire_on_commit=False)

    async def create_all(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def create(self, request: VerificationRequest) -> None:
        async with self._sessionmaker() as db:
            db.add(
                VerificationRequestRow(
                    token=request.token,
                    user_id=request.user_id,
                    guild_id=request.guild_id,
                    purpose=request.purpose,
                    metadata_json=request.metadata,
                    challenge_json=(
                        request.challenge.model_dump(mode="json")
                        if request.challenge is not None
                        else None
                    ),
                    verified=request.verified,
                    created_at=request.created_at,
                    expires_at=request.expires_at,
                )
            )
            await db.commit()

    async def get(self, token: str) -> VerificationRequest | None:
        async with self._sessionmaker() as db:
            row = await db.get(VerificationRequestRow, token)
            if row is None:
                return None
            return VerificationRequest(
                token=row.token,
                user_id=row.user_id,
                guild_id=row.guild_id,
                purpose=row.purpose,
                metadata=row.metadata_json,
                challenge=(
                    CaptchaChallenge.model_validate(row.challenge_json)
                    if row.challenge_json is not None
                    else None
                ),
                verified=row.verified,
                created_at=_as_utc(row.created_at),
                expires_at=_as_utc(row.expires_at),
            )

    async def mark_verified(self, token: str) -> None:
        async with self._sessionmaker() as db:
            row = await db.get(VerificationRequestRow, token)
            if row is not None:
                row.verified = True
                await db.commit()

    async def delete(self, token: str) -> None:
        async with self._sessionmaker() as db:
            row = await db.get(VerificationRequestRow, token)
            if row is not None:
                await db.delete(row)
                await db.commit()

    async def purge_expired(self) -> int:
        """Bulk-deletes every verification request past its `expires_at`
        -- same storage-hygiene role as `SQLCaptchaStore.purge_expired()`.
        Note this doesn't also clean up a corresponding
        `SQLAdaptiveDecisionStore` row for the same token, if one exists
        (that store has no `expires_at` of its own -- its lifecycle
        follows whichever `VerificationRequest` it was resolved for);
        purge that store's genuinely orphaned rows separately if you use
        `AdaptiveCaptchaGate` with a SQL decision store and care about
        this scale of storage hygiene."""
        async with self._sessionmaker() as db:
            result = cast(
                CursorResult[Any],
                await db.execute(
                    delete(VerificationRequestRow).where(
                        VerificationRequestRow.expires_at <= datetime.now(UTC)
                    )
                ),
            )
            await db.commit()
            return result.rowcount or 0


class SQLTrajectoryFingerprintStore:
    """`TrajectoryFingerprintStore` backed by SQLAlchemy 2.0 async -- the
    multi-process-safe version of `MemoryTrajectoryFingerprintStore`, so a
    replayed fingerprint is caught even if it lands on a different web
    replica than the one that saw it first. Call `create_all()` once at
    startup (or manage the tables via Alembic)."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._sessionmaker = async_sessionmaker(engine, expire_on_commit=False)

    async def create_all(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def seen_recently(self, fingerprint: str) -> bool:
        async with self._sessionmaker() as db:
            row = await db.get(TrajectoryFingerprintRow, fingerprint)
            if row is None:
                return False
            if _as_utc(row.expires_at) <= datetime.now(UTC):
                await db.delete(row)
                await db.commit()
                return False
            return True

    async def record(self, fingerprint: str, ttl: timedelta) -> None:
        expires_at = datetime.now(UTC) + ttl

        def _apply(row: TrajectoryFingerprintRow) -> None:
            row.expires_at = expires_at

        async with self._sessionmaker() as db:
            row = await db.get(TrajectoryFingerprintRow, fingerprint)
            is_new = row is None
            if row is None:
                row = TrajectoryFingerprintRow(fingerprint=fingerprint, expires_at=expires_at)
                db.add(row)
            else:
                _apply(row)
            await _commit_upsert(
                db,
                is_new=is_new,
                get_existing=lambda: db.get(TrajectoryFingerprintRow, fingerprint),
                apply_fields=_apply,
            )

    async def purge_expired(self) -> int:
        """Bulk-deletes every fingerprint past its `expires_at` -- same
        storage-hygiene role as `SQLCaptchaStore.purge_expired()`.
        `seen_recently()` already lazily deletes one expired row per
        read; this covers fingerprints nobody's checked against since
        they expired."""
        async with self._sessionmaker() as db:
            result = cast(
                CursorResult[Any],
                await db.execute(
                    delete(TrajectoryFingerprintRow).where(
                        TrajectoryFingerprintRow.expires_at <= datetime.now(UTC)
                    )
                ),
            )
            await db.commit()
            return result.rowcount or 0


class AdaptiveDecisionRow(Base):
    __tablename__ = "wac_captcha_adaptive_decisions"

    token: Mapped[str] = mapped_column(String(64), primary_key=True)
    requires_captcha: Mapped[bool] = mapped_column(Boolean)
    challenge_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)


class SQLAdaptiveDecisionStore:
    """`AdaptiveDecisionStore` backed by SQLAlchemy 2.0 async -- the
    multi-process-safe version of `MemoryAdaptiveDecisionStore`, so every
    web replica agrees on whether a given token already got its
    escalation decision (and what it was)."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._sessionmaker = async_sessionmaker(engine, expire_on_commit=False)

    async def create_all(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def get(self, token: str) -> AdaptiveDecision | None:
        async with self._sessionmaker() as db:
            row = await db.get(AdaptiveDecisionRow, token)
            if row is None:
                return None
            return AdaptiveDecision(
                requires_captcha=row.requires_captcha,
                challenge=(
                    CaptchaChallenge.model_validate(row.challenge_json)
                    if row.challenge_json is not None
                    else None
                ),
            )

    async def set(self, token: str, decision: AdaptiveDecision) -> None:
        # Two concurrent AdaptiveCaptchaGates racing to resolve the same
        # token's decision (across web replicas -- within one process,
        # AdaptiveCaptchaGate's own per-token asyncio.Lock already
        # prevents this) both calling `set()` used to make the loser
        # crash with an unhandled IntegrityError. Unlike a plain "set my
        # value" store (SQLTrustStore/SQLTrajectoryFingerprintStore
        # below), overwriting here would be WRONG, not just redundant --
        # the two racing decisions can carry genuinely DIFFERENT
        # escalation challenges, and whichever was persisted FIRST is
        # the one every caller must agree on (a different challenge may
        # already be rendered on someone's screen). So on conflict we
        # deliberately discard our own write rather than overwrite the
        # existing row; `AdaptiveCaptchaGate._resolve_decision_locked`
        # re-reads via `get()` after calling this, so the loser ends up
        # returning the actually-persisted decision, not its own
        # orphaned one.
        challenge_json = (
            decision.challenge.model_dump(mode="json") if decision.challenge is not None else None
        )
        async with self._sessionmaker() as db:
            db.add(
                AdaptiveDecisionRow(
                    token=token,
                    requires_captcha=decision.requires_captcha,
                    challenge_json=challenge_json,
                )
            )
            try:
                await db.commit()
            except IntegrityError:
                await db.rollback()

    async def delete(self, token: str) -> None:
        async with self._sessionmaker() as db:
            row = await db.get(AdaptiveDecisionRow, token)
            if row is not None:
                await db.delete(row)
                await db.commit()


class TrustRow(Base):
    __tablename__ = "wac_captcha_trust"

    user_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    trusted_until: Mapped[datetime] = mapped_column(_TIMESTAMP)
    bound_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)


class SQLTrustStore:
    """`TrustStore` backed by SQLAlchemy 2.0 async -- the multi-process-
    safe version of `MemoryTrustStore`."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._sessionmaker = async_sessionmaker(engine, expire_on_commit=False)

    async def create_all(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def is_trusted(self, user_id: int, *, ip: str | None = None) -> bool:
        async with self._sessionmaker() as db:
            row = await db.get(TrustRow, user_id)
            if row is None:
                return False
            if _as_utc(row.trusted_until) <= datetime.now(UTC):
                await db.delete(row)
                await db.commit()
                return False
            if ip is not None and row.bound_ip is not None and row.bound_ip != ip:
                return False
            return True

    async def trust(self, user_id: int, *, ttl: timedelta, ip: str | None = None) -> None:
        trusted_until = datetime.now(UTC) + ttl

        def _apply(row: TrustRow) -> None:
            row.trusted_until = trusted_until
            row.bound_ip = ip

        async with self._sessionmaker() as db:
            row = await db.get(TrustRow, user_id)
            is_new = row is None
            if row is None:
                row = TrustRow(user_id=user_id, trusted_until=trusted_until, bound_ip=ip)
                db.add(row)
            else:
                _apply(row)
            await _commit_upsert(
                db,
                is_new=is_new,
                get_existing=lambda: db.get(TrustRow, user_id),
                apply_fields=_apply,
            )

    async def purge_expired(self) -> int:
        """Bulk-deletes every trust entry past its `trusted_until` --
        same storage-hygiene role as `SQLCaptchaStore.purge_expired()`.
        `is_trusted()` already lazily deletes one expired row per read;
        this covers users nobody's checked trust for since it expired."""
        async with self._sessionmaker() as db:
            result = cast(
                CursorResult[Any],
                await db.execute(
                    delete(TrustRow).where(TrustRow.trusted_until <= datetime.now(UTC))
                ),
            )
            await db.commit()
            return result.rowcount or 0
