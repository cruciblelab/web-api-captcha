"""Proof-of-work captcha -- the invisible, low-cost layer (think of a
Cloudflare-Turnstile-style silent check rather than a puzzle the user
solves).

The user never sees or does anything: when the page loads (or a form is
submitted), the frontend runs a small hashcash-style search in the
background and returns the answer. The asymmetry is the whole point --
the client does ~2^difficulty hashes, the server verifies with **exactly
one** hash. That makes it genuinely cheap on the server side (no image
rendering, no IP-reputation lookups, no third-party call), while making
mass automation pay a real per-request CPU cost.

What it does and doesn't do (be honest with yourself when you deploy it):
- It raises the cost of doing something *many times*. A single determined
  bot still solves it -- it's a speed bump against volume, not a human
  test.
- It proves "someone spent CPU," never "a human did this." Layer it with
  `AccountMatchCheck` (identity) and/or an interactive challenge if you
  need more. The intended design is: run this silently first, and only
  fall back to a visible captcha for requests you're still unsure about.

Needs no extra dependency (stdlib `hashlib`) -- unlike the image
providers, this works without `discord-webapi[captcha]`.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from webapi_captcha._shared import check_pending_challenge
from webapi_captcha.base import CaptchaStore
from webapi_captcha.models import CaptchaChallenge, PendingCaptcha


def _leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        # count leading zeros within this byte, then stop
        bits += 8 - byte.bit_length()
        break
    return bits


class LoadAdaptiveDifficulty:
    """Scales PoW difficulty with the rate of challenges being issued --
    the mCaptcha pattern: a quiet site stays at `base_difficulty` (cheap,
    near-instant for real visitors), a traffic spike/DDoS pushes difficulty
    up towards `max_difficulty` (each extra bit doubles the client's
    expected work), and it relaxes again once the spike passes. Server
    cost is unaffected either way -- verification is always one hash.

    Pass an instance as `ProofOfWorkProvider(..., difficulty=LoadAdaptiveDifficulty())`.
    Call it (or let the provider call it) once per issued challenge; it
    keeps its own sliding window, no external metrics/store needed.
    """

    def __init__(
        self,
        *,
        base_difficulty: int = 16,
        max_difficulty: int = 24,
        window_seconds: float = 10.0,
        requests_per_second_at_max: float = 20.0,
    ) -> None:
        if max_difficulty < base_difficulty:
            raise ValueError("max_difficulty must be >= base_difficulty")
        self.base_difficulty = base_difficulty
        self.max_difficulty = max_difficulty
        self.window_seconds = window_seconds
        self.requests_per_second_at_max = requests_per_second_at_max
        self._issued_at: deque[float] = deque()

    def __call__(self) -> int:
        now = time.monotonic()
        self._issued_at.append(now)
        cutoff = now - self.window_seconds
        while self._issued_at and self._issued_at[0] < cutoff:
            self._issued_at.popleft()

        rate = len(self._issued_at) / self.window_seconds
        load_fraction = min(1.0, rate / self.requests_per_second_at_max)
        span = self.max_difficulty - self.base_difficulty
        return self.base_difficulty + round(load_fraction * span)


class ProofOfWorkProvider:
    """`CaptchaProvider` whose "challenge" is: find a `nonce` such that
    `sha256(f"{prefix}{nonce}")` has at least `difficulty` leading zero
    bits. `difficulty` is the single cost knob -- each extra bit doubles
    the client's expected work (and does nothing to the server's, which is
    always one hash). A "cheap" tier might be ~12-16 bits (tens of ms of
    JS); a "stricter" tier ~18-22 bits. Server cost is identical either
    way -- this is the low-server-cost option you asked for.
    """

    kind = "pow"

    def __init__(
        self,
        store: CaptchaStore,
        *,
        difficulty: int | Callable[[], int] = 16,
        ttl: timedelta = timedelta(minutes=10),
        max_attempts: int = 50,
    ) -> None:
        if isinstance(difficulty, int) and difficulty < 1:
            raise ValueError("difficulty must be >= 1")
        self.store = store
        self.difficulty = difficulty
        self.ttl = ttl
        # A PoW answer isn't a single secret to guess -- brute-forcing the
        # verify endpoint gains nothing (you'd still have to do the work).
        # So max_attempts is generous; it only bounds pathological retries.
        self.max_attempts = max_attempts

    async def issue(self) -> CaptchaChallenge:
        prefix = secrets.token_hex(8)
        challenge_id = secrets.token_urlsafe(16)
        now = datetime.now(UTC)
        difficulty = self.difficulty() if callable(self.difficulty) else self.difficulty
        await self.store.create(
            PendingCaptcha(
                challenge_id=challenge_id,
                kind=self.kind,
                answer=json.dumps({"prefix": prefix, "difficulty": difficulty}),
                created_at=now,
                expires_at=now + self.ttl,
            )
        )
        return CaptchaChallenge(
            challenge_id=challenge_id,
            kind=self.kind,
            prompt="(automatic -- no user action required)",
            params={
                "algorithm": "sha256-leading-zero-bits",
                "prefix": prefix,
                "difficulty": difficulty,
            },
            expires_at=now + self.ttl,
        )

    async def verify(self, challenge_id: str, response: str) -> bool:
        """`response` is the nonce the client found. Recomputes the single
        hash and checks it clears the stored difficulty."""

        def _verifier(pending: PendingCaptcha) -> bool:
            spec = json.loads(pending.answer)
            digest = hashlib.sha256(f"{spec['prefix']}{response}".encode()).digest()
            return _leading_zero_bits(digest) >= int(spec["difficulty"])

        return await check_pending_challenge(
            self.store, challenge_id, max_attempts=self.max_attempts, verifier=_verifier
        )
