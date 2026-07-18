from __future__ import annotations

from webapi_captcha.models import PendingCaptcha, VerificationRequest


class MemoryCaptchaStore:
    """Dict-backed CaptchaStore. Zero infrastructure -- the default."""

    def __init__(self) -> None:
        self._pending: dict[str, PendingCaptcha] = {}

    async def create(self, pending: PendingCaptcha) -> None:
        self._pending[pending.challenge_id] = pending

    async def get(self, challenge_id: str) -> PendingCaptcha | None:
        return self._pending.get(challenge_id)

    async def increment_attempts(self, challenge_id: str) -> int:
        pending = self._pending.get(challenge_id)
        if pending is None:
            return 0
        pending.attempts += 1
        return pending.attempts

    async def delete(self, challenge_id: str) -> None:
        self._pending.pop(challenge_id, None)


class MemoryVerificationStore:
    """Dict-backed VerificationStore. Zero infrastructure -- the default."""

    def __init__(self) -> None:
        self._requests: dict[str, VerificationRequest] = {}

    async def create(self, request: VerificationRequest) -> None:
        self._requests[request.token] = request

    async def get(self, token: str) -> VerificationRequest | None:
        return self._requests.get(token)

    async def mark_verified(self, token: str) -> None:
        request = self._requests.get(token)
        if request is not None:
            request.verified = True

    async def delete(self, token: str) -> None:
        self._requests.pop(token, None)
