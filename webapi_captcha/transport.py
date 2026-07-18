"""The pub/sub seam this package uses to announce `captcha_verified` --
deliberately the narrowest possible interface (`publish`/`subscribe`
only, no RPC), so any real message bus (or a host application's own
richer Transport abstraction, like discord-webapi's) satisfies it
structurally without needing to import anything from here.

`InProcessTransport` is a complete, standalone implementation -- this
package needs no other dependency to actually run. If you're using this
alongside discord-webapi, its own `discord_webapi.transport.
InProcessTransport`/`RedisTransport` already satisfy `Transport`
structurally (both implement `publish`/`subscribe` with this exact
shape) -- pass either one straight through, no adapter needed.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger("webapi_captcha.transport")

CATCH_ALL_EVENT_TYPE = "*"


class TransportError(Exception):
    """Raised for transport-level failures (a non-JSON-serializable
    payload, most commonly)."""


@dataclasses.dataclass(frozen=True)
class Event:
    """A broadcast message published over a Transport.

    `payload` must be JSON-serializable -- enforced even by the bundled
    `InProcessTransport` so behavior doesn't silently diverge once a
    deployment switches to a real message bus.
    """

    type: str
    payload: dict[str, Any]
    source: str | None = None


EventHandler = Callable[[Event], Awaitable[None]]


@runtime_checkable
class Transport(Protocol):
    """The only two verbs this package needs: broadcast an event, and
    listen for one. Any object with these two methods works -- a
    dataclass, a thin wrapper around Redis pub/sub, or a host
    application's own larger Transport abstraction that happens to
    implement (among other things) this exact shape."""

    async def publish(self, event: Event) -> None: ...

    def subscribe(self, event_type: str, handler: EventHandler) -> None: ...


def _assert_json_serializable(payload: dict[str, Any], *, context: str) -> None:
    try:
        json.dumps(payload)
    except (TypeError, ValueError) as exc:
        raise TransportError(
            f"{context} payload is not JSON-serializable: {exc}. Event payloads must "
            "stay JSON-serializable so this works identically in-process and over a "
            "real message bus."
        ) from exc


class InProcessTransport:
    """Zero-infrastructure `Transport`: bot/web (or any two parts of your
    app) share one asyncio event loop. Subscribers are a plain in-memory
    dict; `publish()` fans out via `asyncio.create_task` so one failing
    subscriber can never break the publisher or another subscriber."""

    def __init__(self, *, strict_serialization: bool = True) -> None:
        self._subscribers: dict[str, list[EventHandler]] = {}
        self._strict_serialization = strict_serialization

    async def publish(self, event: Event) -> None:
        if self._strict_serialization:
            _assert_json_serializable(event.payload, context=f"Event({event.type!r})")

        handlers = [
            *self._subscribers.get(event.type, ()),
            *self._subscribers.get(CATCH_ALL_EVENT_TYPE, ()),
        ]
        for handler in handlers:
            asyncio.create_task(self._run_handler_safely(handler, event))

    async def _run_handler_safely(self, handler: EventHandler, event: Event) -> None:
        try:
            await handler(event)
        except Exception:
            logger.exception("Unhandled error in subscriber for event type %r", event.type)

    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        self._subscribers.setdefault(event_type, []).append(handler)

    def unsubscribe(self, event_type: str, handler: EventHandler) -> None:
        handlers = self._subscribers.get(event_type)
        if handlers is not None and handler in handlers:
            handlers.remove(handler)
