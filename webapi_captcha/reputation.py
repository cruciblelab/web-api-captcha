"""IP reputation -- the pluggable "is this connection suspicious"
question `AdaptiveCaptchaGate` asks before deciding whether to escalate
to a visible captcha.

This library ships no reputation *database* or *service* of its own --
same principle as everywhere else here (no opinion on which captcha
backend, which OAuth provider, which reputation source you'd trust).
`IPReputationChecker` is the seam: implement it against your own
blocklist, a paid reputation API (IPQualityScore, AbuseIPDB, your CDN's
own signal, ...), or nothing at all.

`StaticBlocklistReputationChecker` is the one concrete implementation
shipped here, and it's deliberately named for what it actually is: a
plain in-memory IP/CIDR blocklist, not a reputation service. It answers
"is this IP one I've already decided to block," nothing more -- no
scoring, no third-party data, no claim of detecting anything on its own.
"""

from __future__ import annotations

import ipaddress
from typing import Protocol


class IPReputationChecker(Protocol):
    """Answers one question: does this IP look suspicious enough to
    escalate to a visible captcha? Implement this against whatever you
    actually trust -- a blocklist, a paid reputation API, your own abuse
    history. `AdaptiveCaptchaGate` calls this once per verification link,
    the first time it's opened."""

    async def is_suspicious(self, ip: str) -> bool: ...


class StaticBlocklistReputationChecker:
    """The simplest possible `IPReputationChecker`: a plain set of
    blocked IPs and/or CIDR ranges you maintain yourself. Not a
    reputation *service* -- there's no scoring, no external data, no
    attempt to guess whether an IP is "probably bad." It only knows what
    you've told it. Good for "block these specific IPs I've identified
    myself"; wire in an actual reputation source for anything more.
    """

    def __init__(
        self,
        blocked_ips: set[str] | None = None,
        blocked_networks: list[str] | None = None,
    ) -> None:
        self._blocked_ips = set(blocked_ips or ())
        self._blocked_networks = [
            ipaddress.ip_network(network) for network in (blocked_networks or ())
        ]

    async def is_suspicious(self, ip: str) -> bool:
        if ip in self._blocked_ips:
            return True
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(address in network for network in self._blocked_networks)

    def block(self, ip: str) -> None:
        self._blocked_ips.add(ip)

    def unblock(self, ip: str) -> None:
        self._blocked_ips.discard(ip)
