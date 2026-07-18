"""Exercises `StaticBlocklistReputationChecker` -- the one concrete
`IPReputationChecker` shipped here (a plain blocklist, not a reputation
service)."""

from webapi_captcha.reputation import StaticBlocklistReputationChecker


async def test_blocked_exact_ip_is_suspicious() -> None:
    checker = StaticBlocklistReputationChecker(blocked_ips={"1.2.3.4"})

    assert await checker.is_suspicious("1.2.3.4") is True


async def test_unlisted_ip_is_not_suspicious() -> None:
    checker = StaticBlocklistReputationChecker(blocked_ips={"1.2.3.4"})

    assert await checker.is_suspicious("5.6.7.8") is False


async def test_blocked_cidr_range_matches() -> None:
    checker = StaticBlocklistReputationChecker(blocked_networks=["10.0.0.0/24"])

    assert await checker.is_suspicious("10.0.0.42") is True
    assert await checker.is_suspicious("10.0.1.1") is False


async def test_malformed_ip_is_not_suspicious_rather_than_erroring() -> None:
    checker = StaticBlocklistReputationChecker(blocked_networks=["10.0.0.0/24"])

    assert await checker.is_suspicious("not-an-ip") is False


async def test_block_and_unblock_update_the_list_live() -> None:
    checker = StaticBlocklistReputationChecker()

    assert await checker.is_suspicious("9.9.9.9") is False

    checker.block("9.9.9.9")
    assert await checker.is_suspicious("9.9.9.9") is True

    checker.unblock("9.9.9.9")
    assert await checker.is_suspicious("9.9.9.9") is False
