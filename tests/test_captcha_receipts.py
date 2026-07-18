"""Exercises TrustTokenIssuer/TrustTokenVerifier -- the v1, deliberately
non-anonymous cross-site trust receipt. `verify()` must fail CLOSED
(return None) on every kind of ambiguity, never raise."""

from datetime import timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from webapi_captcha.receipts import TrustTokenIssuer, TrustTokenVerifier, _b64encode


def test_issue_and_verify_round_trip() -> None:
    key = Ed25519PrivateKey.generate()
    issuer = TrustTokenIssuer(key, issuer_id="site-a")
    verifier = TrustTokenVerifier({"site-a": key.public_key()})

    token = issuer.issue("visitor-42", ttl=timedelta(hours=1), purpose="checkout")
    receipt = verifier.verify(token)

    assert receipt is not None
    assert receipt.subject_id == "visitor-42"
    assert receipt.issuer_id == "site-a"
    assert receipt.purpose == "checkout"


def test_verify_rejects_unknown_issuer() -> None:
    key = Ed25519PrivateKey.generate()
    issuer = TrustTokenIssuer(key, issuer_id="site-a")
    token = issuer.issue("visitor-42", ttl=timedelta(hours=1))

    other_verifier = TrustTokenVerifier({"site-b": Ed25519PrivateKey.generate().public_key()})
    assert other_verifier.verify(token) is None


def test_verify_rejects_tampered_payload() -> None:
    key = Ed25519PrivateKey.generate()
    issuer = TrustTokenIssuer(key, issuer_id="site-a")
    verifier = TrustTokenVerifier({"site-a": key.public_key()})
    token = issuer.issue("visitor-42", ttl=timedelta(hours=1))

    payload_part, signature_part = token.split(".")
    tampered = payload_part[:-4] + "xxxx" + "." + signature_part
    assert verifier.verify(tampered) is None


def test_verify_rejects_expired_receipt() -> None:
    key = Ed25519PrivateKey.generate()
    issuer = TrustTokenIssuer(key, issuer_id="site-a")
    verifier = TrustTokenVerifier({"site-a": key.public_key()})

    token = issuer.issue("visitor-42", ttl=timedelta(seconds=-1))
    assert verifier.verify(token) is None


def test_verify_rejects_malformed_token_never_raises() -> None:
    key = Ed25519PrivateKey.generate()
    verifier = TrustTokenVerifier({"site-a": key.public_key()})

    for garbage in ("", "not-a-token", "a.b.c", "onlyonepart", ".", "abc.def", "🙂.🙃"):
        assert verifier.verify(garbage) is None


def test_verify_rejects_valid_base64_but_invalid_json() -> None:
    key = Ed25519PrivateKey.generate()
    verifier = TrustTokenVerifier({"site-a": key.public_key()})

    # Sign garbage bytes with the same key -- valid signature, unusable payload.
    garbage_payload = b"not json at all"
    signature = key.sign(garbage_payload)
    token = f"{_b64encode(garbage_payload)}.{_b64encode(signature)}"
    assert verifier.verify(token) is None
