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


# -- subject/purpose binding (expected_subject_id / required_purpose) --


def test_verify_accepts_a_matching_expected_subject_id() -> None:
    key = Ed25519PrivateKey.generate()
    issuer = TrustTokenIssuer(key, issuer_id="site-a")
    verifier = TrustTokenVerifier({"site-a": key.public_key()})
    token = issuer.issue("visitor-42", ttl=timedelta(hours=1))

    receipt = verifier.verify(token, expected_subject_id="visitor-42")

    assert receipt is not None
    assert receipt.subject_id == "visitor-42"


def test_verify_rejects_a_mismatched_expected_subject_id() -> None:
    key = Ed25519PrivateKey.generate()
    issuer = TrustTokenIssuer(key, issuer_id="site-a")
    verifier = TrustTokenVerifier({"site-a": key.public_key()})
    token = issuer.issue("visitor-42", ttl=timedelta(hours=1))

    assert verifier.verify(token, expected_subject_id="someone-else") is None


def test_verify_accepts_a_matching_required_purpose() -> None:
    key = Ed25519PrivateKey.generate()
    issuer = TrustTokenIssuer(key, issuer_id="site-a")
    verifier = TrustTokenVerifier({"site-a": key.public_key()})
    token = issuer.issue("visitor-42", ttl=timedelta(hours=1), purpose="checkout")

    receipt = verifier.verify(token, required_purpose="checkout")

    assert receipt is not None


def test_verify_rejects_a_mismatched_required_purpose() -> None:
    key = Ed25519PrivateKey.generate()
    issuer = TrustTokenIssuer(key, issuer_id="site-a")
    verifier = TrustTokenVerifier({"site-a": key.public_key()})
    token = issuer.issue("visitor-42", ttl=timedelta(hours=1), purpose="checkout")

    assert verifier.verify(token, required_purpose="login") is None


def test_verify_rejects_required_purpose_when_receipt_has_none() -> None:
    key = Ed25519PrivateKey.generate()
    issuer = TrustTokenIssuer(key, issuer_id="site-a")
    verifier = TrustTokenVerifier({"site-a": key.public_key()})
    token = issuer.issue("visitor-42", ttl=timedelta(hours=1))  # no purpose

    assert verifier.verify(token, required_purpose="checkout") is None


def test_verify_with_no_binding_params_accepts_any_subject_and_purpose() -> None:
    """Regression guard: omitting both stays today's unbounded behavior."""
    key = Ed25519PrivateKey.generate()
    issuer = TrustTokenIssuer(key, issuer_id="site-a")
    verifier = TrustTokenVerifier({"site-a": key.public_key()})
    token = issuer.issue("visitor-42", ttl=timedelta(hours=1), purpose="checkout")

    assert verifier.verify(token) is not None
