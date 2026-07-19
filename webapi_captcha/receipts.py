"""A v1, deliberately NON-anonymous cross-site trust receipt --
"solve a captcha on site A, be recognized as already-verified on site B"
-- for sites that have chosen to mutually trust each other.

**Read this before using it.** This is explicitly NOT the anonymous,
unlinkable proof-of-humanity that IETF Privacy Pass (RFC 9576/9577/9578,
built on RSA Blind Signatures, RFC 9474) provides. No mature, audited
Python implementation of that blind-signature scheme exists today, and
rolling one by hand for a "should be maximally secure" primitive would
be exactly the wrong way to build it. This module instead uses ONLY an
already-audited primitive already in this package's dependency tree
(`cryptography`, already used for `Fernet` in `webapi_captcha.sql`) --
Ed25519 signatures, not blind signatures. `TrustReceipt.subject_id` is
opaque but LINKABLE: two different sites that both see the same
`subject_id` can correlate that it's the same visitor across them. A
real anonymous "v2" would need a properly vetted blind-signature library
or expert cryptographic review before ever shipping -- not attempted
here.

**Why Ed25519, not Fernet.** Fernet is symmetric -- every site in a
trust relationship would need to share the SAME secret key, and anyone
holding that key could forge receipts, not just verify them. That's the
wrong shape for N independently-run sites that want to trust an
*issuer's claims* without being able to mint fake ones themselves.
Ed25519 is asymmetric: one issuer holds an `Ed25519PrivateKey` and signs;
any number of verifiers hold only that issuer's `Ed25519PublicKey` and
can verify without ever being able to forge. A `TrustTokenVerifier` can
be configured to trust multiple issuers' public keys -- this is the
literal mechanism for "which sites do I choose to trust," and it directly
answers the Sybil concern of a rogue site vouching for itself: it can
only ever vouch for its OWN issuer identity, and nobody is forced to add
that identity to their trusted set. Already available with zero new
dependency (`cryptography.hazmat.primitives.asymmetric.ed25519`), and,
unlike RSA/ECDSA, has no parameter choices (key size, curve, padding) to
get wrong -- an appropriately conservative choice for a deliberately
conservative v1.

**Fails CLOSED, unlike almost everything else in this package.** Every
other check here (`IPReputationChecker`, `SignalScoreCheck`,
`RepeatedMovementCheck`, every `RiskSignal`) fails OPEN on purpose: those
are soft heuristics, and blocking a real human on a false positive is
worse than occasionally letting a bot through. A trust receipt is
different -- it's the thing GRANTING trust outright, the same tier of
consequence as `TrustStore.is_trusted() == True` -- so `verify()` treats
any ambiguity whatsoever (bad signature, unknown issuer, expired,
malformed input, an exception during parsing) as "not trusted," never as
a best-effort guess in the receipt's favor.

**Not solved here, and not this module's job:** how the token actually
travels from site A's browser session to site B. Third-party cookies are
being phased out industry-wide; carrying this across sites needs the
consuming application's own mechanism (a redirect handoff, a same-site-
set arrangement, a server-to-server call). This module ships only the
issue/verify primitives and (see `webapi_captcha.adaptive`) the
integration seam -- not a transport.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel


class TrustReceipt(BaseModel):
    """A signed claim: `subject_id` was verified human by `issuer_id`,
    valid until `expires_at`. See the module docstring -- `subject_id`
    is opaque but NOT anonymous/unlinkable."""

    subject_id: str
    issuer_id: str
    issued_at: datetime
    expires_at: datetime
    purpose: str | None = None


def _canonical_json(receipt: TrustReceipt) -> bytes:
    # Sorted keys, no extra whitespace -- both sides must derive the
    # exact same bytes from the same logical receipt for the signature
    # to verify, regardless of dict ordering.
    return json.dumps(
        receipt.model_dump(mode="json"), separators=(",", ":"), sort_keys=True
    ).encode()


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


class TrustTokenIssuer:
    """Signs `TrustReceipt`s with one Ed25519 private key. One issuer
    per identity you want relying sites to recognize -- e.g. one key per
    site/organization, not one key per user."""

    def __init__(self, private_key: Ed25519PrivateKey, *, issuer_id: str) -> None:
        self.private_key = private_key
        self.issuer_id = issuer_id

    def issue(self, subject_id: str, *, ttl: timedelta, purpose: str | None = None) -> str:
        """Returns an opaque, self-contained signed token string --
        `base64url(payload).base64url(signature)`. JSON, not a compact
        binary framing: this receipt is a handful of small fields, the
        crypto already forces canonicalization work regardless of
        wire format, and plain JSON keeps the payload debuggable/loggable
        (minus the signature) without a separate schema/codec."""
        now = datetime.now(UTC)
        receipt = TrustReceipt(
            subject_id=subject_id,
            issuer_id=self.issuer_id,
            issued_at=now,
            expires_at=now + ttl,
            purpose=purpose,
        )
        payload = _canonical_json(receipt)
        signature = self.private_key.sign(payload)
        return f"{_b64encode(payload)}.{_b64encode(signature)}"


class TrustTokenVerifier:
    """Verifies tokens from `TrustTokenIssuer` against a configured set
    of trusted issuers. **Fails closed** -- see the module docstring for
    why this is a deliberate exception to this package's usual fail-open
    posture. `verify()` never raises; any problem returns `None`."""

    def __init__(self, trusted_issuers: dict[str, Ed25519PublicKey]) -> None:
        self.trusted_issuers = dict(trusted_issuers)

    def verify(
        self,
        token: str,
        *,
        expected_subject_id: str | None = None,
        required_purpose: str | None = None,
    ) -> TrustReceipt | None:
        """`expected_subject_id`/`required_purpose`: optional binding
        checks, both `None` (no binding at all) by default -- see the
        module docstring's honest limitation about this. Without them, a
        valid receipt for ANY `subject_id` from a trusted issuer is
        accepted; the caller is then responsible for making sure the
        token it handed in actually belongs to the current visitor (e.g.
        it extracted the token from that visitor's own cookie/session).
        Pass `expected_subject_id=` (the local id you believe this token
        should belong to) and/or `required_purpose=` to have `verify()`
        enforce that itself instead -- a mismatch on either is treated
        exactly like every other failure mode here: fails closed,
        returns `None`, never raises."""
        try:
            payload_part, signature_part = token.split(".")
            payload = _b64decode(payload_part)
            signature = _b64decode(signature_part)
            receipt = TrustReceipt.model_validate_json(payload)

            public_key = self.trusted_issuers.get(receipt.issuer_id)
            if public_key is None:
                return None
            public_key.verify(signature, payload)

            if datetime.now(UTC) > receipt.expires_at:
                return None
            if expected_subject_id is not None and receipt.subject_id != expected_subject_id:
                return None
            if required_purpose is not None and receipt.purpose != required_purpose:
                return None
            return receipt
        except Exception:  # noqa: BLE001
            # Deliberately broad and deliberately fail-CLOSED (see class
            # docstring) -- any malformed input, decode error, validation
            # failure, or bad signature must resolve to "not trusted",
            # never propagate as a crash a caller might mishandle.
            return None
