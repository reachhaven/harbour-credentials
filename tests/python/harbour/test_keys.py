"""Tests for Ed25519 and P-256 key generation and encoding."""

import base64

from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from harbour.keys import (
    generate_ed25519_keypair,
    generate_p256_keypair,
    keypair_to_jwk,
    p256_keypair_to_jwk,
    p256_public_key_to_did_key,
    p256_public_key_to_jwk,
    p256_public_key_to_multibase,
    public_key_to_did_key,
    public_key_to_multibase,
)

# ---------------------------------------------------------------------------
# Ed25519
# ---------------------------------------------------------------------------


def test_generate_ed25519_keypair():
    private_key, public_key = generate_ed25519_keypair()
    assert isinstance(private_key, Ed25519PrivateKey)
    assert isinstance(public_key, Ed25519PublicKey)


def test_ed25519_multibase_encoding(public_key):
    mb = public_key_to_multibase(public_key)
    assert mb.startswith("z6Mk"), f"Expected z6Mk... prefix, got {mb[:8]}"
    assert len(mb) > 40


def test_ed25519_multibase_deterministic(public_key):
    mb1 = public_key_to_multibase(public_key)
    mb2 = public_key_to_multibase(public_key)
    assert mb1 == mb2


def test_ed25519_did_key_format(public_key):
    did = public_key_to_did_key(public_key)
    assert did.startswith("did:key:z6Mk")


def test_ed25519_jwk_roundtrip(private_key, public_key):
    jwk = keypair_to_jwk(private_key)
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == "Ed25519"
    assert "x" in jwk
    assert "d" in jwk

    x_bytes = base64.urlsafe_b64decode(jwk["x"] + "==")
    reimported = Ed25519PublicKey.from_public_bytes(x_bytes)
    assert reimported.public_bytes(
        Encoding.Raw, PublicFormat.Raw
    ) == public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


# ---------------------------------------------------------------------------
# P-256
# ---------------------------------------------------------------------------


def test_generate_p256_keypair():
    private_key, public_key = generate_p256_keypair()
    assert isinstance(private_key, EllipticCurvePrivateKey)
    assert isinstance(public_key, EllipticCurvePublicKey)


def test_p256_jwk_has_correct_fields(p256_private_key):
    jwk = p256_keypair_to_jwk(p256_private_key)
    assert jwk["kty"] == "EC"
    assert jwk["crv"] == "P-256"
    assert "x" in jwk
    assert "y" in jwk
    assert "d" in jwk


def test_p256_public_jwk_no_private(p256_public_key):
    jwk = p256_public_key_to_jwk(p256_public_key)
    assert jwk["kty"] == "EC"
    assert jwk["crv"] == "P-256"
    assert "x" in jwk
    assert "y" in jwk
    assert "d" not in jwk


def test_p256_jwk_roundtrip(p256_private_key, p256_public_key):
    """JWK export and re-import yields the same public key coordinates."""
    jwk = p256_keypair_to_jwk(p256_private_key)
    pub_numbers = p256_public_key.public_numbers()
    x_bytes = base64.urlsafe_b64decode(jwk["x"] + "==")
    y_bytes = base64.urlsafe_b64decode(jwk["y"] + "==")
    assert int.from_bytes(x_bytes, "big") == pub_numbers.x
    assert int.from_bytes(y_bytes, "big") == pub_numbers.y


def test_p256_multibase_encoding(p256_public_key):
    mb = p256_public_key_to_multibase(p256_public_key)
    assert mb.startswith("zDn"), f"Expected zDn... prefix, got {mb[:8]}"
    assert len(mb) > 40


def test_p256_multibase_deterministic(p256_public_key):
    mb1 = p256_public_key_to_multibase(p256_public_key)
    mb2 = p256_public_key_to_multibase(p256_public_key)
    assert mb1 == mb2


def test_p256_did_key_format(p256_public_key):
    did = p256_public_key_to_did_key(p256_public_key)
    assert did.startswith("did:key:zDn")
