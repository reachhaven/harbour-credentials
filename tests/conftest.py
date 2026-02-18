"""Shared fixtures for harbour-credentials JOSE tests."""

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateNumbers,
    EllipticCurvePublicNumbers,
    SECP256R1,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from harbour.jose.keys import p256_public_key_to_did_key, public_key_to_did_key

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---------------------------------------------------------------------------
# Ed25519 fixtures
# ---------------------------------------------------------------------------


def _load_ed25519_keypair():
    """Load the committed Ed25519 test keypair from fixtures."""
    jwk_path = FIXTURES_DIR / "test-keypair.json"
    with open(jwk_path) as f:
        jwk = json.load(f)
    raw_private = _b64url_decode(jwk["d"])
    private_key = Ed25519PrivateKey.from_private_bytes(raw_private)
    return private_key, private_key.public_key()


@pytest.fixture(scope="session")
def ed25519_keypair():
    """Ed25519 key pair loaded from the committed test fixture."""
    return _load_ed25519_keypair()


@pytest.fixture(scope="session")
def ed25519_private_key(ed25519_keypair):
    return ed25519_keypair[0]


@pytest.fixture(scope="session")
def ed25519_public_key(ed25519_keypair):
    return ed25519_keypair[1]


# Backwards-compatible aliases for legacy tests
@pytest.fixture(scope="session")
def private_key(ed25519_keypair):
    return ed25519_keypair[0]


@pytest.fixture(scope="session")
def public_key(ed25519_keypair):
    return ed25519_keypair[1]


@pytest.fixture(scope="session")
def did_key_vm(public_key):
    """A did:key verification method ID (did:key:z6Mk...#z6Mk...)."""
    did = public_key_to_did_key(public_key)
    fragment = did.split(":")[-1]
    return f"{did}#{fragment}"


# ---------------------------------------------------------------------------
# P-256 fixtures
# ---------------------------------------------------------------------------


def _load_p256_keypair():
    """Load the committed P-256 test keypair from fixtures."""
    jwk_path = FIXTURES_DIR / "test-keypair-p256.json"
    with open(jwk_path) as f:
        jwk = json.load(f)
    x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
    d = int.from_bytes(_b64url_decode(jwk["d"]), "big")
    pub_numbers = EllipticCurvePublicNumbers(x, y, SECP256R1())
    priv_numbers = EllipticCurvePrivateNumbers(d, pub_numbers)
    private_key = priv_numbers.private_key()
    return private_key, private_key.public_key()


@pytest.fixture(scope="session")
def p256_keypair():
    """P-256 key pair loaded from the committed test fixture."""
    return _load_p256_keypair()


@pytest.fixture(scope="session")
def p256_private_key(p256_keypair):
    return p256_keypair[0]


@pytest.fixture(scope="session")
def p256_public_key(p256_keypair):
    return p256_keypair[1]


@pytest.fixture(scope="session")
def p256_did_key_vm(p256_public_key):
    """A did:key verification method ID for P-256 (did:key:zDn...#zDn...)."""
    did = p256_public_key_to_did_key(p256_public_key)
    fragment = did.split(":")[-1]
    return f"{did}#{fragment}"


# ---------------------------------------------------------------------------
# Sample credentials
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_vc():
    """A minimal unsigned VC dict (W3C VC Data Model v2 structure)."""
    vc_path = FIXTURES_DIR / "sample-vc.json"
    with open(vc_path) as f:
        return json.load(f)


@pytest.fixture()
def sample_vp(sample_vc):
    """A minimal unsigned VP dict wrapping the sample VC."""
    return {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiablePresentation"],
        "verifiableCredential": [sample_vc],
    }
