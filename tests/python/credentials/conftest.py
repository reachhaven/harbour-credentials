"""Pytest fixtures for credentials module tests."""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    EllipticCurvePrivateNumbers,
    EllipticCurvePublicNumbers,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from harbour.keys import p256_public_key_to_did_key


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return __import__("base64").urlsafe_b64decode(s)


# Find fixtures and examples directories
_TEST_DIR = Path(__file__).resolve().parent
_HARBOUR_ROOT = _TEST_DIR
while (
    _HARBOUR_ROOT.name != "harbour-credentials"
    and _HARBOUR_ROOT != _HARBOUR_ROOT.parent
):
    _HARBOUR_ROOT = _HARBOUR_ROOT.parent

FIXTURES_DIR = _HARBOUR_ROOT / "tests" / "fixtures"
EXAMPLES_DIR = _HARBOUR_ROOT.parent.parent / "examples"
SIGNED_DIR = EXAMPLES_DIR / "signed"


@pytest.fixture(scope="session")
def p256_private_key():
    """Load the test P-256 private key."""
    jwk_path = FIXTURES_DIR / "test-keypair-p256.json"
    jwk = json.loads(jwk_path.read_text())
    x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
    d = int.from_bytes(_b64url_decode(jwk["d"]), "big")
    pub_numbers = EllipticCurvePublicNumbers(x, y, SECP256R1())
    priv_numbers = EllipticCurvePrivateNumbers(d, pub_numbers)
    return priv_numbers.private_key()


@pytest.fixture(scope="session")
def p256_public_key(p256_private_key):
    """Get the public key from the test private key."""
    return p256_private_key.public_key()


@pytest.fixture(scope="session")
def p256_did_key_vm(p256_public_key):
    """Get the DID:key verification method for the test key."""
    did = p256_public_key_to_did_key(p256_public_key)
    return f"{did}#{did.split(':')[-1]}"


@pytest.fixture(
    params=list(EXAMPLES_DIR.glob("simpulseid-*.json")) if EXAMPLES_DIR.exists() else []
)
def example_vc(request):
    """Parametrized fixture for each example credential."""
    return json.loads(request.param.read_text())


# Legacy Ed25519 fixtures for backwards compatibility tests
@pytest.fixture(scope="session")
def private_key():
    """Generate an Ed25519 private key for legacy tests."""
    return Ed25519PrivateKey.generate()


@pytest.fixture(scope="session")
def public_key(private_key):
    """Get the Ed25519 public key."""
    return private_key.public_key()


@pytest.fixture(scope="session")
def did_key_vm(private_key):
    """Generate DID:key verification method for Ed25519 key."""
    from harbour.keys import public_key_to_did_key

    pub = private_key.public_key()
    did = public_key_to_did_key(pub)
    return f"{did}#{did.split(':')[-1]}"


@pytest.fixture(params=list(SIGNED_DIR.glob("*.jwt")) if SIGNED_DIR.exists() else [])
def signed_jwt(request):
    """Parametrized fixture for each pre-signed JWT."""
    return request.param.read_text().strip()
