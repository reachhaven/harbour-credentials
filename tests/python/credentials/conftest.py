"""Pytest fixtures for credentials module tests."""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    EllipticCurvePrivateNumbers,
    EllipticCurvePublicNumbers,
)
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
KEYS_DIR = FIXTURES_DIR / "keys"
EXAMPLES_DIR = _HARBOUR_ROOT / "examples"
GAIAX_EXAMPLES_DIR = EXAMPLES_DIR / "gaiax"
SIGNED_DIR = EXAMPLES_DIR / "signed"
GAIAX_SIGNED_DIR = GAIAX_EXAMPLES_DIR / "signed"


@pytest.fixture(scope="session")
def p256_private_key():
    """Load the test P-256 private key."""
    jwk_path = KEYS_DIR / "test-keypair-p256.json"
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


def _all_example_credentials() -> list[Path]:
    """Collect credential/receipt JSON files from examples/ and examples/gaiax/."""
    files: list[Path] = []
    if EXAMPLES_DIR.exists():
        files.extend(sorted(EXAMPLES_DIR.glob("*-credential.json")))
        files.extend(sorted(EXAMPLES_DIR.glob("*-receipt.json")))
    if GAIAX_EXAMPLES_DIR.exists():
        files.extend(sorted(GAIAX_EXAMPLES_DIR.glob("*-credential.json")))
        files.extend(sorted(GAIAX_EXAMPLES_DIR.glob("*-receipt.json")))
    return files


@pytest.fixture(
    params=_all_example_credentials(),
    ids=lambda p: (f"gaiax/{p.name}" if p.parent.name == "gaiax" else p.name),
)
def example_vc(request):
    """Parametrized fixture for each example credential."""
    return json.loads(request.param.read_text())


def _all_signed_jwts() -> list[Path]:
    """Collect pre-signed VC JWTs from signed/ dirs (excludes evidence VPs)."""
    files: list[Path] = []
    for d in [SIGNED_DIR, GAIAX_SIGNED_DIR]:
        if d.exists():
            files.extend(
                p for p in sorted(d.glob("*.jwt")) if ".evidence-vp." not in p.name
            )
    return files


@pytest.fixture(params=_all_signed_jwts())
def signed_jwt(request):
    """Parametrized fixture for each pre-signed VC JWT (excludes evidence VPs)."""
    return request.param.read_text().strip()
