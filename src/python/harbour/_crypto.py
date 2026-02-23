"""Shared cryptographic helpers for JOSE key import and algorithm resolution.

Internal module — used by signer, verifier, sd_jwt, and kb_jwt.
"""

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    EllipticCurvePrivateKey,
    EllipticCurvePrivateNumbers,
    EllipticCurvePublicKey,
    EllipticCurvePublicNumbers,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from harbour.keys import (
    PrivateKey,
    PublicKeyType,
    _b64url_decode,
    keypair_to_jwk,
    p256_keypair_to_jwk,
    p256_public_key_to_jwk,
    public_key_to_jwk,
)
from joserfc.jwk import ECKey, OKPKey


def import_private_key(private_key: PrivateKey, alg: str) -> ECKey | OKPKey:
    """Import a cryptography private key into a joserfc JWK."""
    if isinstance(private_key, EllipticCurvePrivateKey):
        jwk_dict = p256_keypair_to_jwk(private_key)
        return ECKey.import_key(jwk_dict)
    elif isinstance(private_key, Ed25519PrivateKey):
        jwk_dict = keypair_to_jwk(private_key)
        return OKPKey.import_key(jwk_dict)
    raise TypeError(f"Unsupported key type: {type(private_key)}")


def import_public_key(public_key: PublicKeyType) -> ECKey | OKPKey:
    """Import a cryptography public key into a joserfc JWK."""
    if isinstance(public_key, EllipticCurvePublicKey):
        jwk_dict = p256_public_key_to_jwk(public_key)
        return ECKey.import_key(jwk_dict)
    elif isinstance(public_key, Ed25519PublicKey):
        jwk_dict = public_key_to_jwk(public_key)
        return OKPKey.import_key(jwk_dict)
    raise TypeError(f"Unsupported key type: {type(public_key)}")


def resolve_private_key_alg(private_key: PrivateKey, alg: str | None) -> str:
    """Determine the JWS algorithm from a private key type."""
    if alg is not None:
        return alg
    if isinstance(private_key, EllipticCurvePrivateKey):
        return "ES256"
    if isinstance(private_key, Ed25519PrivateKey):
        return "EdDSA"
    raise TypeError(f"Unsupported key type: {type(private_key)}")


def resolve_public_key_alg(public_key: PublicKeyType) -> str:
    """Determine the JWS algorithm from a public key type."""
    if isinstance(public_key, EllipticCurvePublicKey):
        return "ES256"
    if isinstance(public_key, Ed25519PublicKey):
        return "EdDSA"
    raise TypeError(f"Unsupported key type: {type(public_key)}")


def load_private_key(jwk_path: str) -> tuple[PrivateKey, str]:
    """Load a private key from JWK file and return (key, alg)."""
    jwk = json.loads(Path(jwk_path).read_text())

    if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
        x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
        d = int.from_bytes(_b64url_decode(jwk["d"]), "big")
        pub_nums = EllipticCurvePublicNumbers(x, y, SECP256R1())
        priv_nums = EllipticCurvePrivateNumbers(d, pub_nums)
        return priv_nums.private_key(), "ES256"
    elif jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
        d_bytes = _b64url_decode(jwk["d"])
        return Ed25519PrivateKey.from_private_bytes(d_bytes), "EdDSA"
    else:
        raise ValueError(f"Unsupported key type: {jwk.get('kty')}/{jwk.get('crv')}")


def load_public_key(jwk_path: str) -> PublicKeyType:
    """Load a public key from JWK file."""
    jwk = json.loads(Path(jwk_path).read_text())

    if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
        x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
        numbers = EllipticCurvePublicNumbers(x, y, SECP256R1())
        return numbers.public_key()
    elif jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
        x_bytes = _b64url_decode(jwk["x"])
        return Ed25519PublicKey.from_public_bytes(x_bytes)
    else:
        raise ValueError(f"Unsupported key type: {jwk.get('kty')}/{jwk.get('crv')}")
