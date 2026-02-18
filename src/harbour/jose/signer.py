"""Sign Verifiable Credentials and Presentations as VC-JOSE-COSE compact JWS.

Replaces the legacy Ed25519Signature2018 detached-JWS format with standard
compact JWS per W3C VC-JOSE-COSE and ADR-001/003.
"""

import json
import warnings

from joserfc import jws
from joserfc.jwk import ECKey, OKPKey

from harbour.jose.keys import (
    PrivateKey,
    keypair_to_jwk,
    p256_keypair_to_jwk,
)

# Legacy imports for backwards compatibility
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey


def sign_vc_jose(
    vc: dict,
    private_key: PrivateKey,
    *,
    alg: str | None = None,
    kid: str | None = None,
    x5c: list[str] | None = None,
) -> str:
    """Sign a VC as VC-JOSE-COSE compact JWS.

    Args:
        vc: The Verifiable Credential JSON-LD dict.
        private_key: ES256 (P-256) or EdDSA (Ed25519) private key.
        alg: Algorithm override. Default: ES256 for P-256, EdDSA for Ed25519.
        kid: Key ID (DID verification method) for the JOSE header.
        x5c: X.509 certificate chain (base64 DER) for the JOSE header.

    Returns:
        Compact JWS string (header.payload.signature).
    """
    alg = _resolve_alg(private_key, alg)
    header = _build_header(alg, typ="vc+ld+jwt", kid=kid, x5c=x5c)
    payload = json.dumps(vc, ensure_ascii=False).encode("utf-8")
    key = _import_private_key(private_key, alg)
    return jws.serialize_compact(header, payload, key, algorithms=[alg])


def sign_vp_jose(
    vp: dict,
    private_key: PrivateKey,
    *,
    alg: str | None = None,
    kid: str | None = None,
    nonce: str | None = None,
    audience: str | None = None,
) -> str:
    """Sign a VP as VC-JOSE-COSE compact JWS.

    Args:
        vp: The Verifiable Presentation JSON-LD dict.
        private_key: ES256 (P-256) or EdDSA (Ed25519) private key.
        alg: Algorithm override. Default: ES256 for P-256, EdDSA for Ed25519.
        kid: Key ID (DID verification method) for the JOSE header.
        nonce: Challenge nonce for replay protection.
        audience: Intended audience (verifier DID or URL).

    Returns:
        Compact JWS string (header.payload.signature).
    """
    alg = _resolve_alg(private_key, alg)
    header = _build_header(alg, typ="vp+ld+jwt", kid=kid)

    # Add nonce and audience to the VP payload (not header)
    vp_payload = dict(vp)
    if nonce is not None:
        vp_payload["nonce"] = nonce
    if audience is not None:
        vp_payload["aud"] = audience

    payload = json.dumps(vp_payload, ensure_ascii=False).encode("utf-8")
    key = _import_private_key(private_key, alg)
    return jws.serialize_compact(header, payload, key, algorithms=[alg])


# ---------------------------------------------------------------------------
# Legacy API (deprecated)
# ---------------------------------------------------------------------------


def sign_vc(
    vc: dict,
    private_key: Ed25519PrivateKey,
    verification_method: str,
) -> dict:
    """Sign a VC with Ed25519Signature2018 detached JWS proof.

    .. deprecated:: 0.2.0
        Use :func:`sign_vc_jose` instead.
    """
    import copy
    from datetime import datetime, timezone

    warnings.warn(
        "sign_vc() is deprecated. Use sign_vc_jose() for standard VC-JOSE-COSE.",
        DeprecationWarning,
        stacklevel=2,
    )

    signed = copy.deepcopy(vc)
    signed.pop("proof", None)

    payload = _canonicalize(signed)
    jwk_dict = keypair_to_jwk(private_key)
    key = OKPKey.import_key(jwk_dict)
    protected = {"alg": "EdDSA", "b64": False, "crit": ["b64"]}
    token = jws.serialize_compact(protected, payload, key, algorithms=["EdDSA"])

    parts = token.split(".")
    detached_jws = f"{parts[0]}..{parts[2]}"

    proof = {
        "type": "Ed25519Signature2018",
        "proofPurpose": "assertionMethod",
        "verificationMethod": verification_method,
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "jws": detached_jws,
    }

    signed["proof"] = proof
    return signed


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_alg(private_key: PrivateKey, alg: str | None) -> str:
    """Determine the JWS algorithm from the key type."""
    if alg is not None:
        return alg
    if isinstance(private_key, EllipticCurvePrivateKey):
        return "ES256"
    if isinstance(private_key, Ed25519PrivateKey):
        return "EdDSA"
    raise TypeError(f"Unsupported key type: {type(private_key)}")


def _build_header(
    alg: str,
    typ: str,
    kid: str | None = None,
    x5c: list[str] | None = None,
) -> dict:
    """Build a JOSE protected header."""
    header = {"alg": alg, "typ": typ}
    if kid is not None:
        header["kid"] = kid
    if x5c is not None:
        header["x5c"] = x5c
    return header


def _import_private_key(private_key: PrivateKey, alg: str):
    """Import a cryptography private key into a joserfc JWK."""
    if isinstance(private_key, EllipticCurvePrivateKey):
        jwk_dict = p256_keypair_to_jwk(private_key)
        return ECKey.import_key(jwk_dict)
    elif isinstance(private_key, Ed25519PrivateKey):
        jwk_dict = keypair_to_jwk(private_key)
        return OKPKey.import_key(jwk_dict)
    raise TypeError(f"Unsupported key type: {type(private_key)}")


def _canonicalize(obj: dict) -> bytes:
    """Canonical JSON serialization (legacy, used only by sign_vc)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
