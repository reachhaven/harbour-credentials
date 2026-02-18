"""Key Binding JWT (KB-JWT) for SD-JWT-VC presentation.

Supports OIDC4VP transaction_data binding per spec:
the holder creates a KB-JWT that includes transaction_data_hashes.
"""

import base64
import hashlib
import json
import time

from joserfc import jws

from harbour.jose.keys import PrivateKey, PublicKeyType
from harbour.jose.signer import _import_private_key, _resolve_alg
from harbour.jose.verifier import VerificationError, _import_public_key, _alg_for_key

SD_JWT_SEPARATOR = "~"


def create_kb_jwt(
    sd_jwt: str,
    holder_private_key: PrivateKey,
    *,
    nonce: str,
    audience: str,
    transaction_data: list[str] | None = None,
) -> str:
    """Create a Key Binding JWT for SD-JWT-VC presentation.

    Appends the KB-JWT to the SD-JWT string (after the trailing ~).

    Args:
        sd_jwt: The SD-JWT compact string (ending with ~).
        holder_private_key: Holder's private key.
        nonce: Verifier-provided nonce for replay protection.
        audience: Verifier identifier (DID or URL).
        transaction_data: Optional list of transaction data strings to bind.

    Returns:
        Complete SD-JWT-VC + KB-JWT string.
    """
    alg = _resolve_alg(holder_private_key, None)

    # Compute sd_hash (SHA-256 of the issuer-jwt part)
    issuer_jwt = sd_jwt.split(SD_JWT_SEPARATOR)[0]
    sd_hash = (
        base64.urlsafe_b64encode(
            hashlib.sha256(issuer_jwt.encode("ascii")).digest()
        )
        .rstrip(b"=")
        .decode()
    )

    # Build KB-JWT payload
    kb_payload: dict = {
        "nonce": nonce,
        "aud": audience,
        "iat": int(time.time()),
        "sd_hash": sd_hash,
    }

    if transaction_data is not None:
        td_hashes = [
            base64.urlsafe_b64encode(
                hashlib.sha256(td.encode("utf-8")).digest()
            )
            .rstrip(b"=")
            .decode()
            for td in transaction_data
        ]
        kb_payload["transaction_data_hashes"] = td_hashes
        kb_payload["transaction_data_hashes_alg"] = "sha-256"

    # Sign KB-JWT
    header = {"alg": alg, "typ": "kb+jwt"}
    payload_bytes = json.dumps(kb_payload, ensure_ascii=False).encode("utf-8")
    key = _import_private_key(holder_private_key, alg)
    kb_jwt = jws.serialize_compact(header, payload_bytes, key, algorithms=[alg])

    # Ensure sd_jwt ends with ~ then append kb_jwt
    if not sd_jwt.endswith(SD_JWT_SEPARATOR):
        sd_jwt += SD_JWT_SEPARATOR
    return sd_jwt + kb_jwt


def verify_kb_jwt(
    sd_jwt_with_kb: str,
    holder_public_key: PublicKeyType,
    *,
    expected_nonce: str,
    expected_audience: str,
    expected_transaction_data: list[str] | None = None,
) -> dict:
    """Verify KB-JWT and optionally validate transaction_data_hashes.

    Args:
        sd_jwt_with_kb: Complete SD-JWT-VC + KB-JWT string.
        holder_public_key: Holder's public key.
        expected_nonce: Expected nonce value.
        expected_audience: Expected audience value.
        expected_transaction_data: If provided, verify transaction_data_hashes match.

    Returns:
        The KB-JWT payload dict.

    Raises:
        VerificationError: If verification fails.
    """
    # Split: the KB-JWT is the last segment
    # Format: issuer-jwt~[disc1~disc2~...]kb-jwt
    parts = sd_jwt_with_kb.split(SD_JWT_SEPARATOR)
    if len(parts) < 2:
        raise VerificationError("Invalid SD-JWT+KB format: too few parts")

    kb_jwt = parts[-1]
    if not kb_jwt:
        raise VerificationError("No KB-JWT found (empty trailing segment)")

    # Verify KB-JWT signature
    key = _import_public_key(holder_public_key)
    alg = _alg_for_key(holder_public_key)

    try:
        result = jws.deserialize_compact(kb_jwt, key, algorithms=[alg])
    except Exception as e:
        raise VerificationError(f"KB-JWT verification failed: {e}") from e

    header = result.headers()
    if header.get("typ") != "kb+jwt":
        raise VerificationError(
            f"Unexpected KB-JWT typ: expected 'kb+jwt', got {header.get('typ')!r}"
        )

    payload = json.loads(result.payload)

    # Verify nonce
    if payload.get("nonce") != expected_nonce:
        raise VerificationError(
            f"Nonce mismatch: expected {expected_nonce!r}, "
            f"got {payload.get('nonce')!r}"
        )

    # Verify audience
    if payload.get("aud") != expected_audience:
        raise VerificationError(
            f"Audience mismatch: expected {expected_audience!r}, "
            f"got {payload.get('aud')!r}"
        )

    # Verify sd_hash
    issuer_jwt = parts[0]
    expected_sd_hash = (
        base64.urlsafe_b64encode(
            hashlib.sha256(issuer_jwt.encode("ascii")).digest()
        )
        .rstrip(b"=")
        .decode()
    )
    if payload.get("sd_hash") != expected_sd_hash:
        raise VerificationError("sd_hash mismatch")

    # Verify transaction_data_hashes if expected
    if expected_transaction_data is not None:
        expected_hashes = [
            base64.urlsafe_b64encode(
                hashlib.sha256(td.encode("utf-8")).digest()
            )
            .rstrip(b"=")
            .decode()
            for td in expected_transaction_data
        ]
        actual_hashes = payload.get("transaction_data_hashes", [])
        if actual_hashes != expected_hashes:
            raise VerificationError(
                "transaction_data_hashes mismatch"
            )
        if payload.get("transaction_data_hashes_alg") != "sha-256":
            raise VerificationError(
                "transaction_data_hashes_alg must be 'sha-256'"
            )

    return payload
