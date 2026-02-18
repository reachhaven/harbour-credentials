"""SD-JWT-VC verification — verify and disclose SD-JWT-VC credentials."""

import base64
import hashlib
import json

from joserfc import jws

from harbour.jose.keys import PublicKeyType
from harbour.jose.verifier import VerificationError, _import_public_key, _alg_for_key

SD_JWT_SEPARATOR = "~"


def verify_sd_jwt_vc(
    sd_jwt: str,
    public_key: PublicKeyType,
    *,
    expected_vct: str | None = None,
) -> dict:
    """Verify an SD-JWT-VC and return all disclosed claims.

    Args:
        sd_jwt: SD-JWT compact string (<issuer-jwt>~<disclosure1>~...~).
        public_key: Issuer's public key (P-256 or Ed25519).
        expected_vct: If provided, verify the vct claim matches.

    Returns:
        Dict with all disclosed claims (always-disclosed + selectively-disclosed).

    Raises:
        VerificationError: If signature is invalid or disclosures don't match.
    """
    parts = sd_jwt.split(SD_JWT_SEPARATOR)
    if len(parts) < 2:
        raise VerificationError("Invalid SD-JWT format: missing separator")

    issuer_jwt = parts[0]
    # Last element is empty (trailing ~), disclosures are in between
    disclosure_strings = [p for p in parts[1:] if p]

    # Verify the issuer JWT signature
    key = _import_public_key(public_key)
    alg = _alg_for_key(public_key)

    try:
        result = jws.deserialize_compact(issuer_jwt, key, algorithms=[alg])
    except Exception as e:
        raise VerificationError(f"SD-JWT signature verification failed: {e}") from e

    # Validate typ header
    header = result.headers()
    if header.get("typ") != "vc+sd-jwt":
        raise VerificationError(
            f"Unexpected typ: expected 'vc+sd-jwt', got {header.get('typ')!r}"
        )

    payload = json.loads(result.payload)

    # Check vct
    if expected_vct is not None and payload.get("vct") != expected_vct:
        raise VerificationError(
            f"VCT mismatch: expected {expected_vct!r}, got {payload.get('vct')!r}"
        )

    # Process disclosures
    sd_digests = set(payload.get("_sd", []))
    disclosed_claims = {
        k: v for k, v in payload.items() if k not in ("_sd", "_sd_alg")
    }

    for disc_b64 in disclosure_strings:
        # Verify this disclosure matches a digest in _sd
        disc_hash = (
            base64.urlsafe_b64encode(
                hashlib.sha256(disc_b64.encode("ascii")).digest()
            )
            .rstrip(b"=")
            .decode()
        )
        if disc_hash not in sd_digests:
            raise VerificationError(
                f"Disclosure hash {disc_hash[:16]}... not found in _sd digests"
            )
        sd_digests.discard(disc_hash)

        # Decode and extract claim
        disc_json = base64.urlsafe_b64decode(disc_b64 + "=" * (-len(disc_b64) % 4))
        disc_array = json.loads(disc_json)
        if len(disc_array) != 3:
            raise VerificationError(
                f"Invalid disclosure format: expected [salt, name, value]"
            )
        _, claim_name, claim_value = disc_array
        disclosed_claims[claim_name] = claim_value

    return disclosed_claims
