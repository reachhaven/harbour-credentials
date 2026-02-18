"""SD-JWT-VC issuance — IETF SD-JWT-based Verifiable Credentials.

Issues credentials in SD-JWT-VC format with selective disclosure,
using ES256 (P-256) as the primary algorithm.
"""

import hashlib
import json
import secrets

from joserfc import jws
from joserfc.jwk import ECKey, OKPKey

from harbour.jose.keys import PrivateKey, keypair_to_jwk, p256_keypair_to_jwk
from harbour.jose.signer import _import_private_key, _resolve_alg

# SD-JWT uses ~-delimited format: <issuer-jwt>~<disclosure1>~<disclosure2>~...~
SD_JWT_SEPARATOR = "~"


def issue_sd_jwt_vc(
    claims: dict,
    private_key: PrivateKey,
    *,
    vct: str,
    disclosable: list[str] | None = None,
    alg: str | None = None,
    x5c: list[str] | None = None,
    cnf: dict | None = None,
) -> str:
    """Issue an SD-JWT-VC credential.

    Args:
        claims: The credential claims (flat key-value pairs).
        private_key: Issuer's private key (P-256 or Ed25519).
        vct: Verifiable Credential Type URI.
        disclosable: List of claim names to make selectively disclosable.
        alg: Algorithm override (default: ES256 for P-256).
        x5c: X.509 certificate chain for JOSE header.
        cnf: Confirmation key (holder's public key JWK for key binding).

    Returns:
        SD-JWT compact string: <issuer-jwt>~<disclosure1>~...~
    """
    alg = _resolve_alg(private_key, alg)
    disclosable = disclosable or []

    # Separate disclosable and always-disclosed claims
    sd_claims = {}
    disclosed_claims = {"vct": vct}
    disclosures = []

    for key, value in claims.items():
        if key in disclosable:
            # Create a disclosure: [salt, claim_name, claim_value]
            salt = secrets.token_urlsafe(16)
            disclosure_array = [salt, key, value]
            disclosure_json = json.dumps(
                disclosure_array, ensure_ascii=False
            ).encode("utf-8")
            import base64

            disclosure_b64 = (
                base64.urlsafe_b64encode(disclosure_json).rstrip(b"=").decode()
            )
            disclosures.append(disclosure_b64)

            # Hash the disclosure for the SD digest array
            digest = (
                base64.urlsafe_b64encode(
                    hashlib.sha256(disclosure_b64.encode("ascii")).digest()
                )
                .rstrip(b"=")
                .decode()
            )
            sd_claims.setdefault("_sd", []).append(digest)
        else:
            disclosed_claims[key] = value

    # Build JWT payload
    payload = {**disclosed_claims}
    if "_sd" in sd_claims:
        payload["_sd"] = sd_claims["_sd"]
        payload["_sd_alg"] = "sha-256"

    if cnf is not None:
        payload["cnf"] = cnf

    # Build header
    header = {"alg": alg, "typ": "vc+sd-jwt"}
    if x5c is not None:
        header["x5c"] = x5c

    # Sign the issuer JWT
    payload_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    key = _import_private_key(private_key, alg)
    issuer_jwt = jws.serialize_compact(header, payload_bytes, key, algorithms=[alg])

    # Compose SD-JWT: issuer-jwt~disclosure1~disclosure2~...~
    parts = [issuer_jwt] + disclosures + [""]
    return SD_JWT_SEPARATOR.join(parts)
