"""Batched credential evidence — the single authorization JWT plus per-credential
Merkle inclusion proof.

Implements the wire format and verification of
``docs/specs/batched-credential-evidence.md`` §4–6. An authorizing party signs
**one** authorization JWT whose ``nonce`` is the base64url Merkle root over a
batch of credential payloads; each credential then carries a
``harbour:BatchCredentialEvidence`` object with the authorizer DID, that single
authorization JWT, and its own inclusion proof.

The authorization JWT is a plain ES256/EdDSA JWS (``typ: harbour-batch-auth+jwt``)
— not an SD-JWT KB-JWT, since the authorizer presents no credential. Its signing
key is a verification method of the authorizer's ``did:ethr``; a verifier resolves
that DID (as of the JWT ``iat``) to obtain it.

CLI Usage::

    python -m harbour.batch_evidence --help
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from joserfc import jws

from harbour._crypto import import_private_key as _import_private_key
from harbour._crypto import import_public_key as _import_public_key
from harbour._crypto import resolve_private_key_alg as _resolve_alg
from harbour._crypto import resolve_public_key_alg as _alg_for_key
from harbour.keys import PrivateKey, PublicKeyType
from harbour.merkle import (
    b64url_decode,
    compute_leaf,
    inclusion_proof,
    merkle_root_b64url,
    verify_inclusion,
)
from harbour.verifier import VerificationError

__all__ = [
    "AUTHORIZATION_JWT_TYP",
    "EVIDENCE_TYPE",
    "sign_authorization",
    "verify_authorization",
    "build_batch_evidence",
    "verify_batch_evidence",
]

# typ header of the batch authorization JWS (§4.3).
AUTHORIZATION_JWT_TYP = "harbour-batch-auth+jwt"
# The harbour:BatchCredentialEvidence evidence type token (§5).
EVIDENCE_TYPE = "harbour:BatchCredentialEvidence"


def sign_authorization(
    root: str,
    authorizer_key: PrivateKey,
    *,
    authorizer_did: str,
    audience: str,
    iat: int | None = None,
    kid: str | None = None,
    alg: str | None = None,
) -> str:
    """Sign the single batch authorization JWT (§4.3).

    Args:
        root: base64url Merkle root over the batch (becomes the ``nonce`` claim).
        authorizer_key: The authorizing party's private key (a verification
            method of its ``did:ethr``).
        authorizer_did: The authorizer DID (the JWT ``iss``).
        audience: The Signing Service identifier (the JWT ``aud``).
        iat: Issued-at (Unix seconds); defaults to now.
        kid: Verification-method id; defaults to ``<authorizer_did>#controller``.
        alg: Algorithm override (default resolved from the key, e.g. ES256).

    Returns:
        The compact JWS authorization token.
    """
    alg = _resolve_alg(authorizer_key, alg)
    header = {
        "alg": alg,
        "typ": AUTHORIZATION_JWT_TYP,
        "kid": kid or f"{authorizer_did}#controller",
    }
    payload = {
        "iss": authorizer_did,
        "aud": audience,
        "iat": int(time.time()) if iat is None else int(iat),
        "nonce": root,
    }
    payload_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    key = _import_private_key(authorizer_key, alg)
    return jws.serialize_compact(header, payload_bytes, key, algorithms=[alg])


def verify_authorization(
    token: str,
    authorizer_public_key: PublicKeyType,
    *,
    expected_audience: str | None = None,
    expected_authorizer: str | None = None,
) -> dict:
    """Verify the authorization JWT signature and claims; return its payload.

    Args:
        token: The compact JWS authorization token.
        authorizer_public_key: The authorizer verification-method public key
            (resolved from its ``did:ethr`` as of the JWT ``iat``).
        expected_audience: If given, require ``aud`` to match.
        expected_authorizer: If given, require ``iss`` to match.

    Returns:
        The decoded payload (``iss``, ``aud``, ``iat``, ``nonce`` = Merkle root).

    Raises:
        VerificationError: on any signature, type, or claim mismatch.
    """
    key = _import_public_key(authorizer_public_key)
    alg = _alg_for_key(authorizer_public_key)
    try:
        result = jws.deserialize_compact(token, key, algorithms=[alg])
    except Exception as e:  # noqa: BLE001 — surface as VerificationError
        raise VerificationError(f"Authorization JWT verification failed: {e}") from e

    header = result.headers()
    if header.get("typ") != AUTHORIZATION_JWT_TYP:
        raise VerificationError(
            f"Unexpected authorization typ: expected {AUTHORIZATION_JWT_TYP!r}, "
            f"got {header.get('typ')!r}"
        )
    payload = json.loads(result.payload)

    if expected_authorizer is not None and payload.get("iss") != expected_authorizer:
        raise VerificationError(
            f"Authorizer mismatch: expected {expected_authorizer!r}, "
            f"got {payload.get('iss')!r}"
        )
    if expected_audience is not None and payload.get("aud") != expected_audience:
        raise VerificationError(
            f"Audience mismatch: expected {expected_audience!r}, "
            f"got {payload.get('aud')!r}"
        )
    if not isinstance(payload.get("nonce"), str):
        raise VerificationError("Authorization JWT missing string nonce (Merkle root)")
    return payload


def build_batch_evidence(
    payloads: list[dict[str, Any]],
    authorizer_key: PrivateKey,
    *,
    authorizer_did: str,
    audience: str,
    iat: int | None = None,
    kid: str | None = None,
    alg: str | None = None,
) -> list[dict[str, Any]]:
    """Build the ``harbour:BatchCredentialEvidence`` object for each credential.

    The leaf of credential *i* is ``compute_leaf(payloads[i])`` — i.e. over the
    issuer payload with its ``evidence``/``proof`` members removed (§4.1). The
    authorizer signs the root once; each returned evidence object embeds that
    same authorization JWT plus the credential's own inclusion proof.

    Args:
        payloads: The issuer payloads in batch order. Each is the credential as
            it will be signed; ``compute_leaf`` strips ``evidence``/``proof``.
        authorizer_key / authorizer_did / audience / iat / kid / alg: see
            :func:`sign_authorization`.

    Returns:
        A list aligned to *payloads*; element *i* is the evidence object to set
        as ``payloads[i]["evidence"]`` (wrapped in a single-element list).
    """
    if not payloads:
        raise ValueError("cannot build batch evidence over an empty batch")
    leaves = [compute_leaf(p) for p in payloads]
    root = merkle_root_b64url(leaves)
    authorization = sign_authorization(
        root,
        authorizer_key,
        authorizer_did=authorizer_did,
        audience=audience,
        iat=iat,
        kid=kid,
        alg=alg,
    )
    evidence: list[dict[str, Any]] = []
    for i in range(len(payloads)):
        # Each nested object carries its JSON-LD type so the evidence remains
        # a valid harbour:MerkleProof / harbour:MerklePathElement under the
        # closed SHACL shapes (spec §5).
        path = [
            {"type": "harbour:MerklePathElement", **step}
            for step in inclusion_proof(leaves, i)
        ]
        evidence.append(
            {
                "type": [EVIDENCE_TYPE],
                "authorizedBy": authorizer_did,
                "authorization": authorization,
                "merkleProof": {"type": "harbour:MerkleProof", "path": path},
            }
        )
    return evidence


def verify_batch_evidence(
    payload: dict[str, Any],
    evidence: dict[str, Any],
    authorizer_public_key: PublicKeyType,
    *,
    expected_audience: str | None = None,
) -> dict:
    """Verify one credential's batch evidence in isolation (§6, steps 2–5).

    Recomputes the leaf from *payload*, folds the inclusion proof, checks the
    folded root equals the authorization JWT ``nonce``, and verifies the
    authorization signature against the authorizer key.

    Args:
        payload: The issued credential's issuer payload (``evidence`` may be
            present — it is stripped for the leaf).
        evidence: The single ``harbour:BatchCredentialEvidence`` object.
        authorizer_public_key: The authorizer verification-method public key.
        expected_audience: If given, require the authorization ``aud`` to match.

    Returns:
        The verified authorization payload.

    Raises:
        VerificationError: on any mismatch.
    """
    auth = evidence.get("authorization")
    if not isinstance(auth, str):
        raise VerificationError("BatchCredentialEvidence missing authorization JWT")

    authorizer = evidence.get("authorizedBy")
    auth_payload = verify_authorization(
        auth,
        authorizer_public_key,
        expected_audience=expected_audience,
        expected_authorizer=authorizer if isinstance(authorizer, str) else None,
    )

    proof = evidence.get("merkleProof")
    if not isinstance(proof, dict) or not isinstance(proof.get("path"), list):
        raise VerificationError("BatchCredentialEvidence missing merkleProof.path")

    leaf = compute_leaf(payload)
    root = b64url_decode(auth_payload["nonce"])
    if not verify_inclusion(leaf, proof["path"], root):
        raise VerificationError(
            "Merkle inclusion proof does not fold to the signed root"
        )
    return auth_payload


def main() -> None:
    """CLI entry point: verify a credential's batch evidence."""
    parser = argparse.ArgumentParser(
        prog="harbour.batch_evidence",
        description=(
            "Batched credential evidence — verify a credential's authorization "
            "JWT and Merkle inclusion proof "
            "(docs/specs/batched-credential-evidence.md)."
        ),
    )
    sub = parser.add_subparsers(dest="command")
    v = sub.add_parser("verify", help="Verify a credential's batch evidence")
    v.add_argument(
        "--credential", required=True, help="JSON credential (with evidence)"
    )
    v.add_argument(
        "--authorizer-key", required=True, help="Authorizer public key (JWK)"
    )
    v.add_argument("--audience", help="Expected audience (Signing Service)")

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "verify":
        from harbour._crypto import load_public_key as _load_public_key

        credential = json.loads(Path(args.credential).read_text(encoding="utf-8"))
        evidence_list = credential.get("evidence") or []
        if not evidence_list:
            print("No evidence on credential", file=sys.stderr)
            sys.exit(1)
        pub = _load_public_key(args.authorizer_key)
        try:
            payload = verify_batch_evidence(
                credential, evidence_list[0], pub, expected_audience=args.audience
            )
            print(json.dumps(payload, indent=2))
        except VerificationError as e:
            print(f"Verification failed: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
