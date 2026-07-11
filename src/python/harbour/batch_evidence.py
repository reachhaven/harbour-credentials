"""Batched credential evidence — one wallet KB-JWT plus per-credential
Merkle inclusion proof.

Implements the wire format and verification of
``docs/specs/batched-credential-evidence.md`` §4–6. An admin of the
authorizing organization signs — via their wallet's OID4VP **KB-JWT** — a
SIWE-style authorization message whose statement carries the batch Merkle
root; each credential then carries a ``harbour:BatchCredentialEvidence``
object with the org DID (``authorizedBy``), that single KB-JWT
(``authorization``), the verbatim message (``authorizationMessage``), and its
own inclusion proof.

Wallets cannot produce arbitrary JWS signatures: the KB-JWT of an OID4VP
presentation is the only signature obtainable from a wallet, so the KB-JWT
``nonce`` carries ``SHA-256(message)`` (lowercase hex) and the message carries
the root (spec §4.3). The signing wallet key is a verification method of the
authorizer's ``did:ethr``; a verifier resolves that DID (as of the KB-JWT
``iat``) to obtain it. The KB-JWT carries no ``iss`` and no ``kid``.

CLI Usage::

    python -m harbour.batch_evidence --help
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import secrets
import sys
import time
from datetime import datetime, timezone
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
    "compose_authorization_message",
    "extract_root_from_message",
    "sign_authorization",
    "verify_authorization",
    "build_batch_evidence",
    "verify_batch_evidence",
]

# typ header of the batch authorization token — an OID4VP KB-JWT (§4.3).
AUTHORIZATION_JWT_TYP = "kb+jwt"
# The harbour:BatchCredentialEvidence evidence type token (§5).
EVIDENCE_TYPE = "harbour:BatchCredentialEvidence"

# Normative statement grammar (§4.3.1): exactly one such line per message;
# the root is base64url unpadded SHA-256 (43 chars).
STATEMENT_TEMPLATE = (
    "I authorize the issuance of {n} credential(s) committed to by Merkle root {root}."
)
_STATEMENT_RE = re.compile(
    r"^I authorize the issuance of (\d+) credential\(s\) "
    r"committed to by Merkle root ([A-Za-z0-9_-]{43})\.$",
    re.MULTILINE,
)


def _message_hash(message: str) -> str:
    """SHA-256 of the message as received, lowercase hex (§4.3.1)."""
    return hashlib.sha256(message.encode("utf-8")).hexdigest()


def compose_authorization_message(
    root: str,
    batch_size: int,
    *,
    domain: str,
    address: str,
    nonce: str | None = None,
    issued_at: str | None = None,
) -> str:
    """Compose a SIWE-style authorization message around the batch root.

    Only the statement line is normative (§4.3.1); the surrounding SIWE-style
    fields are ceremony metadata, carried verbatim in the evidence and hashed
    as-is. In production the message is composed by the intake service
    (gatehouse) and shown on the wallet's consent screen; this helper produces
    an equivalent message for pipelines and tests.
    """
    statement = STATEMENT_TEMPLATE.format(n=batch_size, root=root)
    nonce = nonce if nonce is not None else secrets.token_hex(8)
    issued_at = (
        issued_at
        if issued_at is not None
        else datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
    return (
        f"{domain} wants you to sign this authorization with your wallet:\n"
        f"{address}\n"
        f"\n"
        f"{statement}\n"
        f"\n"
        f"Version: 1\n"
        f"Nonce: {nonce}\n"
        f"Issued At: {issued_at}"
    )


def extract_root_from_message(message: str) -> tuple[str, int]:
    """Extract ``(root, batch_size)`` from the message's statement line.

    Raises:
        VerificationError: unless the message contains exactly one statement
            line matching the normative template (§4.3.1).
    """
    matches = _STATEMENT_RE.findall(message)
    if len(matches) != 1:
        raise VerificationError(
            "authorizationMessage must contain exactly one statement line "
            f"matching the batch-root template (found {len(matches)})"
        )
    n, root = matches[0]
    return root, int(n)


def sign_authorization(
    message: str,
    wallet_key: PrivateKey,
    *,
    audience: str,
    sd_hash: str,
    iat: int | None = None,
    alg: str | None = None,
) -> str:
    """Sign the batch authorization KB-JWT over *message* (§4.3).

    Simulates the wallet's side of the OID4VP ceremony: a KB-JWT
    (``typ: kb+jwt``, no ``iss``, no ``kid``) whose ``nonce`` is the SHA-256
    hex of the message shown on the consent screen. In production this token
    is produced by the admin's wallet through the intake service (gatehouse).

    Args:
        message: The exact authorization message string (§4.3.1).
        wallet_key: The admin's wallet private key (a verification method of
            the authorizer organization's ``did:ethr``).
        audience: The OID4VP intake verifier's client identifier (the JWT
            ``aud``; in Haven, the gatehouse ``did:key``).
        sd_hash: The ``sd_hash`` binding the KB-JWT to the presented
            credential — REQUIRED in every KB-JWT ([SD-JWT] RFC 9901 §4.3);
            wallet-produced tokens always carry it, downstream verifiers
            ignore its value (§6).
        iat: Issued-at (Unix seconds); defaults to now.
        alg: Algorithm override (default resolved from the key, e.g. ES256).

    Returns:
        The compact KB-JWT.
    """
    alg = _resolve_alg(wallet_key, alg)
    header = {"alg": alg, "typ": AUTHORIZATION_JWT_TYP}
    payload: dict[str, Any] = {
        "iat": int(time.time()) if iat is None else int(iat),
        "aud": audience,
        "nonce": _message_hash(message),
        "sd_hash": sd_hash,
    }
    payload_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    key = _import_private_key(wallet_key, alg)
    return jws.serialize_compact(header, payload_bytes, key, algorithms=[alg])


def verify_authorization(
    token: str,
    wallet_public_key: PublicKeyType,
    *,
    message: str,
    expected_audience: str | None = None,
) -> dict:
    """Verify the authorization KB-JWT signature and message commitment.

    Args:
        token: The compact KB-JWT.
        wallet_public_key: The admin wallet public key — a verification
            method of the ``authorizedBy`` DID document, resolved by the
            caller as of the KB-JWT ``iat`` (§6, step 5).
        message: The exact ``authorizationMessage``; its SHA-256 hex must
            equal the KB-JWT ``nonce``.
        expected_audience: If given, require ``aud`` to match (an intake-side
            check; downstream verifiers normally pass None, §6).

    Returns:
        The decoded payload (``iat``, ``aud``, ``nonce``, optional
        ``sd_hash`` — the latter is opaque here).

    Raises:
        VerificationError: on any signature, type, or claim mismatch.
    """
    key = _import_public_key(wallet_public_key)
    alg = _alg_for_key(wallet_public_key)
    try:
        result = jws.deserialize_compact(token, key, algorithms=[alg])
    except Exception as e:  # noqa: BLE001 — surface as VerificationError
        raise VerificationError(f"Authorization KB-JWT verification failed: {e}") from e

    header = result.headers()
    if header.get("typ") != AUTHORIZATION_JWT_TYP:
        raise VerificationError(
            f"Unexpected authorization typ: expected {AUTHORIZATION_JWT_TYP!r}, "
            f"got {header.get('typ')!r}"
        )
    payload = json.loads(result.payload)

    iat = payload.get("iat")
    if isinstance(iat, bool) or not isinstance(iat, int):
        raise VerificationError("Authorization KB-JWT missing integer iat")
    if expected_audience is not None and payload.get("aud") != expected_audience:
        raise VerificationError(
            f"Audience mismatch: expected {expected_audience!r}, "
            f"got {payload.get('aud')!r}"
        )
    expected_nonce = _message_hash(message)
    if payload.get("nonce") != expected_nonce:
        raise VerificationError(
            "KB-JWT nonce does not match SHA-256(authorizationMessage)"
        )
    return payload


def build_batch_evidence(
    payloads: list[dict[str, Any]],
    wallet_key: PrivateKey,
    *,
    authorized_by: str,
    audience: str,
    sd_hash: str,
    domain: str = "harbour.local",
    ceremony_nonce: str | None = None,
    issued_at: str | None = None,
    iat: int | None = None,
    alg: str | None = None,
) -> list[dict[str, Any]]:
    """Build the ``harbour:BatchCredentialEvidence`` object for each credential.

    The leaf of credential *i* is ``compute_leaf(payloads[i])`` — i.e. over the
    issuer payload with its ``evidence``/``proof`` members removed (§4.1). One
    authorization message is composed around the batch root (§4.3.1) and
    signed once with the admin wallet key (KB-JWT); each returned evidence
    object embeds that same KB-JWT and message plus the credential's own
    inclusion proof.

    Args:
        payloads: The issuer payloads in batch order. Each is the credential as
            it will be signed; ``compute_leaf`` strips ``evidence``/``proof``.
        wallet_key: The admin's wallet private key (a verification method of
            the authorizer organization's ``did:ethr``).
        authorized_by: The authorizer organization's ``did:ethr`` (the
            evidence ``authorizedBy``; also used as the message address line).
            For the identity credentials it MUST equal each payload's
            ``issuer`` (spec §6, step 6 — verifiers enforce the equality).
        audience / sd_hash / iat / alg: see :func:`sign_authorization`.
        domain / ceremony_nonce / issued_at: message ceremony metadata,
            see :func:`compose_authorization_message`.

    Returns:
        A list aligned to *payloads*; element *i* is the evidence object to set
        as ``payloads[i]["evidence"]`` (wrapped in a single-element list).
    """
    if not payloads:
        raise ValueError("cannot build batch evidence over an empty batch")
    leaves = [compute_leaf(p) for p in payloads]
    root = merkle_root_b64url(leaves)
    message = compose_authorization_message(
        root,
        len(payloads),
        domain=domain,
        address=authorized_by,
        nonce=ceremony_nonce,
        issued_at=issued_at,
    )
    authorization = sign_authorization(
        message,
        wallet_key,
        audience=audience,
        sd_hash=sd_hash,
        iat=iat,
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
                "authorizedBy": authorized_by,
                "authorization": authorization,
                "authorizationMessage": message,
                "merkleProof": {"type": "harbour:MerkleProof", "path": path},
            }
        )
    return evidence


def verify_batch_evidence(
    payload: dict[str, Any],
    evidence: dict[str, Any],
    wallet_public_key: PublicKeyType,
    *,
    expected_audience: str | None = None,
) -> dict:
    """Verify one credential's batch evidence in isolation (§6, steps 2–5).

    Recomputes the leaf from *payload*, folds the inclusion proof, checks the
    folded root equals the root committed in ``authorizationMessage``, checks
    ``SHA-256(authorizationMessage)`` equals the KB-JWT ``nonce``, and
    verifies the KB-JWT signature against the wallet key.

    The ``authorizedBy`` binding is the caller's responsibility: resolve that
    DID document (as of the KB-JWT ``iat``) and pass one of its verification
    methods as *wallet_public_key* — a KB-JWT has no ``iss`` to compare.

    Args:
        payload: The issued credential's issuer payload (``evidence`` may be
            present — it is stripped for the leaf).
        evidence: The single ``harbour:BatchCredentialEvidence`` object.
        wallet_public_key: An admin wallet public key from the
            ``authorizedBy`` DID document.
        expected_audience: If given, require the KB-JWT ``aud`` to match
            (intake-side check; downstream verifiers normally pass None).

    Returns:
        The verified KB-JWT payload.

    Raises:
        VerificationError: on any mismatch.
    """
    auth = evidence.get("authorization")
    if not isinstance(auth, str):
        raise VerificationError("BatchCredentialEvidence missing authorization KB-JWT")
    message = evidence.get("authorizationMessage")
    if not isinstance(message, str):
        raise VerificationError("BatchCredentialEvidence missing authorizationMessage")

    auth_payload = verify_authorization(
        auth,
        wallet_public_key,
        message=message,
        expected_audience=expected_audience,
    )

    root_b64, _batch_size = extract_root_from_message(message)

    proof = evidence.get("merkleProof")
    if not isinstance(proof, dict) or not isinstance(proof.get("path"), list):
        raise VerificationError("BatchCredentialEvidence missing merkleProof.path")

    leaf = compute_leaf(payload)
    root = b64url_decode(root_b64)
    if not verify_inclusion(leaf, proof["path"], root):
        raise VerificationError(
            "Merkle inclusion proof does not fold to the committed root"
        )
    return auth_payload


def main() -> None:
    """CLI entry point: verify a credential's batch evidence."""
    parser = argparse.ArgumentParser(
        prog="harbour.batch_evidence",
        description=(
            "Batched credential evidence — verify a credential's authorization "
            "KB-JWT, message commitment, and Merkle inclusion proof "
            "(docs/specs/batched-credential-evidence.md)."
        ),
    )
    sub = parser.add_subparsers(dest="command")
    v = sub.add_parser("verify", help="Verify a credential's batch evidence")
    v.add_argument(
        "--credential", required=True, help="JSON credential (with evidence)"
    )
    v.add_argument(
        "--wallet-key",
        required=True,
        help="Admin wallet public key (JWK; a VM of the authorizedBy DID doc)",
    )
    v.add_argument("--audience", help="Expected audience (intake verifier client id)")

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
        pub = _load_public_key(args.wallet_key)
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
