"""SD-JWT Verifiable Presentations for privacy-preserving consent.

This module enables creating VPs where:
- The inner credential is an SD-JWT-VC with selectively disclosed claims
- The VP envelope includes evidence (e.g., DelegatedSignatureEvidence)
- The VP is signed by the holder's key (KB-JWT style binding)

The SD-JWT VP format follows the IETF SD-JWT specification, extending it for
presentations with evidence. The format is:

    <vp-jwt>~<vc-disclosures>~<kb-jwt>

Where:
- vp-jwt: The VP envelope JWT (typ: vp+sd-jwt)
- vc-disclosures: Selected disclosures from the inner SD-JWT-VC
- kb-jwt: Key binding JWT proving holder possession

CLI Usage:
    python -m harbour.sd_jwt_vp --help
    python -m harbour.sd_jwt_vp issue --help
    python -m harbour.sd_jwt_vp verify --help
"""

import argparse
import base64
import hashlib
import json
import sys
import time
from copy import deepcopy
from pathlib import Path

from harbour._crypto import import_private_key as _import_private_key
from harbour._crypto import import_public_key as _import_public_key
from harbour._crypto import load_private_key as _load_private_key
from harbour._crypto import load_public_key as _load_public_key
from harbour._crypto import resolve_private_key_alg as _resolve_alg
from harbour._crypto import resolve_public_key_alg as _alg_for_key
from harbour.delegation import (
    TransactionData,
    compute_transaction_data_param_hash,
    create_delegation_challenge,
)
from harbour.keys import PrivateKey, PublicKeyType
from harbour.verifier import VerificationError
from joserfc import jws

# SD-JWT uses ~-delimited format
SD_JWT_SEPARATOR = "~"
DELEGATED_EVIDENCE_TYPES = {
    "DelegatedSignatureEvidence",
    "harbour:DelegatedSignatureEvidence",
}


def _dedupe(values: list[str]) -> list[str]:
    """Return values in first-seen order without duplicates."""
    return list(dict.fromkeys(values))


def _get_transaction_data(
    evidence_item: dict, exception_type: type[Exception]
) -> dict[str, object]:
    """Extract transaction data from delegated signing evidence."""
    transaction_data = evidence_item.get("transaction_data")
    if transaction_data is None:
        raise exception_type("DelegatedSignatureEvidence requires transaction_data")
    if not isinstance(transaction_data, dict):
        raise exception_type(
            "DelegatedSignatureEvidence transaction data must be an object"
        )
    return transaction_data


def _normalize_delegation_evidence(
    evidence: list[dict] | None,
) -> tuple[list[dict] | None, list[str], list[str], list[str]]:
    """Derive and inject challenge/hash bindings for delegated evidence."""
    if evidence is None:
        return None, [], [], []

    normalized: list[dict] = []
    tx_hashes: list[str] = []
    tx_nonces: list[str] = []
    delegated_to_values: list[str] = []

    for item in evidence:
        ev = deepcopy(item)
        if ev.get("type") in DELEGATED_EVIDENCE_TYPES:
            transaction_data = _get_transaction_data(ev, ValueError)
            tx = TransactionData.from_dict(transaction_data)
            challenge = create_delegation_challenge(tx)
            existing_challenge = ev.get("challenge")
            if (
                existing_challenge is not None
                and isinstance(existing_challenge, str)
                and existing_challenge != challenge
            ):
                raise ValueError(
                    "DelegatedSignatureEvidence challenge does not match transaction_data"
                )
            ev["challenge"] = challenge

            tx_hashes.append(compute_transaction_data_param_hash(tx))
            tx_nonces.append(tx.nonce)

            delegated_to = ev.get("delegatedTo")
            if isinstance(delegated_to, str):
                delegated_to_values.append(delegated_to)

        normalized.append(ev)

    return (
        normalized,
        _dedupe(tx_hashes),
        _dedupe(tx_nonces),
        _dedupe(delegated_to_values),
    )


def _derive_delegation_bindings(
    evidence: list[dict] | None,
) -> tuple[list[str], list[str], list[str]]:
    """Derive expected hash/nonce/audience bindings from delegated evidence."""
    if not evidence:
        return [], [], []

    tx_hashes: list[str] = []
    tx_nonces: list[str] = []
    delegated_to_values: list[str] = []

    for item in evidence:
        if item.get("type") in DELEGATED_EVIDENCE_TYPES:
            transaction_data = _get_transaction_data(item, VerificationError)
            tx = TransactionData.from_dict(transaction_data)
            expected_challenge = create_delegation_challenge(tx)
            provided_challenge = item.get("challenge")
            if (
                provided_challenge is not None
                and isinstance(provided_challenge, str)
                and provided_challenge != expected_challenge
            ):
                raise VerificationError(
                    "Delegation challenge mismatch in evidence transaction_data"
                )

            tx_hashes.append(compute_transaction_data_param_hash(tx))
            tx_nonces.append(tx.nonce)

            delegated_to = item.get("delegatedTo")
            if isinstance(delegated_to, str):
                delegated_to_values.append(delegated_to)

    return _dedupe(tx_hashes), _dedupe(tx_nonces), _dedupe(delegated_to_values)


def issue_sd_jwt_vp(
    sd_jwt_vc: str,
    holder_private_key: PrivateKey,
    *,
    disclosures: list[str] | None = None,
    evidence: list[dict] | None = None,
    nonce: str | None = None,
    audience: str | None = None,
    holder_did: str | None = None,
) -> str:
    """Issue an SD-JWT VP with selective disclosure and evidence.

    Creates a Verifiable Presentation containing:
    - An SD-JWT-VC with selected disclosures (for privacy)
    - Evidence objects (e.g., DelegatedSignatureEvidence)
    - Key binding proof (holder signature)

    Args:
        sd_jwt_vc: The SD-JWT-VC to present (<issuer-jwt>~<disc1>~...~).
        holder_private_key: Holder's private key for VP and KB-JWT signatures.
        disclosures: Which disclosures to include (by claim name).
                     If None, includes all available disclosures.
                     If empty list [], includes no disclosures (max privacy).
        evidence: Evidence objects to include in the VP. Supported types:
                  - CredentialEvidence: prior credential/VP the issuer relied upon
                  - DelegatedSignatureEvidence: consent proof with transaction_data
        nonce: Challenge nonce for replay protection.
        audience: Intended verifier (DID or URL).
        holder_did: Holder's DID for the VP. If not provided, will not be included.

    Returns:
        SD-JWT VP string: <vp-jwt>~<selected-disclosures>~<kb-jwt>
    """
    alg = _resolve_alg(holder_private_key, None)

    # Parse the SD-JWT-VC
    parts = sd_jwt_vc.split(SD_JWT_SEPARATOR)
    if len(parts) < 2:
        raise ValueError("Invalid SD-JWT-VC format: missing separator")

    issuer_jwt = parts[0]
    # Last element is empty (trailing ~), disclosures are in between
    all_disclosures = [p for p in parts[1:] if p]

    # Decode issuer JWT to get _sd digests and claims
    issuer_parts = issuer_jwt.split(".")
    if len(issuer_parts) != 3:
        raise ValueError("Invalid issuer JWT format")

    payload_b64 = issuer_parts[1]
    base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))

    # Build mapping: claim_name -> disclosure_string
    disclosure_map = {}
    for disc_b64 in all_disclosures:
        disc_json = base64.urlsafe_b64decode(disc_b64 + "=" * (-len(disc_b64) % 4))
        disc_array = json.loads(disc_json)
        if len(disc_array) == 3:
            _, claim_name, _ = disc_array
            disclosure_map[claim_name] = disc_b64

    # Select which disclosures to include
    if disclosures is None:
        # Include all disclosures
        selected_disclosures = list(disclosure_map.values())
    else:
        # Include only named disclosures
        selected_disclosures = []
        for name in disclosures:
            if name in disclosure_map:
                selected_disclosures.append(disclosure_map[name])

    normalized_evidence, tx_hashes, tx_nonces, delegated_to_values = (
        _normalize_delegation_evidence(evidence)
    )

    resolved_nonce = nonce
    if tx_nonces:
        if resolved_nonce is None:
            if len(tx_nonces) != 1:
                raise ValueError(
                    "DelegatedSignatureEvidence contains multiple transaction_data nonce values; "
                    "pass explicit nonce"
                )
            resolved_nonce = tx_nonces[0]
        elif any(tx_nonce != resolved_nonce for tx_nonce in tx_nonces):
            raise ValueError(
                "Nonce must match DelegatedSignatureEvidence transaction_data.nonce"
            )

    resolved_audience = audience
    if delegated_to_values:
        if resolved_audience is None:
            if len(delegated_to_values) != 1:
                raise ValueError(
                    "DelegatedSignatureEvidence contains multiple delegatedTo values; "
                    "pass explicit audience"
                )
            resolved_audience = delegated_to_values[0]
        elif any(value != resolved_audience for value in delegated_to_values):
            raise ValueError(
                "Audience must match DelegatedSignatureEvidence delegatedTo"
            )

    # Build VP payload
    vp_payload = {
        "vp": {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
        },
        "iat": int(time.time()),
    }

    if holder_did:
        vp_payload["vp"]["holder"] = holder_did
        vp_payload["iss"] = holder_did

    if resolved_nonce:
        vp_payload["nonce"] = resolved_nonce

    if resolved_audience:
        vp_payload["aud"] = resolved_audience

    if normalized_evidence:
        vp_payload["vp"]["evidence"] = normalized_evidence

    # Include reference to the VC (the issuer JWT will be reconstructed on verify)
    # We store a hash of the issuer JWT for binding
    vc_hash = (
        base64.urlsafe_b64encode(hashlib.sha256(issuer_jwt.encode("ascii")).digest())
        .rstrip(b"=")
        .decode()
    )
    vp_payload["_vc_hash"] = vc_hash

    # Sign VP JWT
    vp_header = {"alg": alg, "typ": "vp+sd-jwt"}
    vp_payload_bytes = json.dumps(vp_payload, ensure_ascii=False).encode("utf-8")
    key = _import_private_key(holder_private_key, alg)
    vp_jwt = jws.serialize_compact(vp_header, vp_payload_bytes, key, algorithms=[alg])

    # Create KB-JWT for holder binding
    # RFC 9901 §4.3.1 — sd_hash over <issuer-jwt>~<disc1>~...~<discN>~
    sd_material = (
        issuer_jwt
        + SD_JWT_SEPARATOR
        + SD_JWT_SEPARATOR.join(selected_disclosures)
        + SD_JWT_SEPARATOR
    )
    kb_payload = {
        "iat": int(time.time()),
        "sd_hash": base64.urlsafe_b64encode(
            hashlib.sha256(sd_material.encode("ascii")).digest()
        )
        .rstrip(b"=")
        .decode(),
    }

    if resolved_nonce:
        kb_payload["nonce"] = resolved_nonce
    if resolved_audience:
        kb_payload["aud"] = resolved_audience
    if tx_hashes:
        kb_payload["transaction_data_hashes"] = tx_hashes
        kb_payload["transaction_data_hashes_alg"] = "sha-256"

    kb_header = {"alg": alg, "typ": "kb+jwt"}
    kb_payload_bytes = json.dumps(kb_payload, ensure_ascii=False).encode("utf-8")
    kb_jwt = jws.serialize_compact(kb_header, kb_payload_bytes, key, algorithms=[alg])

    # Compose: vp-jwt~issuer-jwt~disc1~disc2~...~kb-jwt
    # The issuer JWT is included so verifiers can check the VC
    result_parts = [vp_jwt, issuer_jwt] + selected_disclosures + [kb_jwt]
    return SD_JWT_SEPARATOR.join(result_parts)


def verify_sd_jwt_vp(
    sd_jwt_vp: str,
    issuer_public_key: PublicKeyType,
    holder_public_key: PublicKeyType,
    *,
    expected_nonce: str | None = None,
    expected_audience: str | None = None,
) -> dict:
    """Verify an SD-JWT VP and return disclosed claims and evidence.

    Args:
        sd_jwt_vp: The SD-JWT VP string to verify.
        issuer_public_key: Issuer's public key (for inner VC verification).
        holder_public_key: Holder's public key (for VP and KB-JWT verification).
        expected_nonce: If provided, verify nonce matches.
        expected_audience: If provided, verify audience matches.

    Returns:
        dict with:
        - 'holder': Holder DID (if present)
        - 'credential': Verified credential claims (disclosed only)
        - 'evidence': Evidence array (if present)
        - 'nonce': Nonce value (if present)
        - 'audience': Audience value (if present)

    Raises:
        VerificationError: If any verification step fails.
    """
    parts = sd_jwt_vp.split(SD_JWT_SEPARATOR)
    if len(parts) < 3:
        raise VerificationError("Invalid SD-JWT VP format: too few parts")

    vp_jwt = parts[0]
    issuer_jwt = parts[1]
    kb_jwt = parts[-1]

    # Disclosures are everything between issuer_jwt and kb_jwt
    disclosures = parts[2:-1]

    # 1. Verify VP JWT signature (holder)
    holder_key = _import_public_key(holder_public_key)
    holder_alg = _alg_for_key(holder_public_key)

    try:
        vp_result = jws.deserialize_compact(vp_jwt, holder_key, algorithms=[holder_alg])
    except Exception as e:
        raise VerificationError(f"VP JWT verification failed: {e}") from e

    vp_header = vp_result.headers()
    if vp_header.get("typ") != "vp+sd-jwt":
        raise VerificationError(
            f"Unexpected VP typ: expected 'vp+sd-jwt', got {vp_header.get('typ')!r}"
        )

    vp_payload = json.loads(vp_result.payload)

    # 2. Verify issuer JWT signature (issuer)
    issuer_key = _import_public_key(issuer_public_key)
    issuer_alg = _alg_for_key(issuer_public_key)

    try:
        vc_result = jws.deserialize_compact(
            issuer_jwt, issuer_key, algorithms=[issuer_alg]
        )
    except Exception as e:
        raise VerificationError(f"VC JWT verification failed: {e}") from e

    vc_header = vc_result.headers()
    if vc_header.get("typ") != "vc+sd-jwt":
        raise VerificationError(
            f"Unexpected VC typ: expected 'vc+sd-jwt', got {vc_header.get('typ')!r}"
        )

    vc_payload = json.loads(vc_result.payload)

    # 3. Verify KB-JWT signature (holder)
    try:
        kb_result = jws.deserialize_compact(kb_jwt, holder_key, algorithms=[holder_alg])
    except Exception as e:
        raise VerificationError(f"KB-JWT verification failed: {e}") from e

    kb_header = kb_result.headers()
    if kb_header.get("typ") != "kb+jwt":
        raise VerificationError(
            f"Unexpected KB-JWT typ: expected 'kb+jwt', got {kb_header.get('typ')!r}"
        )

    kb_payload = json.loads(kb_result.payload)

    # 4. Verify VC hash binding
    expected_vc_hash = (
        base64.urlsafe_b64encode(hashlib.sha256(issuer_jwt.encode("ascii")).digest())
        .rstrip(b"=")
        .decode()
    )

    if vp_payload.get("_vc_hash") != expected_vc_hash:
        raise VerificationError("VC hash mismatch: VP does not bind to presented VC")

    # 5. Verify SD hash in KB-JWT
    # RFC 9901 §4.3.1 — sd_hash over <issuer-jwt>~<disc1>~...~<discN>~
    sd_material = (
        issuer_jwt
        + SD_JWT_SEPARATOR
        + SD_JWT_SEPARATOR.join(disclosures)
        + SD_JWT_SEPARATOR
    )
    expected_sd_hash = (
        base64.urlsafe_b64encode(hashlib.sha256(sd_material.encode("ascii")).digest())
        .rstrip(b"=")
        .decode()
    )

    if kb_payload.get("sd_hash") != expected_sd_hash:
        raise VerificationError("SD hash mismatch in KB-JWT")

    vp_nonce = vp_payload.get("nonce")
    kb_nonce = kb_payload.get("nonce")
    if vp_nonce != kb_nonce and (vp_nonce is not None or kb_nonce is not None):
        raise VerificationError("Nonce mismatch between VP and KB-JWT")

    vp_audience = vp_payload.get("aud")
    kb_audience = kb_payload.get("aud")
    if vp_audience != kb_audience and (
        vp_audience is not None or kb_audience is not None
    ):
        raise VerificationError("Audience mismatch between VP and KB-JWT")

    vp_obj = vp_payload.get("vp", {})
    evidence = vp_obj.get("evidence") if isinstance(vp_obj, dict) else None
    evidence_list = evidence if isinstance(evidence, list) else None
    tx_hashes, tx_nonces, delegated_to_values = _derive_delegation_bindings(
        evidence_list
    )

    if tx_hashes:
        kb_hashes = kb_payload.get("transaction_data_hashes")
        if not isinstance(kb_hashes, list) or not all(
            isinstance(item, str) for item in kb_hashes
        ):
            raise VerificationError(
                "Missing transaction_data_hashes in KB-JWT for delegated evidence"
            )
        if kb_hashes != tx_hashes:
            raise VerificationError("transaction_data_hashes mismatch")
        if kb_payload.get("transaction_data_hashes_alg") != "sha-256":
            raise VerificationError("transaction_data_hashes_alg must be 'sha-256'")

    if len(tx_nonces) > 1:
        raise VerificationError(
            "DelegatedSignatureEvidence contains multiple transaction_data nonce values"
        )
    if tx_nonces and vp_nonce != tx_nonces[0]:
        raise VerificationError(
            "Nonce mismatch: VP/KB nonce does not match transaction_data nonce"
        )

    if len(delegated_to_values) > 1:
        raise VerificationError(
            "DelegatedSignatureEvidence contains multiple delegatedTo values"
        )
    if delegated_to_values and vp_audience != delegated_to_values[0]:
        raise VerificationError(
            "Audience mismatch: VP/KB audience does not match delegatedTo"
        )

    # 6. Verify nonce
    if expected_nonce is not None:
        if vp_nonce != expected_nonce:
            raise VerificationError(
                f"Nonce mismatch: expected {expected_nonce!r}, got {vp_nonce!r}"
            )
        if kb_nonce != expected_nonce:
            raise VerificationError("Nonce mismatch in KB-JWT")

    # 7. Verify audience
    if expected_audience is not None:
        if vp_audience != expected_audience:
            raise VerificationError(
                f"Audience mismatch: expected {expected_audience!r}, got {vp_audience!r}"
            )
        if kb_audience != expected_audience:
            raise VerificationError("Audience mismatch in KB-JWT")

    # 8. Process disclosures
    sd_digests = set(vc_payload.get("_sd", []))
    disclosed_claims = {
        k: v for k, v in vc_payload.items() if k not in ("_sd", "_sd_alg")
    }

    for disc_b64 in disclosures:
        disc_hash = (
            base64.urlsafe_b64encode(hashlib.sha256(disc_b64.encode("ascii")).digest())
            .rstrip(b"=")
            .decode()
        )

        if disc_hash not in sd_digests:
            raise VerificationError(
                f"Disclosure hash {disc_hash[:16]}... not found in _sd digests"
            )
        sd_digests.discard(disc_hash)

        disc_json = base64.urlsafe_b64decode(disc_b64 + "=" * (-len(disc_b64) % 4))
        disc_array = json.loads(disc_json)
        if len(disc_array) != 3:
            raise VerificationError(
                "Invalid disclosure format: expected [salt, name, value]"
            )
        _, claim_name, claim_value = disc_array
        disclosed_claims[claim_name] = claim_value

    # Build result
    result = {
        "credential": disclosed_claims,
    }

    if "holder" in vp_obj:
        result["holder"] = vp_obj["holder"]

    if "evidence" in vp_obj:
        result["evidence"] = vp_obj["evidence"]

    if "nonce" in vp_payload:
        result["nonce"] = vp_payload["nonce"]

    if "aud" in vp_payload:
        result["audience"] = vp_payload["aud"]

    return result


def main():
    """CLI entry point for SD-JWT VP operations."""
    parser = argparse.ArgumentParser(
        prog="harbour.sd_jwt_vp",
        description="Harbour SD-JWT VP CLI - Issue and verify SD-JWT Verifiable Presentations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Issue an SD-JWT VP with selective disclosure
  python -m harbour.sd_jwt_vp issue --sd-jwt-vc vc.txt --key holder-key.jwk \\
      --disclosures memberOf --nonce abc123 --audience did:web:verifier.example.com

  # Issue with evidence (DelegatedSignatureEvidence)
  python -m harbour.sd_jwt_vp issue --sd-jwt-vc vc.txt --key holder-key.jwk \\
      --evidence evidence.json --nonce abc123

  # Verify an SD-JWT VP
  python -m harbour.sd_jwt_vp verify --sd-jwt-vp vp.txt \\
      --issuer-key issuer-pub.jwk --holder-key holder-pub.jwk
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Issue subcommand
    issue_parser = subparsers.add_parser(
        "issue",
        help="Issue an SD-JWT VP",
        description="Create an SD-JWT Verifiable Presentation with selective disclosure.",
    )
    issue_parser.add_argument(
        "--sd-jwt-vc", required=True, help="File containing the SD-JWT-VC to present"
    )
    issue_parser.add_argument(
        "--key", required=True, help="Holder's private key (JWK file)"
    )
    issue_parser.add_argument(
        "--disclosures",
        nargs="*",
        help="Claim names to disclose (default: all). Use empty for none.",
    )
    issue_parser.add_argument("--evidence", help="JSON file with evidence objects")
    issue_parser.add_argument("--nonce", help="Challenge nonce for replay protection")
    issue_parser.add_argument("--audience", help="Intended verifier (DID or URL)")
    issue_parser.add_argument("--holder-did", help="Holder's DID")
    issue_parser.add_argument("--output", "-o", help="Output file (default: stdout)")

    # Verify subcommand
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify an SD-JWT VP",
        description="Verify an SD-JWT Verifiable Presentation.",
    )
    verify_parser.add_argument(
        "--sd-jwt-vp", required=True, help="File containing the SD-JWT VP to verify"
    )
    verify_parser.add_argument(
        "--issuer-key", required=True, help="Issuer's public key (JWK file)"
    )
    verify_parser.add_argument(
        "--holder-key", required=True, help="Holder's public key (JWK file)"
    )
    verify_parser.add_argument("--nonce", help="Expected nonce")
    verify_parser.add_argument("--audience", help="Expected audience")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "issue":
        # Load SD-JWT-VC
        sd_jwt_vc = Path(args.sd_jwt_vc).read_text().strip()

        # Load holder private key
        private_key, _ = _load_private_key(args.key)

        # Load evidence if provided
        evidence = None
        if args.evidence:
            evidence = json.loads(Path(args.evidence).read_text())
            if not isinstance(evidence, list):
                evidence = [evidence]

        # Determine disclosures
        disclosures = args.disclosures  # None means all, [] means none

        # Issue VP
        vp = issue_sd_jwt_vp(
            sd_jwt_vc,
            private_key,
            disclosures=disclosures,
            evidence=evidence,
            nonce=args.nonce,
            audience=args.audience,
            holder_did=args.holder_did,
        )

        # Output
        if args.output:
            Path(args.output).write_text(vp + "\n")
            print(f"SD-JWT VP written to {args.output}", file=sys.stderr)
        else:
            print(vp)

    elif args.command == "verify":
        # Load SD-JWT VP
        sd_jwt_vp = Path(args.sd_jwt_vp).read_text().strip()

        # Load keys
        issuer_public_key = _load_public_key(args.issuer_key)
        holder_public_key = _load_public_key(args.holder_key)

        try:
            result = verify_sd_jwt_vp(
                sd_jwt_vp,
                issuer_public_key,
                holder_public_key,
                expected_nonce=args.nonce,
                expected_audience=args.audience,
            )
            print(json.dumps(result, indent=2))
        except VerificationError as e:
            print(f"Verification failed: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
