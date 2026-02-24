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
from pathlib import Path

from harbour._crypto import import_private_key as _import_private_key
from harbour._crypto import import_public_key as _import_public_key
from harbour._crypto import load_private_key as _load_private_key
from harbour._crypto import load_public_key as _load_public_key
from harbour._crypto import resolve_private_key_alg as _resolve_alg
from harbour._crypto import resolve_public_key_alg as _alg_for_key
from harbour.keys import PrivateKey, PublicKeyType
from harbour.verifier import VerificationError
from joserfc import jws

# SD-JWT uses ~-delimited format
SD_JWT_SEPARATOR = "~"


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
        evidence: Evidence objects to include in the VP (e.g., transaction intent).
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

    if nonce:
        vp_payload["nonce"] = nonce

    if audience:
        vp_payload["aud"] = audience

    if evidence:
        vp_payload["vp"]["evidence"] = evidence

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
    kb_payload = {
        "iat": int(time.time()),
        "sd_hash": base64.urlsafe_b64encode(
            hashlib.sha256(
                (
                    issuer_jwt
                    + SD_JWT_SEPARATOR
                    + SD_JWT_SEPARATOR.join(selected_disclosures)
                ).encode("ascii")
            ).digest()
        )
        .rstrip(b"=")
        .decode(),
    }

    if nonce:
        kb_payload["nonce"] = nonce
    if audience:
        kb_payload["aud"] = audience

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
    sd_material = issuer_jwt + SD_JWT_SEPARATOR + SD_JWT_SEPARATOR.join(disclosures)
    expected_sd_hash = (
        base64.urlsafe_b64encode(hashlib.sha256(sd_material.encode("ascii")).digest())
        .rstrip(b"=")
        .decode()
    )

    if kb_payload.get("sd_hash") != expected_sd_hash:
        raise VerificationError("SD hash mismatch in KB-JWT")

    # 6. Verify nonce
    if expected_nonce is not None:
        if vp_payload.get("nonce") != expected_nonce:
            raise VerificationError(
                f"Nonce mismatch: expected {expected_nonce!r}, got {vp_payload.get('nonce')!r}"
            )
        if kb_payload.get("nonce") != expected_nonce:
            raise VerificationError("Nonce mismatch in KB-JWT")

    # 7. Verify audience
    if expected_audience is not None:
        if vp_payload.get("aud") != expected_audience:
            raise VerificationError(
                f"Audience mismatch: expected {expected_audience!r}, got {vp_payload.get('aud')!r}"
            )
        if kb_payload.get("aud") != expected_audience:
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
    vp_obj = vp_payload.get("vp", {})
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
