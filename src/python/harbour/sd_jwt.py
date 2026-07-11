"""SD-JWT-VC — IETF SD-JWT-based Verifiable Credentials.

Provides issuance and verification of SD-JWT-VC credentials with selective
disclosure per RFC 9901, using ES256 (P-256) or EdDSA (Ed25519) algorithms.

Supports both flat and structured (nested) selective disclosure:
  - Flat: ``disclosable=["email", "duns"]`` — top-level claims
  - Structured: ``disclosable=["credentialSubject.email"]`` — nested paths

CLI Usage:
    python -m harbour.sd_jwt --help
    python -m harbour.sd_jwt issue --help
    python -m harbour.sd_jwt verify --help
"""

import argparse
import base64
import copy
import hashlib
import json
import secrets
import sys
from pathlib import Path
from typing import Any

from joserfc import jws

from harbour._crypto import import_private_key as _import_private_key
from harbour._crypto import import_public_key as _import_public_key
from harbour._crypto import resolve_private_key_alg as _resolve_alg
from harbour._crypto import resolve_public_key_alg as _alg_for_key
from harbour.keys import PrivateKey, PublicKeyType
from harbour.verifier import VerificationError

# SD-JWT uses ~-delimited format: <issuer-jwt>~<disclosure1>~<disclosure2>~...~
SD_JWT_SEPARATOR = "~"


def _create_disclosure(claim_name: str, claim_value: Any) -> tuple[str, str]:
    """Create a single SD-JWT disclosure.

    Returns:
        Tuple of (base64url-encoded disclosure, base64url-encoded SHA-256 digest).
    """
    salt = secrets.token_urlsafe(16)
    disclosure_array = [salt, claim_name, claim_value]
    disclosure_json = json.dumps(disclosure_array, ensure_ascii=False).encode("utf-8")
    disclosure_b64 = base64.urlsafe_b64encode(disclosure_json).rstrip(b"=").decode()
    digest = (
        base64.urlsafe_b64encode(
            hashlib.sha256(disclosure_b64.encode("ascii")).digest()
        )
        .rstrip(b"=")
        .decode()
    )
    return disclosure_b64, digest


def _apply_structured_disclosures(
    payload: dict, disclosable: list[str | list[str]]
) -> tuple[dict, list[str]]:
    """Apply structured selective disclosure to a nested payload.

    Places ``_sd`` digests at the correct nesting level per RFC 9901 §6.2.
    Each disclosable entry is either a **list of key segments** (exact keys,
    safe for keys that themselves contain dots, e.g.
    ``["credentialSubject", "harbour.gx:labelLevel"]``) or a **dot-separated
    string** (``"credentialSubject.email"``; a simple non-dotted name is a
    top-level claim).

    Args:
        payload: The claims dict (will be deep-copied, not mutated).
        disclosable: Claim paths as segment lists or dot-separated strings.

    Returns:
        Tuple of (modified payload with _sd arrays, list of disclosure strings).

    Raises:
        ValueError: if a declared path does not resolve to an existing claim —
            a declared-but-missing disclosure is a caller bug, and skipping it
            would silently issue the claim in plaintext.
    """
    result = copy.deepcopy(payload)
    disclosures: list[str] = []

    for path in disclosable:
        parts = path.split(".") if isinstance(path, str) else list(path)
        if not parts:
            raise ValueError("empty disclosable path")
        leaf_key = parts[-1]

        # Navigate to the parent object
        parent = result
        for part in parts[:-1]:
            if isinstance(parent, dict) and part in parent:
                parent = parent[part]
            else:
                raise ValueError(f"disclosable path not found in claims: {parts!r}")
        if not isinstance(parent, dict) or leaf_key not in parent:
            raise ValueError(f"disclosable path not found in claims: {parts!r}")

        value = parent.pop(leaf_key)
        disc_b64, digest = _create_disclosure(leaf_key, value)
        disclosures.append(disc_b64)
        parent.setdefault("_sd", []).append(digest)

    return result, disclosures


def build_sd_jwt_payload(
    claims: dict,
    *,
    vct: str,
    disclosable: list[str | list[str]] | None = None,
    cnf: dict | None = None,
) -> tuple[dict, list[str]]:
    """Build the issuer SD-JWT payload (with ``_sd`` digests) and its disclosures.

    This is the salt-fixing step of issuance, split out from signing so callers
    can compute a stable hash of the payload before signing — e.g. the Merkle
    leaf for batched credential evidence (the leaf is over the issuer payload,
    so salts must be fixed first; see docs/specs/batched-credential-evidence.md
    §4.1). The returned payload may be augmented (e.g. an ``evidence`` member
    added) and then handed to :func:`sign_sd_jwt`.

    Args:
        claims: Credential claims dict (flat or nested).
        vct: Verifiable Credential Type URI.
        disclosable: Claim names/paths to make selectively disclosable
            (segment lists for exact keys — required when a key contains a
            dot — or dot-separated strings; RFC 9901 §6). Every path MUST
            resolve (ValueError otherwise).
        cnf: Confirmation key (holder's public key JWK for key binding).

    Returns:
        ``(payload, disclosures)`` — the issuer payload and the base64url
        disclosure strings (salts already fixed).
    """
    disclosable = disclosable or []
    payload = {**claims, "vct": vct}
    payload, disclosures = _apply_structured_disclosures(payload, disclosable)
    if disclosures:
        payload["_sd_alg"] = "sha-256"
    if cnf is not None:
        payload["cnf"] = cnf
    return payload, disclosures


def sign_sd_jwt(
    payload: dict,
    disclosures: list[str],
    private_key: PrivateKey,
    *,
    alg: str | None = None,
    x5c: list[str] | None = None,
    kid: str | None = None,
) -> str:
    """Sign a prepared SD-JWT payload and assemble the compact SD-JWT.

    Counterpart of :func:`build_sd_jwt_payload`: signs the (possibly augmented)
    issuer payload and appends the previously-built disclosures.

    Args:
        kid: Verification-method DID URL naming the signing key in the
            issuer's DID document (ADR-006 mandate signing).

    Returns:
        SD-JWT compact string: ``<issuer-jwt>~<disclosure1>~...~``
    """
    alg = _resolve_alg(private_key, alg)
    header = {"alg": alg, "typ": "vc+sd-jwt"}
    if kid is not None:
        header["kid"] = kid
    if x5c is not None:
        header["x5c"] = x5c
    payload_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    key = _import_private_key(private_key, alg)
    issuer_jwt = jws.serialize_compact(header, payload_bytes, key, algorithms=[alg])
    parts = [issuer_jwt] + disclosures + [""]
    return SD_JWT_SEPARATOR.join(parts)


def issue_sd_jwt_vc(
    claims: dict,
    private_key: PrivateKey,
    *,
    vct: str,
    disclosable: list[str | list[str]] | None = None,
    alg: str | None = None,
    x5c: list[str] | None = None,
    cnf: dict | None = None,
) -> str:
    """Issue an SD-JWT-VC credential with selective disclosure.

    Supports both flat and structured (nested) claims per RFC 9901 §6:
      - Flat: ``claims={"email": "a@b.com"}, disclosable=["email"]``
      - Structured: ``claims={"credentialSubject": {"email": "a@b.com"}},
        disclosable=["credentialSubject.email"]``

    Thin wrapper over :func:`build_sd_jwt_payload` + :func:`sign_sd_jwt`.

    Args:
        claims: Credential claims dict (flat or nested).
        private_key: Issuer's private key (P-256 or Ed25519).
        vct: Verifiable Credential Type URI.
        disclosable: Claim names/paths to make selectively disclosable.
        alg: Algorithm override (default: ES256 for P-256).
        x5c: X.509 certificate chain for JOSE header.
        cnf: Confirmation key (holder's public key JWK for key binding).

    Returns:
        SD-JWT compact string: ``<issuer-jwt>~<disclosure1>~...~``
    """
    payload, disclosures = build_sd_jwt_payload(
        claims, vct=vct, disclosable=disclosable, cnf=cnf
    )
    return sign_sd_jwt(payload, disclosures, private_key, alg=alg, x5c=x5c)


def _collect_sd_digests(obj: Any) -> set[str]:
    """Recursively collect all _sd digests from a nested payload."""
    digests: set[str] = set()
    if isinstance(obj, dict):
        digests.update(obj.get("_sd", []))
        for v in obj.values():
            digests.update(_collect_sd_digests(v))
    elif isinstance(obj, list):
        for item in obj:
            digests.update(_collect_sd_digests(item))
    return digests


def _insert_disclosure_recursive(
    obj: dict, claim_name: str, claim_value: Any, digest: str
) -> bool:
    """Recursively find the _sd array containing this digest and insert the claim.

    Returns True if the digest was found and the claim was inserted.
    """
    if isinstance(obj, dict):
        sd_array = obj.get("_sd", [])
        if digest in sd_array:
            obj[claim_name] = claim_value
            sd_array.remove(digest)
            if not sd_array:
                del obj["_sd"]
            return True
            # Recurse into nested objects
        for v in obj.values():
            if isinstance(v, dict):
                if _insert_disclosure_recursive(v, claim_name, claim_value, digest):
                    return True
    return False


def _clean_sd_metadata(obj: Any) -> Any:
    """Remove remaining _sd arrays and _sd_alg from the processed payload."""
    if isinstance(obj, dict):
        return {
            k: _clean_sd_metadata(v)
            for k, v in obj.items()
            if k not in ("_sd", "_sd_alg")
        }
    elif isinstance(obj, list):
        return [_clean_sd_metadata(item) for item in obj]
    return obj


def verify_sd_jwt_vc(
    sd_jwt: str,
    public_key: PublicKeyType,
    *,
    expected_vct: str | None = None,
) -> dict:
    """Verify an SD-JWT-VC and return all disclosed claims.

    Supports recursive ``_sd`` processing per RFC 9901 §7.1: digests may
    appear at any nesting level in the payload.

    Args:
        sd_jwt: SD-JWT compact string (``<issuer-jwt>~<disclosure1>~...~``).
        public_key: Issuer's public key (P-256 or Ed25519).
        expected_vct: If provided, verify the vct claim matches.

    Returns:
        Dict with all disclosed claims (always-disclosed + selectively-disclosed),
        preserving the original nesting structure.

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

    # Collect all _sd digests recursively
    all_digests = _collect_sd_digests(payload)

    # Process each disclosure: find its matching _sd digest and insert
    for disc_b64 in disclosure_strings:
        disc_hash = (
            base64.urlsafe_b64encode(hashlib.sha256(disc_b64.encode("ascii")).digest())
            .rstrip(b"=")
            .decode()
        )
        if disc_hash not in all_digests:
            raise VerificationError(
                f"Disclosure hash {disc_hash[:16]}... not found in _sd digests"
            )
        all_digests.discard(disc_hash)

        # Decode disclosure
        disc_json = base64.urlsafe_b64decode(disc_b64 + "=" * (-len(disc_b64) % 4))
        disc_array = json.loads(disc_json)
        if len(disc_array) != 3:
            raise VerificationError(
                "Invalid disclosure format: expected [salt, name, value]"
            )
        _, claim_name, claim_value = disc_array

        # Insert the claim at the correct nesting level
        if not _insert_disclosure_recursive(
            payload, claim_name, claim_value, disc_hash
        ):
            raise VerificationError(
                f"Could not locate _sd digest for claim {claim_name!r}"
            )

    # Clean up _sd metadata from the result
    return _clean_sd_metadata(payload)


def main():
    """CLI entry point for SD-JWT-VC operations."""
    parser = argparse.ArgumentParser(
        prog="harbour.sd_jwt",
        description="Harbour SD-JWT-VC CLI - Issue and verify SD-JWT-VC credentials",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Issue an SD-JWT-VC
  python -m harbour.sd_jwt issue --claims claims.json --key key.jwk --vct https://example.com/vc/type

  # Verify an SD-JWT-VC
  python -m harbour.sd_jwt verify --sd-jwt token.txt --public-key key.jwk
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Issue subcommand
    issue_parser = subparsers.add_parser(
        "issue",
        help="Issue an SD-JWT-VC with selective disclosure",
        description="Issue an SD-JWT-VC credential with configurable selective disclosure claims.",
    )
    issue_parser.add_argument(
        "--claims", required=True, help="JSON file with credential claims"
    )
    issue_parser.add_argument(
        "--key", required=True, help="Private key file (JWK format)"
    )
    issue_parser.add_argument(
        "--vct", required=True, help="Verifiable Credential Type URI"
    )
    issue_parser.add_argument(
        "--disclose",
        action="append",
        default=[],
        help="Claim name to make selectively disclosable (can be repeated)",
    )
    issue_parser.add_argument("--output", "-o", help="Output file (default: stdout)")

    # Verify subcommand
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify an SD-JWT-VC and show disclosed claims",
        description="Verify an SD-JWT-VC signature and display all disclosed claims.",
    )
    verify_parser.add_argument(
        "--sd-jwt", required=True, help="SD-JWT file or '-' for stdin"
    )
    verify_parser.add_argument(
        "--public-key", required=True, help="Public key file (JWK format)"
    )
    verify_parser.add_argument("--vct", help="Expected VCT (optional validation)")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "issue":
        from harbour._crypto import load_private_key

        claims_data = json.loads(Path(args.claims).read_text(encoding="utf-8"))
        private_key, _ = load_private_key(args.key)

        sd_jwt_token = issue_sd_jwt_vc(
            claims_data,
            private_key,
            vct=args.vct,
            disclosable=args.disclose or None,
        )

        if args.output:
            Path(args.output).write_text(sd_jwt_token, encoding="utf-8")
            print(f"SD-JWT-VC written to {args.output}", file=sys.stderr)
        else:
            print(sd_jwt_token)

    elif args.command == "verify":
        from harbour._crypto import load_public_key as _load_public_key

        if args.sd_jwt == "-":
            sd_jwt_token = sys.stdin.read().strip()
        else:
            sd_jwt_token = Path(args.sd_jwt).read_text(encoding="utf-8").strip()

        public_key = _load_public_key(args.public_key)

        try:
            disclosed = verify_sd_jwt_vc(
                sd_jwt_token, public_key, expected_vct=args.vct
            )
            print(json.dumps(disclosed, indent=2))
        except VerificationError as e:
            print(f"Verification failed: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
