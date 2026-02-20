"""SD-JWT-VC — IETF SD-JWT-based Verifiable Credentials.

Provides issuance and verification of SD-JWT-VC credentials with selective
disclosure, using ES256 (P-256) or EdDSA (Ed25519) algorithms.

CLI Usage:
    python -m harbour.sd_jwt --help
    python -m harbour.sd_jwt issue --help
    python -m harbour.sd_jwt verify --help
"""

import argparse
import base64
import hashlib
import json
import secrets
import sys
from pathlib import Path

from harbour.keys import PrivateKey, PublicKeyType
from harbour.signer import _import_private_key, _resolve_alg
from harbour.verifier import VerificationError, _alg_for_key, _import_public_key
from joserfc import jws

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
            disclosure_json = json.dumps(disclosure_array, ensure_ascii=False).encode(
                "utf-8"
            )
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
    disclosed_claims = {k: v for k, v in payload.items() if k not in ("_sd", "_sd_alg")}

    for disc_b64 in disclosure_strings:
        # Verify this disclosure matches a digest in _sd
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

        # Decode and extract claim
        disc_json = base64.urlsafe_b64decode(disc_b64 + "=" * (-len(disc_b64) % 4))
        disc_array = json.loads(disc_json)
        if len(disc_array) != 3:
            raise VerificationError(
                "Invalid disclosure format: expected [salt, name, value]"
            )
        _, claim_name, claim_value = disc_array
        disclosed_claims[claim_name] = claim_value

    return disclosed_claims


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
        # Load claims
        claims_data = json.loads(Path(args.claims).read_text())
        # Load private key
        priv_key_data = json.loads(Path(args.key).read_text())
        # For now, assume JWK format - would need conversion logic
        print(
            f"Issue command not yet fully implemented (claims: {len(claims_data)} keys, key type: {priv_key_data.get('kty', 'unknown')})",
            file=sys.stderr,
        )
        sys.exit(1)

    elif args.command == "verify":
        # Load SD-JWT
        if args.sd_jwt == "-":
            sd_jwt_token = sys.stdin.read().strip()
        else:
            sd_jwt_token = Path(args.sd_jwt).read_text().strip()
        # Load public key
        pub_key_data = json.loads(Path(args.public_key).read_text())
        print(
            f"Verify command not yet fully implemented (token length: {len(sd_jwt_token)}, key type: {pub_key_data.get('kty', 'unknown')})",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
