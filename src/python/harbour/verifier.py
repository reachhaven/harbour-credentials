"""Verify VC-JOSE-COSE compact JWS proofs on Verifiable Credentials/Presentations.

Also retains the legacy Ed25519Signature2018 detached-JWS verifier.

CLI Usage:
    python -m harbour.verifier --help
    python -m harbour.verifier verify-vc --jwt vc.jwt --public-key key.jwk
    python -m harbour.verifier verify-vp --jwt vp.jwt --public-key key.jwk
"""

import argparse
import json
import sys
import warnings
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from harbour._crypto import import_public_key as _import_public_key
from harbour._crypto import load_public_key as _load_public_key
from harbour._crypto import resolve_public_key_alg as _alg_for_key
from harbour.keys import (
    PublicKeyType,
    public_key_to_jwk,
)
from joserfc import jws
from joserfc.jwk import OKPKey


class VerificationError(Exception):
    """Raised when a VC/VP proof fails verification."""


def verify_vc_jose(token: str, public_key: PublicKeyType) -> dict:
    """Verify a VC-JOSE-COSE compact JWS and return the VC payload dict.

    Args:
        token: Compact JWS string (header.payload.signature).
        public_key: ES256 (P-256) or EdDSA (Ed25519) public key.

    Returns:
        The verified VC JSON-LD dict.

    Raises:
        VerificationError: If the signature is invalid or the token is malformed.
    """
    return _verify_jose(token, public_key, expected_typ="vc+ld+jwt")


def verify_vp_jose(
    token: str,
    public_key: PublicKeyType,
    *,
    expected_nonce: str | None = None,
    expected_audience: str | None = None,
) -> dict:
    """Verify a VP-JOSE-COSE compact JWS and return the VP payload dict.

    Args:
        token: Compact JWS string (header.payload.signature).
        public_key: ES256 (P-256) or EdDSA (Ed25519) public key.
        expected_nonce: If provided, verify the nonce claim matches.
        expected_audience: If provided, verify the aud claim matches.

    Returns:
        The verified VP JSON-LD dict.

    Raises:
        VerificationError: If the signature, nonce, or audience is invalid.
    """
    payload = _verify_jose(token, public_key, expected_typ="vp+ld+jwt")

    if expected_nonce is not None:
        actual_nonce = payload.get("nonce")
        if actual_nonce != expected_nonce:
            raise VerificationError(
                f"Nonce mismatch: expected {expected_nonce!r}, got {actual_nonce!r}"
            )

    if expected_audience is not None:
        actual_aud = payload.get("aud")
        if actual_aud != expected_audience:
            raise VerificationError(
                f"Audience mismatch: expected {expected_audience!r}, "
                f"got {actual_aud!r}"
            )

    return payload


# ---------------------------------------------------------------------------
# Legacy API (deprecated)
# ---------------------------------------------------------------------------


def verify_vc(signed_vc: dict, public_key: Ed25519PublicKey) -> bool:
    """Verify the Ed25519Signature2018 JWS proof on a signed VC.

    .. deprecated:: 0.2.0
        Use :func:`verify_vc_jose` instead.

    Returns True if valid, raises VerificationError if invalid.
    """
    import copy

    warnings.warn(
        "verify_vc() is deprecated. Use verify_vc_jose() for standard VC-JOSE-COSE.",
        DeprecationWarning,
        stacklevel=2,
    )

    proof = signed_vc.get("proof")
    if not proof:
        raise VerificationError("No proof found in credential")

    jws_value = proof.get("jws")
    if not jws_value:
        raise VerificationError("No jws field in proof")

    vc_without_proof = copy.deepcopy(signed_vc)
    vc_without_proof.pop("proof", None)
    payload = _canonicalize(vc_without_proof)

    parts = jws_value.split("..")
    if len(parts) != 2:
        raise VerificationError(f"Invalid detached JWS format: {jws_value[:50]}...")

    compact_jws = f"{parts[0]}..{parts[1]}"

    jwk_dict = public_key_to_jwk(public_key)
    key = OKPKey.import_key(jwk_dict)

    try:
        jws.deserialize_compact(compact_jws, key, algorithms=["EdDSA"], payload=payload)
    except Exception as e:
        raise VerificationError(f"JWS verification failed: {e}") from e

    return True


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _verify_jose(token: str, public_key: PublicKeyType, expected_typ: str) -> dict:
    """Verify a compact JWS token and return the decoded payload dict."""
    key = _import_public_key(public_key)
    alg = _alg_for_key(public_key)

    # Use a larger header limit to accommodate x5c certificate chains
    registry = jws.JWSRegistry(algorithms=[alg])
    registry.max_header_length = 8192

    try:
        result = jws.deserialize_compact(
            token, key, algorithms=[alg], registry=registry
        )
    except Exception as e:
        raise VerificationError(f"JWS verification failed: {e}") from e

    # Validate typ header
    header = result.headers()
    actual_typ = header.get("typ")
    if actual_typ != expected_typ:
        raise VerificationError(
            f"Unexpected typ: expected {expected_typ!r}, got {actual_typ!r}"
        )

    try:
        payload = json.loads(result.payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise VerificationError(f"Invalid payload JSON: {e}") from e

    return payload


def _canonicalize(obj: dict) -> bytes:
    """Canonical JSON serialization (legacy, used only by verify_vc)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def main():
    """CLI entry point for VC/VP verification."""
    parser = argparse.ArgumentParser(
        prog="harbour.verifier",
        description="Harbour VC/VP Verifier CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m harbour.verifier verify-vc --jwt vc.jwt --public-key key.jwk
  python -m harbour.verifier verify-vp --jwt vp.jwt --public-key key.jwk --nonce abc123
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # verify-vc subcommand
    vc_parser = subparsers.add_parser(
        "verify-vc",
        help="Verify a VC-JOSE-COSE JWS credential",
        description="Verify a VC compact JWS and display the payload.",
    )
    vc_parser.add_argument("--jwt", required=True, help="VC JWT file or '-' for stdin")
    vc_parser.add_argument("--public-key", required=True, help="Public key (JWK file)")

    # verify-vp subcommand
    vp_parser = subparsers.add_parser(
        "verify-vp",
        help="Verify a VP-JOSE-COSE JWS presentation",
        description="Verify a VP compact JWS and display the payload.",
    )
    vp_parser.add_argument("--jwt", required=True, help="VP JWT file or '-' for stdin")
    vp_parser.add_argument("--public-key", required=True, help="Public key (JWK file)")
    vp_parser.add_argument("--nonce", help="Expected nonce (optional validation)")
    vp_parser.add_argument("--audience", help="Expected audience (optional validation)")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "verify-vc":
        if args.jwt == "-":
            token = sys.stdin.read().strip()
        else:
            token = Path(args.jwt).read_text().strip()

        public_key = _load_public_key(args.public_key)

        try:
            payload = verify_vc_jose(token, public_key)
            print(json.dumps(payload, indent=2))
        except VerificationError as e:
            print(f"Verification failed: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "verify-vp":
        if args.jwt == "-":
            token = sys.stdin.read().strip()
        else:
            token = Path(args.jwt).read_text().strip()

        public_key = _load_public_key(args.public_key)

        try:
            payload = verify_vp_jose(
                token,
                public_key,
                expected_nonce=args.nonce,
                expected_audience=args.audience,
            )
            print(json.dumps(payload, indent=2))
        except VerificationError as e:
            print(f"Verification failed: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
