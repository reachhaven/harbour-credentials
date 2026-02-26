"""Sign Verifiable Credentials and Presentations as VC-JOSE-COSE compact JWS.

CLI Usage:
    python -m harbour.signer --help
    python -m harbour.signer sign-vc --credential vc.json --key key.jwk
    python -m harbour.signer sign-vp --presentation vp.json --key key.jwk
"""

import argparse
import json
import sys
from pathlib import Path

from harbour._crypto import import_private_key as _import_private_key
from harbour._crypto import load_private_key as _load_private_key
from harbour._crypto import resolve_private_key_alg as _resolve_alg
from harbour.keys import PrivateKey
from joserfc import jws


def sign_vc_jose(
    vc: dict,
    private_key: PrivateKey,
    *,
    alg: str | None = None,
    kid: str | None = None,
    x5c: list[str] | None = None,
) -> str:
    """Sign a VC as VC-JOSE-COSE compact JWS.

    Args:
        vc: The Verifiable Credential JSON-LD dict.
        private_key: Private key (P-256 for ES256, or Ed25519 for EdDSA).
        alg: Algorithm override. Default: ES256 for P-256, EdDSA for Ed25519.
        kid: Key ID (DID verification method) for the JOSE header.
        x5c: X.509 certificate chain (base64 DER) for the JOSE header.

    Returns:
        Compact JWS string (header.payload.signature).
    """
    alg = _resolve_alg(private_key, alg)
    header = _build_header(alg, typ="vc+jwt", kid=kid, x5c=x5c)
    payload = json.dumps(vc, ensure_ascii=False).encode("utf-8")
    key = _import_private_key(private_key, alg)
    return jws.serialize_compact(header, payload, key, algorithms=[alg])


def sign_vp_jose(
    vp: dict,
    private_key: PrivateKey,
    *,
    alg: str | None = None,
    kid: str | None = None,
    nonce: str | None = None,
    audience: str | None = None,
) -> str:
    """Sign a VP as VC-JOSE-COSE compact JWS.

    Args:
        vp: The Verifiable Presentation JSON-LD dict.
        private_key: Private key (P-256 for ES256, or Ed25519 for EdDSA).
        alg: Algorithm override. Default: ES256 for P-256, EdDSA for Ed25519.
        kid: Key ID (DID verification method) for the JOSE header.
        nonce: Challenge nonce for replay protection.
        audience: Intended audience (verifier DID or URL).

    Returns:
        Compact JWS string (header.payload.signature).
    """
    alg = _resolve_alg(private_key, alg)
    header = _build_header(alg, typ="vp+jwt", kid=kid)

    # Add nonce and audience to the VP payload (not header)
    vp_payload = dict(vp)
    if nonce is not None:
        vp_payload["nonce"] = nonce
    if audience is not None:
        vp_payload["aud"] = audience

    payload = json.dumps(vp_payload, ensure_ascii=False).encode("utf-8")
    key = _import_private_key(private_key, alg)
    return jws.serialize_compact(header, payload, key, algorithms=[alg])


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_header(
    alg: str,
    typ: str,
    kid: str | None = None,
    x5c: list[str] | None = None,
) -> dict[str, object]:
    """Build a JOSE protected header."""
    header = {"alg": alg, "typ": typ}
    if kid is not None:
        header["kid"] = kid
    if x5c is not None:
        header["x5c"] = x5c
    return header


def main():
    """CLI entry point for VC/VP signing."""
    parser = argparse.ArgumentParser(
        prog="harbour.signer",
        description="Harbour VC/VP Signer CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m harbour.signer sign-vc --credential vc.json --key key.jwk --output vc.jwt
  python -m harbour.signer sign-vp --presentation vp.json --key key.jwk --nonce abc123
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # sign-vc subcommand
    vc_parser = subparsers.add_parser(
        "sign-vc",
        help="Sign a Verifiable Credential as VC-JOSE-COSE JWS",
        description="Sign a VC JSON-LD document and output compact JWS.",
    )
    vc_parser.add_argument("--credential", "-c", required=True, help="VC JSON file")
    vc_parser.add_argument("--key", "-k", required=True, help="Private key (JWK file)")
    vc_parser.add_argument("--kid", help="Key ID for JOSE header")
    vc_parser.add_argument("--output", "-o", help="Output file (default: stdout)")

    # sign-vp subcommand
    vp_parser = subparsers.add_parser(
        "sign-vp",
        help="Sign a Verifiable Presentation as VP-JOSE-COSE JWS",
        description="Sign a VP JSON-LD document and output compact JWS.",
    )
    vp_parser.add_argument("--presentation", "-p", required=True, help="VP JSON file")
    vp_parser.add_argument("--key", "-k", required=True, help="Private key (JWK file)")
    vp_parser.add_argument("--kid", help="Key ID for JOSE header")
    vp_parser.add_argument("--nonce", help="Challenge nonce for replay protection")
    vp_parser.add_argument("--audience", help="Intended audience (verifier DID or URL)")
    vp_parser.add_argument("--output", "-o", help="Output file (default: stdout)")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "sign-vc":
        vc = json.loads(Path(args.credential).read_text())
        private_key, alg = _load_private_key(args.key)
        jwt = sign_vc_jose(vc, private_key, alg=alg, kid=args.kid)

        if args.output:
            Path(args.output).write_text(jwt)
            print(f"Signed VC written to {args.output}", file=sys.stderr)
        else:
            print(jwt)

    elif args.command == "sign-vp":
        vp = json.loads(Path(args.presentation).read_text())
        private_key, alg = _load_private_key(args.key)
        jwt = sign_vp_jose(
            vp,
            private_key,
            alg=alg,
            kid=args.kid,
            nonce=args.nonce,
            audience=args.audience,
        )

        if args.output:
            Path(args.output).write_text(jwt)
            print(f"Signed VP written to {args.output}", file=sys.stderr)
        else:
            print(jwt)


if __name__ == "__main__":
    main()
