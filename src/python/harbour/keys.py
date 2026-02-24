"""Key generation, DID-key encoding, and JWK export for Ed25519 and P-256.

CLI Usage:
    python -m harbour.keys --help
    python -m harbour.keys generate --algorithm ES256
    python -m harbour.keys convert --input key.jwk --format did-key
"""

import argparse
import base64
import json
import sys

import base58
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    generate_private_key,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# Multicodec prefixes (varint-encoded)
_ED25519_MULTICODEC_PREFIX = b"\xed\x01"  # ed25519-pub 0xed
_P256_MULTICODEC_PREFIX = b"\x80\x24"  # p256-pub 0x1200

# Union type for keys supported by this module
PrivateKey = Ed25519PrivateKey | EllipticCurvePrivateKey
PublicKeyType = Ed25519PublicKey | EllipticCurvePublicKey


# ---------------------------------------------------------------------------
# Ed25519 keys
# ---------------------------------------------------------------------------


def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a fresh Ed25519 key pair."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def public_key_to_multibase(public_key: Ed25519PublicKey) -> str:
    """Encode an Ed25519 public key as multibase base58btc (z6Mk...)."""
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return "z" + base58.b58encode(_ED25519_MULTICODEC_PREFIX + raw).decode()


def public_key_to_did_key(public_key: Ed25519PublicKey) -> str:
    """Derive a did:key identifier from an Ed25519 public key."""
    mb = public_key_to_multibase(public_key)
    return f"did:key:{mb}"


def keypair_to_jwk(private_key: Ed25519PrivateKey) -> dict:
    """Export an Ed25519 private key as a JWK dict (OKP/Ed25519)."""
    raw_private = private_key.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    raw_public = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url(raw_public),
        "d": _b64url(raw_private),
    }


def public_key_to_jwk(public_key: Ed25519PublicKey) -> dict:
    """Export an Ed25519 public key as a JWK dict (OKP/Ed25519)."""
    raw_public = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url(raw_public),
    }


# ---------------------------------------------------------------------------
# P-256 (ES256) keys
# ---------------------------------------------------------------------------


def generate_p256_keypair() -> tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    """Generate a fresh P-256 (secp256r1) key pair."""
    private_key = generate_private_key(SECP256R1())
    return private_key, private_key.public_key()


def p256_keypair_to_jwk(private_key: EllipticCurvePrivateKey) -> dict:
    """Export a P-256 private key as a JWK dict (EC/P-256)."""
    numbers = private_key.private_numbers()
    pub = numbers.public_numbers
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(pub.x.to_bytes(32, "big")),
        "y": _b64url(pub.y.to_bytes(32, "big")),
        "d": _b64url(numbers.private_value.to_bytes(32, "big")),
    }


def p256_public_key_to_jwk(public_key: EllipticCurvePublicKey) -> dict:
    """Export a P-256 public key as a JWK dict (EC/P-256)."""
    numbers = public_key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(numbers.x.to_bytes(32, "big")),
        "y": _b64url(numbers.y.to_bytes(32, "big")),
    }


def p256_public_key_to_multibase(public_key: EllipticCurvePublicKey) -> str:
    """Encode a P-256 public key as multibase base58btc (zDn...)."""
    # Compressed SEC1 encoding (33 bytes)
    compressed = public_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    return "z" + base58.b58encode(_P256_MULTICODEC_PREFIX + compressed).decode()


def p256_public_key_to_did_key(public_key: EllipticCurvePublicKey) -> str:
    """Derive a did:key identifier from a P-256 public key."""
    mb = p256_public_key_to_multibase(public_key)
    return f"did:key:{mb}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64url(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    """Base64url decode with padding restoration."""
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    """CLI entry point for key operations."""
    parser = argparse.ArgumentParser(
        prog="harbour.keys",
        description="Harbour Key Management CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m harbour.keys generate --algorithm ES256 --output key.jwk
  python -m harbour.keys generate --algorithm EdDSA
  python -m harbour.keys convert --input key.jwk --format did-key
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Generate subcommand
    gen_parser = subparsers.add_parser(
        "generate",
        help="Generate a new keypair (Ed25519 or P-256)",
        description="Generate a cryptographic keypair for VC signing.",
    )
    gen_parser.add_argument(
        "--algorithm",
        "-a",
        choices=["ES256", "EdDSA"],
        default="ES256",
        help="Algorithm: ES256 (P-256) or EdDSA (Ed25519). Default: ES256",
    )
    gen_parser.add_argument(
        "--output",
        "-o",
        help="Output file for JWK (default: stdout)",
    )
    gen_parser.add_argument(
        "--public-only",
        action="store_true",
        help="Output only public key",
    )

    # Convert subcommand
    conv_parser = subparsers.add_parser(
        "convert",
        help="Convert key formats (JWK, multibase, DID:key)",
        description="Convert between key representations.",
    )
    conv_parser.add_argument(
        "--input",
        "-i",
        required=True,
        help="Input key file (JWK format)",
    )
    conv_parser.add_argument(
        "--format",
        "-f",
        choices=["jwk", "did-key", "multibase"],
        default="did-key",
        help="Output format. Default: did-key",
    )

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "generate":
        if args.algorithm == "ES256":
            priv, pub = generate_p256_keypair()
            if args.public_only:
                jwk = p256_public_key_to_jwk(pub)
            else:
                jwk = p256_keypair_to_jwk(priv)
        else:  # EdDSA
            priv, pub = generate_ed25519_keypair()
            if args.public_only:
                jwk = public_key_to_jwk(pub)
            else:
                jwk = keypair_to_jwk(priv)

        output = json.dumps(jwk, indent=2)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"Key written to {args.output}", file=sys.stderr)
        else:
            print(output)

    elif args.command == "convert":
        from pathlib import Path

        jwk = json.loads(Path(args.input).read_text())

        # Determine key type and convert
        if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
            # Reconstruct Ed25519 public key
            x_bytes = _b64url_decode(jwk["x"])
            pub = Ed25519PublicKey.from_public_bytes(x_bytes)
            if args.format == "did-key":
                print(public_key_to_did_key(pub))
            elif args.format == "multibase":
                print(public_key_to_multibase(pub))
            else:
                print(json.dumps(public_key_to_jwk(pub), indent=2))
        elif jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
            # Reconstruct P-256 public key
            from cryptography.hazmat.primitives.asymmetric.ec import (
                EllipticCurvePublicNumbers,
            )

            x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
            y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
            numbers = EllipticCurvePublicNumbers(x, y, SECP256R1())
            pub = numbers.public_key()
            if args.format == "did-key":
                print(p256_public_key_to_did_key(pub))
            elif args.format == "multibase":
                print(p256_public_key_to_multibase(pub))
            else:
                print(json.dumps(p256_public_key_to_jwk(pub), indent=2))
        else:
            print(
                f"Unsupported key type: {jwk.get('kty')}/{jwk.get('crv')}",
                file=sys.stderr,
            )
            sys.exit(1)


if __name__ == "__main__":
    main()
