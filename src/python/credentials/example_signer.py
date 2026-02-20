"""Generate signed VC-JOSE-COSE JWT artifacts from example credentials.

Reads expanded (human-readable) examples from examples/*.json and produces
wire-format signed JWTs plus decoded companion files in examples/signed/.

Output per credential:
  - <name>.jwt                      — VC-JOSE-COSE compact JWS (wire format)
  - <name>.decoded.json             — Decoded JWT header + payload
  - <name>.evidence-vp.jwt          — Evidence VP JWT (if evidence present)
  - <name>.evidence-vp.decoded.json — Decoded evidence VP with inner VCs decoded

Source examples/*.json are NEVER modified.

CLI Usage:
    python -m credentials.example_signer --help
    python -m credentials.example_signer examples/
    python -m credentials.example_signer examples/vc.json --key my-key.jwk
"""

import argparse
import base64
import copy
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    EllipticCurvePrivateNumbers,
    EllipticCurvePublicNumbers,
)
from harbour.keys import p256_public_key_to_did_key
from harbour.signer import sign_vc_jose, sign_vp_jose


def _find_repo_root() -> Path:
    """Find the repository root by looking for common markers."""
    current = Path(__file__).resolve().parent
    while current != current.parent:
        if (current / ".git").is_dir() or (current / "submodules").is_dir():
            return current
        current = current.parent
    return Path.cwd()


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _decode_jwt(token: str) -> dict:
    """Decode a JWT into header and payload (no verification)."""
    parts = token.split(".")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    return {"header": header, "payload": payload}


def load_test_p256_keypair(fixtures_dir: Path | None = None):
    """Load the committed P-256 test keypair."""
    if fixtures_dir is None:
        repo_root = _find_repo_root()
        fixtures_dir = (
            repo_root / "submodules" / "harbour-credentials" / "tests" / "fixtures"
        )
        if not fixtures_dir.is_dir():
            fixtures_dir = repo_root / "tests" / "fixtures"
    jwk_path = fixtures_dir / "test-keypair-p256.json"
    jwk = json.loads(jwk_path.read_text())
    x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
    d = int.from_bytes(_b64url_decode(jwk["d"]), "big")
    pub_numbers = EllipticCurvePublicNumbers(x, y, SECP256R1())
    priv_numbers = EllipticCurvePrivateNumbers(d, pub_numbers)
    private_key = priv_numbers.private_key()
    return private_key, private_key.public_key()


def sign_evidence_vp(vp: dict, private_key, kid: str) -> str:
    """Sign an evidence VP and its inner VCs as VC-JOSE-COSE JWTs.

    Takes the expanded VP object, signs each inner VC, replaces them with
    JWT strings, then signs the VP envelope.
    """
    clean_vp = {
        "@context": vp.get("@context", ["https://www.w3.org/ns/credentials/v2"]),
        "type": vp.get("type", ["VerifiablePresentation"]),
    }

    if "holder" in vp:
        clean_vp["holder"] = vp["holder"]

    # Sign inner VCs
    inner_vcs = vp.get("verifiableCredential", [])
    inner_jwts = []
    for vc in inner_vcs:
        if isinstance(vc, dict):
            inner_jwt = sign_vc_jose(vc, private_key, kid=kid)
            inner_jwts.append(inner_jwt)
        else:
            # Already a JWT string
            inner_jwts.append(vc)
    if inner_jwts:
        clean_vp["verifiableCredential"] = inner_jwts

    nonce = vp.get("nonce")
    return sign_vp_jose(clean_vp, private_key, kid=kid, nonce=nonce)


def decode_evidence_vp(vp_jwt: str) -> dict:
    """Decode an evidence VP JWT with nested inner VC JWTs decoded inline."""
    decoded = _decode_jwt(vp_jwt)
    inner_vcs = decoded["payload"].get("verifiableCredential", [])
    decoded_inners = []
    for inner in inner_vcs:
        if isinstance(inner, str) and "." in inner:
            inner_decoded = _decode_jwt(inner)
            decoded_inners.append(
                {
                    "_jwt": inner,
                    "_decoded": inner_decoded,
                }
            )
        else:
            decoded_inners.append(inner)
    if decoded_inners:
        decoded["payload"]["verifiableCredential"] = decoded_inners
    return decoded


def process_example(example_path: Path, private_key, kid: str, output_dir: Path):
    """Process a single example credential.

    Reads the expanded example, signs evidence and outer VC, writes all
    artifacts to output_dir. Never modifies the source file.
    """
    vc = json.loads(example_path.read_text())
    stem = example_path.stem

    evidence_vp_jwt = None

    # Sign evidence VPs if present (work on a copy for outer signing)
    vc_for_signing = copy.deepcopy(vc)
    if "evidence" in vc_for_signing:
        for ev in vc_for_signing["evidence"]:
            vp_obj = ev.get("verifiablePresentation")
            if isinstance(vp_obj, dict):
                # Expanded VP — sign it
                evidence_vp_jwt = sign_evidence_vp(vp_obj, private_key, kid)
                # Replace with JWT string for outer VC signing
                ev["verifiablePresentation"] = evidence_vp_jwt

    # Sign the outer credential
    vc_jwt = sign_vc_jose(vc_for_signing, private_key, kid=kid)

    # Write outputs
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Outer VC JWT
    jwt_path = output_dir / f"{stem}.jwt"
    jwt_path.write_text(vc_jwt + "\n")

    # 2. Decoded outer JWT
    decoded = _decode_jwt(vc_jwt)
    decoded_path = output_dir / f"{stem}.decoded.json"
    decoded_obj = {
        "_description": f"Decoded VC-JOSE-COSE JWT for {stem}",
        **decoded,
    }
    decoded_path.write_text(
        json.dumps(decoded_obj, indent=2, ensure_ascii=False) + "\n"
    )

    # 3. Evidence VP JWT (if applicable)
    if evidence_vp_jwt:
        ev_jwt_path = output_dir / f"{stem}.evidence-vp.jwt"
        ev_jwt_path.write_text(evidence_vp_jwt + "\n")

        # 4. Decoded evidence VP
        ev_decoded = decode_evidence_vp(evidence_vp_jwt)
        ev_decoded_path = output_dir / f"{stem}.evidence-vp.decoded.json"
        ev_decoded_obj = {
            "_description": f"Decoded evidence VP JWT for {stem}",
            **ev_decoded,
        }
        ev_decoded_path.write_text(
            json.dumps(ev_decoded_obj, indent=2, ensure_ascii=False) + "\n"
        )

    return jwt_path


def main():
    """CLI entry point for example signing."""
    parser = argparse.ArgumentParser(
        prog="credentials.example_signer",
        description="Sign example credentials for testing and documentation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m credentials.example_signer examples/
  python -m credentials.example_signer examples/vc.json --key my-key.jwk
  python -m credentials.example_signer examples/ --output-dir examples/signed/
        """,
    )

    parser.add_argument(
        "examples",
        nargs="+",
        help="Example credential files or directories",
    )
    parser.add_argument(
        "--key",
        "-k",
        help="Signing key (JWK file). Default: test key from fixtures",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        help="Output directory. Default: <input-dir>/signed/",
    )

    args = parser.parse_args()

    # Load key
    if args.key:
        from harbour.signer import _load_private_key

        private_key, _ = _load_private_key(args.key)
        public_key = private_key.public_key()
    else:
        private_key, public_key = load_test_p256_keypair()

    kid = p256_public_key_to_did_key(public_key)
    kid_vm = f"{kid}#{kid.split(':')[-1]}"

    # Collect example files
    example_files = []
    for path_str in args.examples:
        path = Path(path_str)
        if path.is_dir():
            example_files.extend(sorted(path.glob("*.json")))
        elif path.is_file():
            example_files.append(path)
        else:
            print(f"Warning: {path} not found", file=sys.stderr)

    if not example_files:
        print("No example credentials found", file=sys.stderr)
        sys.exit(1)

    # Determine output directory
    if args.output_dir:
        output_dir = Path(args.output_dir)
    else:
        # Use first input's parent/signed/
        output_dir = example_files[0].parent / "signed"

    print(f"Signing {len(example_files)} example credentials...")
    print(f"  kid: {kid_vm}")
    print(f"  output: {output_dir}")

    for path in example_files:
        jwt_path = process_example(path, private_key, kid_vm, output_dir)
        print(f"  {path.name} -> {jwt_path.name}")

    # List all generated files
    signed_files = sorted(output_dir.iterdir())
    print(f"\nGenerated {len(signed_files)} files in {output_dir}/")

    print("Done.")


if __name__ == "__main__":
    main()
