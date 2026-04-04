"""Generate signed VC-JOSE-COSE JWT artifacts from example credentials.

Reads expanded (human-readable) examples from examples/*.json and produces
wire-format signed JWTs plus decoded companion files in examples/signed/.
When given a directory, also processes gaiax/ subdirectory if present,
outputting signed artifacts to each subdirectory's own signed/ folder.

Each role in the trust chain uses a **separate P-256 key** so that the
signed artifacts cryptographically demonstrate who signed what:

  - Trust Anchor key  → self-signed VC, evidence VPs authorising orgs
  - Haven key         → all outer credentials (issuer)
  - Company key       → evidence VPs authorising employees
  - Employee key      → consent VPs for delegated signing

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
    EllipticCurvePrivateKey,
    EllipticCurvePrivateNumbers,
    EllipticCurvePublicNumbers,
)

from harbour.keys import PrivateKey, p256_public_key_to_did_key
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


def _load_jwk_private_key(jwk_path: Path) -> EllipticCurvePrivateKey:
    """Load a P-256 private key from a JWK file."""
    jwk = json.loads(jwk_path.read_text())
    x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
    d = int.from_bytes(_b64url_decode(jwk["d"]), "big")
    pub_numbers = EllipticCurvePublicNumbers(x, y, SECP256R1())
    priv_numbers = EllipticCurvePrivateNumbers(d, pub_numbers)
    return priv_numbers.private_key()


class RoleKeyring:
    """Manages per-role P-256 keys and DID-to-key resolution.

    Loads role-specific key files from ``tests/fixtures/keys/`` and builds
    a mapping from did:ethr addresses to (private_key, kid) pairs.
    """

    ROLE_FILES = {
        "trust-anchor": "trust-anchor.p256.json",
        "haven": "haven.p256.json",
        "company": "company.p256.json",
        "employee": "employee.p256.json",
        "ascs": "ascs.p256.json",
    }

    def __init__(self, keys_dir: Path):
        from harbour.keys import p256_public_key_to_did_ethr

        self._keys: dict[str, tuple[EllipticCurvePrivateKey, str]] = {}
        self._role_dids: dict[str, str] = {}

        for role, filename in self.ROLE_FILES.items():
            key_path = keys_dir / filename
            if not key_path.exists():
                continue
            priv = _load_jwk_private_key(key_path)
            did = p256_public_key_to_did_ethr(priv.public_key())
            kid = f"{did}#controller"
            self._keys[did] = (priv, kid)
            self._role_dids[role] = did

        if self._keys:
            print(f"  Loaded {len(self._keys)} role keys:")
            for role, did in self._role_dids.items():
                print(f"    {role}: {did}")

    @property
    def role_dids(self) -> dict[str, str]:
        return dict(self._role_dids)

    def resolve(self, did: str) -> tuple[EllipticCurvePrivateKey, str] | None:
        """Resolve a DID to its (private_key, kid) pair."""
        return self._keys.get(did)

    def get_role_key(self, role: str) -> tuple[EllipticCurvePrivateKey, str] | None:
        """Get key pair for a named role."""
        did = self._role_dids.get(role)
        if did:
            return self._keys[did]
        return None


def load_test_p256_keypair(fixtures_dir: Path | None = None):
    """Load the committed P-256 test keypair (legacy single-key mode)."""
    if fixtures_dir is None:
        repo_root = _find_repo_root()
        fixtures_dir = (
            repo_root / "submodules" / "harbour-credentials" / "tests" / "fixtures"
        )
        if not fixtures_dir.is_dir():
            fixtures_dir = repo_root / "tests" / "fixtures"
    keys_dir = fixtures_dir / "keys"
    if keys_dir.is_dir():
        jwk_path = keys_dir / "test-keypair-p256.json"
    else:
        jwk_path = fixtures_dir / "test-keypair-p256.json"
    priv = _load_jwk_private_key(jwk_path)
    return priv, priv.public_key()


def load_role_keyring(fixtures_dir: Path | None = None) -> RoleKeyring | None:
    """Load the multi-role keyring if role key files exist."""
    if fixtures_dir is None:
        repo_root = _find_repo_root()
        fixtures_dir = (
            repo_root / "submodules" / "harbour-credentials" / "tests" / "fixtures"
        )
        if not fixtures_dir.is_dir():
            fixtures_dir = repo_root / "tests" / "fixtures"
    keys_dir = fixtures_dir / "keys"
    if not keys_dir.is_dir():
        return None
    probe = keys_dir / "haven.p256.json"
    if not probe.exists():
        return None
    return RoleKeyring(keys_dir)


def sign_evidence_vp(
    vp: dict,
    private_key: PrivateKey,
    kid: str,
    keyring: RoleKeyring | None = None,
) -> str:
    """Sign an evidence VP and its inner VCs as VC-JOSE-COSE JWTs.

    When *keyring* is provided, each inner VC is signed with its own
    issuer's key (looked up by ``issuer`` DID).  The VP envelope is
    signed with *private_key* / *kid* (the holder's key).
    """
    clean_vp = {
        "@context": vp.get("@context", ["https://www.w3.org/ns/credentials/v2"]),
        "type": vp.get("type", ["VerifiablePresentation"]),
    }

    if "holder" in vp:
        clean_vp["holder"] = vp["holder"]

    inner_vcs = vp.get("verifiableCredential", [])
    inner_jwts = []
    for vc in inner_vcs:
        if isinstance(vc, dict):
            inner_issuer = vc.get("issuer", "")
            inner_key, inner_kid = private_key, kid
            if keyring:
                resolved = keyring.resolve(inner_issuer)
                if resolved:
                    inner_key, inner_kid = resolved
            inner_jwt = sign_vc_jose(vc, inner_key, kid=inner_kid)
            inner_jwts.append(inner_jwt)
        else:
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


def process_example(
    example_path: Path,
    private_key: PrivateKey,
    kid: str,
    output_dir: Path,
    keyring: RoleKeyring | None = None,
) -> Path:
    """Process a single example credential.

    Reads the expanded example, signs evidence and outer VC, writes all
    artifacts to output_dir. Never modifies the source file.

    When *keyring* is provided, the outer VC is signed with the key
    matching the credential's ``issuer`` DID, and each evidence VP is
    signed with the key matching the VP's ``holder`` DID.
    """
    vc = json.loads(example_path.read_text())
    stem = example_path.stem

    # Determine outer credential signing key
    outer_key, outer_kid = private_key, kid
    if keyring:
        issuer_did = vc.get("issuer", "")
        resolved = keyring.resolve(issuer_did)
        if resolved:
            outer_key, outer_kid = resolved

    evidence_vp_jwt = None

    # Sign evidence VPs if present (work on a copy for outer signing)
    vc_for_signing = copy.deepcopy(vc)
    if "evidence" in vc_for_signing:
        for ev in vc_for_signing["evidence"]:
            vp_obj = ev.get("verifiablePresentation")
            if isinstance(vp_obj, dict):
                # Determine evidence VP signing key (holder's key)
                ev_holder = vp_obj.get("holder", "")
                ev_key, ev_kid = private_key, kid
                if keyring:
                    resolved = keyring.resolve(ev_holder)
                    if resolved:
                        ev_key, ev_kid = resolved
                evidence_vp_jwt = sign_evidence_vp(
                    vp_obj, ev_key, ev_kid, keyring=keyring
                )
                ev["verifiablePresentation"] = evidence_vp_jwt

    # Sign the outer credential
    vc_jwt = sign_vc_jose(vc_for_signing, outer_key, kid=outer_kid)

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

    # Load key(s)
    keyring = None
    if args.key:
        from harbour._crypto import load_private_key as _load_private_key

        private_key, _ = _load_private_key(args.key)
        public_key = private_key.public_key()
    else:
        # Try multi-role keyring first, fall back to single test key
        keyring = load_role_keyring()
        private_key, public_key = load_test_p256_keypair()

    kid = p256_public_key_to_did_key(public_key)
    kid_vm = f"{kid}#{kid.split(':')[-1]}"

    # Collect example files
    example_files = []
    for path_str in args.examples:
        path = Path(path_str)
        if path.is_dir():
            # Only process credential/receipt files, skip VPs and other artifacts
            example_files.extend(
                p
                for p in sorted(path.glob("*.json"))
                if p.parent.name != "signed"
                and any(t in p.stem for t in ("credential", "receipt", "offering"))
            )
            # Also process gaiax/ subdirectory if it exists
            gaiax_dir = path / "gaiax"
            if gaiax_dir.is_dir():
                example_files.extend(
                    p
                    for p in sorted(gaiax_dir.glob("*.json"))
                    if p.parent.name != "signed"
                    and any(t in p.stem for t in ("credential", "receipt", "offering"))
                )
        elif path.is_file():
            example_files.append(path)
        else:
            print(f"Warning: {path} not found", file=sys.stderr)

    if not example_files:
        print("No example credentials found", file=sys.stderr)
        sys.exit(1)

    print(f"Signing {len(example_files)} example credentials...")
    print(f"  kid: {kid_vm}")

    output_dirs_used: set[Path] = set()
    for path in example_files:
        # Per-file output: each file's signed artifacts go to file.parent / "signed"
        if args.output_dir:
            output_dir = Path(args.output_dir)
        else:
            output_dir = path.parent / "signed"
        jwt_path = process_example(
            path, private_key, kid_vm, output_dir, keyring=keyring
        )
        output_dirs_used.add(output_dir)
        rel = path.parent.name
        prefix = f"{rel}/" if rel != "examples" else ""
        print(f"  {prefix}{path.name} -> {output_dir.name}/{jwt_path.name}")

    # List all generated files
    for out_dir in sorted(output_dirs_used):
        signed_files = sorted(out_dir.iterdir())
        print(f"\nGenerated {len(signed_files)} files in {out_dir}/")

    print("Done.")


if __name__ == "__main__":
    main()
