"""Issue signed dc+sd-jwt artifacts from example credentials.

Reads expanded (human-readable) examples from ``examples/*.json`` and issues
**dc+sd-jwt** SD-JWT-VC credentials plus decoded companion files in each input
directory's ``signed/`` folder. When given a directory, also processes the
``gaiax/`` subdirectory.

Issuance model (see ``docs/specs/batched-credential-evidence.md`` and ADR-006):

  * Each role in the trust chain uses a **separate P-256 key** (Trust Anchor,
    Signing Service / Haven, Company, Employee), loaded from
    ``tests/fixtures/keys/``.
  * Issuers are sovereign: a credential's ``issuer`` is the vouching party's
    own did:ethr. Every **proof** is executed by the Signing Service key,
    with the proof ``kid`` **resolved at signing time** from the issuer's DID
    document (``examples/did-ethr/``): the assertion method whose
    ``publicKeyJwk`` matches the Signing Service key. did:ethr fragment ids
    are generated per update event and change on rotation, so they are never
    hardcoded (ADR-006; in the current example documents this resolves to
    ``#controller`` on the Signing Service's own artifacts and the
    ``#delegate-1`` mandate for sovereign issuers).
  * Credentials carrying ``harbour:BatchCredentialEvidence`` are grouped into a
    **batch per (output dir, authorizer)**. The authorizer's admin wallet key
    signs **one** KB-JWT over an authorization message committing to the
    batch Merkle root (simulating the OID4VP ceremony, spec §4.3); each
    credential gets its own inclusion proof. The leaf is the issuer SD-JWT
    payload (``evidence`` removed) — so salts are fixed first
    (``build_sd_jwt_payload``), the message is signed, the full evidence is
    injected, and the issuer JWT is signed last (``sign_sd_jwt``), all in one
    pass.
  * Credentials without batch evidence (delegated-signing receipts, out of
    scope here) are issued as plain dc+sd-jwt with their claims passed
    through.

Output per credential:
  - ``<name>.sd-jwt``       — the dc+sd-jwt wire credential
  - ``<name>.decoded.json`` — issuer JWT header + payload (raw, with _sd and the
                              full evidence) + decoded disclosure arrays

Source ``examples/*.json`` are NEVER modified.

CLI Usage::
    python -m credentials.example_signer --help
    python -m credentials.example_signer examples/
"""

import argparse
import base64
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    EllipticCurvePrivateKey,
    EllipticCurvePrivateNumbers,
    EllipticCurvePublicNumbers,
)

from harbour.batch_evidence import EVIDENCE_TYPE, build_batch_evidence
from harbour.keys import PrivateKey, p256_public_key_to_did_key
from harbour.sd_jwt import build_sd_jwt_payload, sign_sd_jwt

# CURIE prefix -> vct base URI (mirrors the LinkML `vct:` class annotations).
_VCT_PREFIX = {
    "harbour": "https://w3id.org/reachhaven/harbour/core/v1/",
    "harbour.gx": "https://w3id.org/reachhaven/harbour/gx/v1/",
    "harbour.delegate": "https://w3id.org/reachhaven/harbour/delegate/v1/",
}
_DEFAULT_VCT = "https://w3id.org/reachhaven/harbour/core/v1/VerifiableCredential"


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


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# Placeholder KB-JWT `sd_hash` for the simulated wallet ceremony (spec §4.3):
# every real KB-JWT carries an sd_hash (RFC 9901 §4.3), but the story pipeline
# has no actual OID4VP presentation to hash, so it uses this fixed value —
# SHA-256 of "harbour-credentials example ceremony: no real OID4VP
# presentation". Downstream verifiers ignore the value by spec.
EXAMPLE_SD_HASH = "s0c-KDj7V3cRdVS9sTSAoiOLY-kvvmMdIk1wO0yt974"


def _load_jwk_private_key(jwk_path: Path) -> EllipticCurvePrivateKey:
    """Load a P-256 private key from a JWK file."""
    jwk = json.loads(jwk_path.read_text(encoding="utf-8"))
    x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
    d = int.from_bytes(_b64url_decode(jwk["d"]), "big")
    pub_numbers = EllipticCurvePublicNumbers(x, y, SECP256R1())
    priv_numbers = EllipticCurvePrivateNumbers(d, pub_numbers)
    return priv_numbers.private_key()


class RoleKeyring:
    """Manages per-role P-256 keys and DID-to-key resolution.

    Loads role-specific key files from ``tests/fixtures/keys/`` and builds a
    mapping from did:ethr identifiers to ``(private_key, kid)`` pairs.
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
        """Resolve a DID to its ``(private_key, kid)`` pair."""
        return self._keys.get(did)


def load_test_p256_keypair(fixtures_dir: Path | None = None):
    """Load the committed P-256 test keypair (fallback single-key mode)."""
    if fixtures_dir is None:
        repo_root = _find_repo_root()
        fixtures_dir = (
            repo_root / "submodules" / "harbour-credentials" / "tests" / "fixtures"
        )
        if not fixtures_dir.is_dir():
            fixtures_dir = repo_root / "tests" / "fixtures"
    keys_dir = fixtures_dir / "keys"
    jwk_path = (
        keys_dir if keys_dir.is_dir() else fixtures_dir
    ) / "test-keypair-p256.json"
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
    if not keys_dir.is_dir() or not (keys_dir / "haven.p256.json").exists():
        return None
    return RoleKeyring(keys_dir)


# ---------------------------------------------------------------------------
# Issuance helpers
# ---------------------------------------------------------------------------


def vct_for_credential(vc: dict) -> str:
    """Derive the SD-JWT ``vct`` from the credential's most-specific harbour type."""
    for t in vc.get("type", []):
        if isinstance(t, str) and ":" in t:
            prefix, local = t.split(":", 1)
            base = _VCT_PREFIX.get(prefix)
            if base:
                return base + local
    return _DEFAULT_VCT


def disclosable_paths(vc: dict) -> list[list[str]]:
    """Selectively-disclosable paths: every credentialSubject claim but id/type.

    Segment lists, not dot-strings — claim keys contain dots (``harbour.gx:*``).
    """
    cs = vc.get("credentialSubject")
    if not isinstance(cs, dict):
        return []
    return [["credentialSubject", k] for k in cs if k not in ("id", "type")]


def batch_evidence_entry(vc: dict) -> dict | None:
    """Return the ``harbour:BatchCredentialEvidence`` object, if any."""
    evidence = vc.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        return None
    ev = evidence[0]
    if not isinstance(ev, dict):
        return None
    types = ev.get("type") or []
    if isinstance(types, str):
        types = [types]
    if any(t == EVIDENCE_TYPE for t in types if isinstance(t, str)):
        return ev
    return None


def batch_authorizer(vc: dict) -> str | None:
    """Return the authorizer DID iff this credential carries batch evidence."""
    ev = batch_evidence_entry(vc)
    if ev is None:
        return None
    authorizer = ev.get("authorizedBy")
    return authorizer if isinstance(authorizer, str) else None


def _decode_sd_jwt(sd_jwt: str) -> dict:
    """Decode a dc+sd-jwt into header, raw payload, and decoded disclosure arrays."""
    parts = sd_jwt.split("~")
    issuer_jwt = parts[0]
    header_b64, payload_b64, _ = issuer_jwt.split(".")
    disclosures = [json.loads(_b64url_decode(p)) for p in parts[1:] if p]
    return {
        "header": json.loads(_b64url_decode(header_b64)),
        "payload": json.loads(_b64url_decode(payload_b64)),
        "disclosures": disclosures,
    }


def _write_outputs(output_dir: Path, stem: str, sd_jwt: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    sd_jwt_path = output_dir / f"{stem}.sd-jwt"
    sd_jwt_path.write_text(sd_jwt + "\n", encoding="utf-8")
    decoded = {
        "_description": f"Decoded dc+sd-jwt for {stem}",
        **_decode_sd_jwt(sd_jwt),
    }
    (output_dir / f"{stem}.decoded.json").write_text(
        json.dumps(decoded, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return sd_jwt_path


def _resolve_key(
    did: str,
    keyring: RoleKeyring | None,
    fallback: tuple[PrivateKey, str],
) -> tuple[PrivateKey, str]:
    if keyring:
        resolved = keyring.resolve(did)
        if resolved:
            return resolved
    return fallback


def _intake_client_id(
    keyring: RoleKeyring | None,
    fallback: tuple[PrivateKey, str],
) -> str:
    """The OID4VP intake verifier's client id (spec §4.3).

    In production this is the gatehouse ``did:key``; the Signing Service
    role's ``did:key`` stands in for it in the examples.
    """
    if keyring:
        ss_did = keyring.role_dids.get("haven")
        resolved = keyring.resolve(ss_did) if ss_did else None
        if resolved:
            priv, _ = resolved
            return p256_public_key_to_did_key(priv.public_key())
    return fallback[1]


def _load_assertion_methods(
    repo_root: Path | None = None,
) -> dict[str, list[tuple[str, tuple[str, str]]]]:
    """Map each example DID to its P-256 assertion methods.

    Reads ``examples/did-ethr/*.did.json`` (standing in for live did:ethr
    resolution) and returns ``did -> [(vm_id, (jwk_x, jwk_y)), ...]`` for
    every verification method listed in the document's ``assertionMethod``.
    """
    if repo_root is None:
        repo_root = _find_repo_root()
    out: dict[str, list[tuple[str, tuple[str, str]]]] = {}
    for path in sorted((repo_root / "examples" / "did-ethr").glob("*.did.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        did = doc.get("id")
        if not isinstance(did, str):
            continue
        assertion = set(doc.get("assertionMethod") or [])
        methods: list[tuple[str, tuple[str, str]]] = []
        for vm in doc.get("verificationMethod", []):
            vm_id = vm.get("id")
            jwk = vm.get("publicKeyJwk")
            if (
                vm_id in assertion
                and isinstance(jwk, dict)
                and jwk.get("crv") == "P-256"
                and isinstance(jwk.get("x"), str)
                and isinstance(jwk.get("y"), str)
            ):
                methods.append((vm_id, (jwk["x"], jwk["y"])))
        out[did] = methods
    return out


def _public_jwk_xy(public_key) -> tuple[str, str]:
    """The (x, y) base64url coordinates of a P-256 public key."""
    numbers = public_key.public_numbers()
    return (
        _b64url_encode(numbers.x.to_bytes(32, "big")),
        _b64url_encode(numbers.y.to_bytes(32, "big")),
    )


def _proof_key(
    issuer_did: str,
    keyring: RoleKeyring | None,
    fallback: tuple[PrivateKey, str],
    assertion_methods: dict[str, list[tuple[str, tuple[str, str]]]] | None = None,
) -> tuple[PrivateKey, str]:
    """Signing Service key + ``kid`` for a credential proof (ADR-006).

    The Signing Service executes every proof; the ``kid`` is **resolved at
    signing time** from the issuer's DID document — the assertion method
    whose ``publicKeyJwk`` matches the Signing Service key. did:ethr
    fragments are per-update-event and can never be hardcoded.

    Raises:
        ValueError: in keyring mode, when the issuer's DID document publishes
            no assertion method for the Signing Service key (missing mandate —
            the resulting proof could never verify).
    """
    if keyring:
        ss_did = keyring.role_dids.get("haven")
        resolved = keyring.resolve(ss_did) if ss_did else None
        if resolved:
            ss_key, _ = resolved
            ss_xy = _public_jwk_xy(ss_key.public_key())
            if assertion_methods is None:
                assertion_methods = _load_assertion_methods()
            for vm_id, vm_xy in assertion_methods.get(issuer_did, []):
                if vm_xy == ss_xy:
                    return ss_key, vm_id
            raise ValueError(
                f"issuer {issuer_did} publishes no assertion method for the "
                "Signing Service key in its DID document (ADR-006 mandate "
                "missing) — cannot sign"
            )
    return fallback


def process_plain(
    vc: dict,
    output_dir: Path,
    stem: str,
    keyring: RoleKeyring | None,
    fallback: tuple[PrivateKey, str],
    assertion_methods: dict[str, list[tuple[str, tuple[str, str]]]] | None = None,
) -> Path:
    """Issue a credential with no batch evidence as a plain dc+sd-jwt."""
    proof_key, proof_kid = _proof_key(
        vc.get("issuer", ""), keyring, fallback, assertion_methods
    )
    payload, disclosures = build_sd_jwt_payload(
        vc, vct=vct_for_credential(vc), disclosable=disclosable_paths(vc)
    )
    sd_jwt = sign_sd_jwt(payload, disclosures, proof_key, kid=proof_kid)
    return _write_outputs(output_dir, stem, sd_jwt)


def process_batch(
    batch: list[tuple[Path, dict, Path]],
    authorizer: str,
    keyring: RoleKeyring | None,
    fallback: tuple[PrivateKey, str],
    assertion_methods: dict[str, list[tuple[str, tuple[str, str]]]] | None = None,
) -> list[Path]:
    """Issue a batch of credentials sharing one authorizer with one signature."""
    # The admin wallet key stands in via the org's controller key (ADR-006 §3).
    wallet_key, _ = _resolve_key(authorizer, keyring, fallback)
    # All credentials in a batch share an issuer: for the identity credentials
    # authorizedBy MUST equal issuer (spec §6, step 6), and batches are grouped
    # by authorizer. Proofs are executed by the Signing Service via the
    # issuer's mandate key. The authorization KB-JWT is addressed (`aud`) to
    # the OID4VP intake verifier — the gatehouse acting for the Signing
    # Service, identified by its did:key (spec §4.3, §9.6).
    issuer_did = batch[0][1].get("issuer", "")
    proof_key, proof_kid = _proof_key(issuer_did, keyring, fallback, assertion_methods)
    audience = _intake_client_id(keyring, fallback)

    # 1. Fix salts: build each issuer payload (evidence stub present, ignored by
    #    the leaf which strips `evidence`).
    payloads: list[dict] = []
    disclosures: list[list[str]] = []
    for _, vc, _ in batch:
        payload, disc = build_sd_jwt_payload(
            vc, vct=vct_for_credential(vc), disclosable=disclosable_paths(vc)
        )
        payloads.append(payload)
        disclosures.append(disc)

    # 2. One wallet signature over the authorization message committing to the
    #    batch Merkle root; per-credential inclusion proof.
    evidence_objs = build_batch_evidence(
        payloads,
        wallet_key,
        authorized_by=authorizer,
        audience=audience,
        sd_hash=EXAMPLE_SD_HASH,
        domain="harbour.local",
    )

    # 3. Inject the full evidence and sign each issuer JWT.
    written: list[Path] = []
    for i, (path, _, output_dir) in enumerate(batch):
        payloads[i]["evidence"] = [evidence_objs[i]]
        sd_jwt = sign_sd_jwt(payloads[i], disclosures[i], proof_key, kid=proof_kid)
        written.append(_write_outputs(output_dir, path.stem, sd_jwt))
    return written


def collect_example_files(paths: list[str]) -> list[Path]:
    """Collect example credential files (credential/receipt/offering, not signed/)."""
    selected: list[Path] = []
    for path_str in paths:
        path = Path(path_str)
        dirs = []
        if path.is_dir():
            dirs.append(path)
            if (path / "gaiax").is_dir():
                dirs.append(path / "gaiax")
        elif path.is_file():
            selected.append(path)
            continue
        else:
            print(f"Warning: {path} not found", file=sys.stderr)
            continue
        for d in dirs:
            selected.extend(
                p
                for p in sorted(d.glob("*.json"))
                if p.parent.name != "signed"
                and any(t in p.stem for t in ("credential", "receipt", "offering"))
            )
    return selected


def main():
    """CLI entry point for example issuance."""
    parser = argparse.ArgumentParser(
        prog="credentials.example_signer",
        description="Issue dc+sd-jwt example credentials with batched evidence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m credentials.example_signer examples/
  python -m credentials.example_signer examples/ --output-dir examples/signed/
        """,
    )
    parser.add_argument("examples", nargs="+", help="Example files or directories")
    parser.add_argument(
        "--output-dir", "-o", help="Output dir (default: <input>/signed/)"
    )
    args = parser.parse_args()

    keyring = load_role_keyring()
    fb_priv, fb_pub = load_test_p256_keypair()
    fallback = (fb_priv, p256_public_key_to_did_key(fb_pub))

    example_files = collect_example_files(args.examples)
    if not example_files:
        print("No example credentials found", file=sys.stderr)
        sys.exit(1)

    # Clear stale artifacts (signed/ is gitignored, regenerated each run).
    signed_dirs = {
        Path(args.output_dir) if args.output_dir else p.parent / "signed"
        for p in example_files
    }
    for d in signed_dirs:
        if d.is_dir():
            for f in d.iterdir():
                if f.is_file():
                    f.unlink()

    print(f"Issuing {len(example_files)} example credentials (dc+sd-jwt)...")

    # Partition into batches (by output dir + authorizer) and plain credentials.
    batches: dict[tuple[str, str], list[tuple[Path, dict, Path]]] = {}
    plain: list[tuple[Path, dict, Path]] = []
    assertion_methods = _load_assertion_methods()
    for path in example_files:
        vc = json.loads(path.read_text(encoding="utf-8"))
        output_dir = (
            Path(args.output_dir) if args.output_dir else path.parent / "signed"
        )
        authorizer = batch_authorizer(vc)
        if authorizer:
            batches.setdefault((str(output_dir), authorizer), []).append(
                (path, vc, output_dir)
            )
        else:
            plain.append((path, vc, output_dir))

    output_dirs: set[Path] = set()
    for (_, authorizer), batch in batches.items():
        members = ", ".join(p.name for p, _, _ in batch)
        print(f"  batch (authorizer {authorizer[-8:]}, N={len(batch)}): {members}")
        for jwt_path in process_batch(
            batch, authorizer, keyring, fallback, assertion_methods
        ):
            output_dirs.add(jwt_path.parent)
    for path, vc, output_dir in plain:
        process_plain(vc, output_dir, path.stem, keyring, fallback, assertion_methods)
        output_dirs.add(output_dir)
        print(f"  plain: {path.name}")

    for out_dir in sorted(output_dirs):
        print(f"\nGenerated {len(list(out_dir.iterdir()))} files in {out_dir}/")
    print("Done.")


if __name__ == "__main__":
    main()
