"""Verify the signed dc+sd-jwt example artifacts produced by example_signer.

For every ``<name>.sd-jwt`` under ``examples/signed/`` and
``examples/gaiax/signed/``:

  1. Verify the issuer SD-JWT signature (``verify_sd_jwt_vc``).
  2. If the credential carries ``harbour:BatchCredentialEvidence``, verify the
     batched evidence (``verify_batch_evidence``): recompute the Merkle leaf from
     the *raw* issuer payload (with ``_sd`` digests, ``evidence`` stripped), fold
     the inclusion proof, and check it against the root signed in the
     authorization JWT — verified against the authorizer's key.

This is the verifier side of ``docs/specs/batched-credential-evidence.md`` §6
(the on-chain status checks of §7 are out of scope for the local story).

CLI Usage::
    python -m credentials.verify_signed_examples
"""

import base64
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from credentials.example_signer import (
    RoleKeyring,
    _find_repo_root,
    batch_authorizer,
    load_role_keyring,
    load_test_p256_keypair,
)
from harbour.batch_evidence import verify_batch_evidence
from harbour.sd_jwt import verify_sd_jwt_vc
from harbour.verifier import VerificationError


@dataclass
class VerificationCounts:
    credentials: int = 0
    batch_evidence: int = 0
    plain: int = 0
    errors: list[str] = field(default_factory=list)


def _build_did_to_pub(keyring: RoleKeyring | None) -> dict[str, object]:
    """Map each role DID to its public key (for issuer + authorizer resolution)."""
    mapping: dict[str, object] = {}
    if keyring:
        for did in keyring.role_dids.values():
            resolved = keyring.resolve(did)
            if resolved:
                priv, _ = resolved
                mapping[did] = priv.public_key()
    return mapping


def _raw_issuer_payload(sd_jwt: str) -> dict:
    """Decode the raw issuer JWT payload (with _sd digests, before disclosure)."""
    issuer_jwt = sd_jwt.split("~")[0]
    payload_b64 = issuer_jwt.split(".")[1]
    raw = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
    return json.loads(raw)


def _discover_signed_dirs(repo_root: Path) -> list[Path]:
    candidates = [
        repo_root / "examples" / "signed",
        repo_root / "examples" / "gaiax" / "signed",
    ]
    return [p for p in candidates if p.is_dir()]


def verify_signed_dir(
    signed_dir: Path, did_to_pub: dict[str, object], fallback_pub: object
) -> VerificationCounts:
    counts = VerificationCounts()
    for sd_jwt_path in sorted(signed_dir.glob("*.sd-jwt")):
        sd_jwt = sd_jwt_path.read_text(encoding="utf-8").strip()
        raw = _raw_issuer_payload(sd_jwt)
        issuer_did = raw.get("issuer", "")
        issuer_pub = did_to_pub.get(issuer_did, fallback_pub)

        try:
            verify_sd_jwt_vc(sd_jwt, issuer_pub)
        except VerificationError as e:
            counts.errors.append(f"{sd_jwt_path.name}: issuer signature: {e}")
            continue
        counts.credentials += 1

        authorizer = batch_authorizer(raw)
        if authorizer is None:
            counts.plain += 1
            print(f"  OK (plain): {sd_jwt_path.name}")
            continue

        authorizer_pub = did_to_pub.get(authorizer)
        if authorizer_pub is None:
            counts.errors.append(
                f"{sd_jwt_path.name}: no key for authorizer {authorizer}"
            )
            continue
        try:
            verify_batch_evidence(
                raw,
                raw["evidence"][0],
                authorizer_pub,
                expected_audience=issuer_did,
            )
        except VerificationError as e:
            counts.errors.append(f"{sd_jwt_path.name}: batch evidence: {e}")
            continue
        counts.batch_evidence += 1
        print(
            f"  OK (batch evidence, authorizer {authorizer[-8:]}): {sd_jwt_path.name}"
        )
    return counts


def main() -> None:
    repo_root = _find_repo_root()
    signed_dirs = _discover_signed_dirs(repo_root)
    if not signed_dirs:
        print(
            "No signed/ directories found — run example_signer first.",
            file=sys.stderr,
        )
        sys.exit(1)

    keyring = load_role_keyring()
    _, fb_pub = load_test_p256_keypair()
    did_to_pub = _build_did_to_pub(keyring)

    total = VerificationCounts()
    for signed_dir in signed_dirs:
        print(f"Verifying {signed_dir.relative_to(repo_root)}/ ...")
        counts = verify_signed_dir(signed_dir, did_to_pub, fb_pub)
        total.credentials += counts.credentials
        total.batch_evidence += counts.batch_evidence
        total.plain += counts.plain
        total.errors.extend(counts.errors)

    print(
        f"\nVerified {total.credentials} credentials "
        f"({total.batch_evidence} with batch evidence, {total.plain} plain)."
    )
    if total.errors:
        print(f"\n{len(total.errors)} FAILURES:", file=sys.stderr)
        for err in total.errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)
    print("All signed examples verified.")


if __name__ == "__main__":
    main()
