"""Verify the signed dc+sd-jwt example artifacts produced by example_signer.

For every ``<name>.sd-jwt`` under ``examples/signed/`` and
``examples/gaiax/signed/``:

  1. Verify the issuer SD-JWT proof (``verify_sd_jwt_vc``) against the
     verification method the proof ``kid`` names in the **issuer's** DID
     document (ADR-006: for sovereign issuers this is the Signing Service's
     assertion-only ``#delegate-1`` mandate key). The example DID documents
     under ``examples/did-ethr/`` stand in for live did:ethr resolution.
  2. If the credential carries ``harbour:BatchCredentialEvidence``, verify the
     batched evidence (``verify_batch_evidence``): recompute the Merkle leaf from
     the *raw* issuer payload (with ``_sd`` digests, ``evidence`` stripped), fold
     the inclusion proof, and check it against the root signed in the
     authorization JWT — verified against the authorizer's admin key.
  3. For credentials carrying ``memberOf``, check ``memberOf == issuer``
     (ADR-006: an organization issues its own members' credentials).

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

from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    EllipticCurvePublicNumbers,
)

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

_MEMBER_OF_KEYS = ("harbour.gx:memberOf", "memberOf")


@dataclass
class VerificationCounts:
    credentials: int = 0
    batch_evidence: int = 0
    plain: int = 0
    errors: list[str] = field(default_factory=list)


def _build_did_to_pub(keyring: RoleKeyring | None) -> dict[str, object]:
    """Map each role DID to its public key (for authorizer resolution)."""
    mapping: dict[str, object] = {}
    if keyring:
        for did in keyring.role_dids.values():
            resolved = keyring.resolve(did)
            if resolved:
                priv, _ = resolved
                mapping[did] = priv.public_key()
    return mapping


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _raw_issuer_payload(sd_jwt: str) -> dict:
    """Decode the raw issuer JWT payload (with _sd digests, before disclosure)."""
    issuer_jwt = sd_jwt.split("~")[0]
    payload_b64 = issuer_jwt.split(".")[1]
    return json.loads(_b64url_decode(payload_b64))


def _issuer_header(sd_jwt: str) -> dict:
    """Decode the issuer JWT protected header."""
    header_b64 = sd_jwt.split("~")[0].split(".")[0]
    return json.loads(_b64url_decode(header_b64))


def _load_did_vm_keys(repo_root: Path) -> dict[str, object]:
    """Map verification-method DID URLs to public keys from the example DID docs.

    Stands in for live ``did:ethr`` resolution: a proof ``kid`` is looked up
    here, so a credential verifies exactly when its ``kid`` names a
    verification method published in the issuer's DID document (including the
    Signing Service's ``#delegate-1`` mandate key, ADR-006).
    """
    keys: dict[str, object] = {}
    for path in sorted((repo_root / "examples" / "did-ethr").glob("*.did.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        for vm in doc.get("verificationMethod", []):
            vm_id = vm.get("id")
            jwk = vm.get("publicKeyJwk")
            if not vm_id or not isinstance(jwk, dict) or jwk.get("crv") != "P-256":
                continue
            x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
            y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
            keys[vm_id] = EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key()
    return keys


def _discover_signed_dirs(repo_root: Path) -> list[Path]:
    candidates = [
        repo_root / "examples" / "signed",
        repo_root / "examples" / "gaiax" / "signed",
    ]
    return [p for p in candidates if p.is_dir()]


def _member_of(claims: dict) -> str | None:
    subject = claims.get("credentialSubject")
    if not isinstance(subject, dict):
        return None
    for key in _MEMBER_OF_KEYS:
        value = subject.get(key)
        if isinstance(value, str):
            return value
    return None


def verify_signed_dir(
    signed_dir: Path,
    did_to_pub: dict[str, object],
    vm_keys: dict[str, object],
    fallback_pub: object,
) -> VerificationCounts:
    counts = VerificationCounts()
    for sd_jwt_path in sorted(signed_dir.glob("*.sd-jwt")):
        sd_jwt = sd_jwt_path.read_text(encoding="utf-8").strip()
        raw = _raw_issuer_payload(sd_jwt)
        issuer_did = raw.get("issuer", "")

        # Resolve the proof key from the issuer's DID document via kid
        # (ADR-006); the fallback key covers keyring-less environments.
        kid = _issuer_header(sd_jwt).get("kid")
        if kid is not None and vm_keys:
            if not kid.startswith(f"{issuer_did}#"):
                counts.errors.append(
                    f"{sd_jwt_path.name}: proof kid {kid!r} does not name a "
                    f"verification method of issuer {issuer_did}"
                )
                continue
            issuer_pub = vm_keys.get(kid, fallback_pub)
        else:
            issuer_pub = did_to_pub.get(issuer_did, fallback_pub)

        try:
            claims = verify_sd_jwt_vc(sd_jwt, issuer_pub)
        except VerificationError as e:
            counts.errors.append(f"{sd_jwt_path.name}: issuer signature: {e}")
            continue
        counts.credentials += 1

        member_of = _member_of(claims)
        if member_of is not None and member_of != issuer_did:
            counts.errors.append(
                f"{sd_jwt_path.name}: memberOf {member_of} != issuer {issuer_did}"
            )
            continue

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
    vm_keys = _load_did_vm_keys(repo_root)

    total = VerificationCounts()
    for signed_dir in signed_dirs:
        print(f"Verifying {signed_dir.relative_to(repo_root)}/ ...")
        counts = verify_signed_dir(signed_dir, did_to_pub, vm_keys, fb_pub)
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
