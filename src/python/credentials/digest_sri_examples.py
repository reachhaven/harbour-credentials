"""Fill and verify ``digestSRI`` integrity hashes in the Gaia-X examples.

The four plain Gaia-X input VCs are the single source of truth:

    gx:LegalPerson   -> examples/gaiax/gx-legal-person.json
    gx:NaturalPerson -> examples/gaiax/gx-natural-person.json
    gx:VatID         -> examples/gaiax/gx-registration-number.json
    gx:Issuer        -> examples/gaiax/gx-terms-and-conditions.json

Every ``harbour.gx:CompliantCredentialReference`` in the example credentials
references one of these by ``harbour.gx:credentialType``. Its ``harbour.gx:digestSRI``
is the Subresource Integrity hash of the referenced credential
(:mod:`harbour.digest_sri`).

Every ``harbour.gx:digestSRI`` is taken over the source-of-truth **input VC**
for its ``credentialType`` -- in every file, including presentations -- except
for a **self-signed** organization (the Trust Anchor: a
``harbour.gx:LegalPersonCredential`` with ``issuer == credentialSubject.id``).
It has no input files of its own; its references resolve only against the gx
VCs bundled in the evidence VP of its own credential, whose canonical copy is
the file that has that credential at its root (``trust-anchor-credential.json``).
Every embedded copy must be identical to that file. This keeps
the value identical wherever a reference ``@id`` (e.g. ``#compliantLegalPersonVC``)
is reused across examples, so the validator's merged graph never sees one node
with two conflicting ``maxCount 1`` values. Plain gx VCs bundled inside a
presentation are left untouched (their own ``@id``) and are illustrative; they
are deliberately NOT rewritten to the input VC, which would make two nodes share
a ``gx:LegalPerson`` ``@id`` and duplicate ``gx:headquartersAddress``.

Modes:
  * ``--write`` recomputes each ``harbour.gx:digestSRI`` from the input VC and
    rewrites any inline ``harbour.gx:embeddedCredential`` to that canonical input
    VC, so the standalone referenced and embedded compliance credentials are
    provably the same credential. It resolves every reference before writing
    anything, so a reference with no source VC aborts the run with no file
    changed.
  * ``--check`` (default) recomputes and verifies every digestSRI without
    modifying any file, failing if a value is stale or tampered. This is the
    integrity step run by ``just story``.

CLI Usage:
    python -m credentials.digest_sri_examples            # check (default)
    python -m credentials.digest_sri_examples --write    # fill / repair
    python -m credentials.digest_sri_examples --help
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterator

from harbour.digest_sri import canonical_json, compute_digest_sri, verify_digest_sri

# Map credentialType -> input VC filename (the source of truth).
INPUT_FILES = {
    "gx:LegalPerson": "gx-legal-person.json",
    "gx:VatID": "gx-registration-number.json",
    "gx:Issuer": "gx-terms-and-conditions.json",
    "gx:NaturalPerson": "gx-natural-person.json",
}

_REF_TYPE = "harbour.gx:CompliantCredentialReference"
_CREDENTIAL_TYPE_KEY = "harbour.gx:credentialType"
_DIGEST_KEY = "harbour.gx:digestSRI"
_EMBEDDED_KEY = "harbour.gx:embeddedCredential"


def _find_repo_root() -> Path:
    current = Path(__file__).resolve().parent
    while current != current.parent:
        if (current / ".git").is_dir() or (current / "submodules").is_dir():
            return current
        current = current.parent
    return Path.cwd()


def load_input_vcs(gaiax_dir: Path) -> dict[str, dict]:
    """Load the three plain Gaia-X input VCs keyed by their credentialSubject type."""
    inputs: dict[str, dict] = {}
    for credential_type, filename in INPUT_FILES.items():
        path = gaiax_dir / filename
        if not path.exists():
            raise FileNotFoundError(f"Missing source-of-truth input VC: {path}")
        inputs[credential_type] = json.loads(path.read_text(encoding="utf-8"))
    return inputs


def iter_reference_nodes(node: Any) -> Iterator[dict]:
    """Yield every ``CompliantCredentialReference`` object found anywhere in *node*."""
    if isinstance(node, dict):
        if _CREDENTIAL_TYPE_KEY in node and _DIGEST_KEY in node:
            yield node
        for value in node.values():
            yield from iter_reference_nodes(value)
    elif isinstance(node, list):
        for item in node:
            yield from iter_reference_nodes(item)


def _iter_dicts(node: Any) -> Iterator[dict]:
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _iter_dicts(value)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_dicts(item)


def _has_type(node: dict, type_value: str) -> bool:
    types = node.get("type")
    if isinstance(types, str):
        types = [types]
    return isinstance(types, list) and type_value in types


def _self_signed_org(cred: dict) -> str | None:
    """The org DID if *cred* is a self-signed LegalPersonCredential, else ``None``."""
    if not _has_type(cred, "harbour.gx:LegalPersonCredential"):
        return None
    subject = cred.get("credentialSubject")
    if not isinstance(subject, dict):
        return None
    org_did = subject.get("id")
    if not org_did or cred.get("issuer") != org_did:
        return None
    return org_did


def load_self_signed_sources(gaiax_dir: Path) -> dict[str, dict[str, dict]]:
    """Map a self-signed org DID -> {credentialType: its own gx VC}.

    The Trust Anchor self-signs its LegalPersonCredential (issuer ==
    credentialSubject.id) and bundles its own gx VCs in its evidence VP. Those
    gx VCs are that org's source of truth (it has no Example-Corp input file).

    The credential occurs in several files: at the root of its own file
    (``trust-anchor-credential.json``), which is the canonical copy, and inside
    the evidence VP of every credential it authorizes. Every embedded copy must
    equal the canonical one, and the bundle may hold one VC per credentialType.
    Otherwise the digests would depend on whichever copy is read first, and an
    edit to any other copy would go unnoticed.

    Raises:
        ValueError: a self-signed credential has no ``id``, is not the root of
            exactly one file, has an embedded copy that differs from that file,
            or bundles two VCs of the same credentialType.
    """
    # credential id -> [(path, is_root, credential)]
    copies: dict[str, list[tuple[Path, bool, dict]]] = {}
    for path in collect_target_files(gaiax_dir):
        obj = json.loads(path.read_text(encoding="utf-8"))
        for cred in _iter_dicts(obj):
            org_did = _self_signed_org(cred)
            if org_did is None:
                continue
            cred_id = cred.get("id")
            if not cred_id:
                raise ValueError(
                    f"{path.name}: self-signed credential of {org_did} has no id"
                )
            copies.setdefault(cred_id, []).append((path, cred is obj, cred))

    sources: dict[str, dict[str, dict]] = {}
    for cred_id, found in copies.items():
        roots = [(path, cred) for path, is_root, cred in found if is_root]
        if len(roots) != 1:
            where = ", ".join(sorted(path.name for path, _ in roots)) or "no file"
            raise ValueError(
                f"self-signed credential {cred_id} must be the root of exactly "
                f"one file (its canonical copy); found: {where}"
            )
        canonical_path, canonical = roots[0]
        drifted = sorted(
            {
                path.name
                for path, is_root, cred in found
                if not is_root and canonical_json(cred) != canonical_json(canonical)
            }
        )
        if drifted:
            raise ValueError(
                f"self-signed credential {cred_id}: the copy embedded in "
                f"{', '.join(drifted)} differs from {canonical_path.name}"
            )

        org_did = _self_signed_org(canonical)
        bundle = sources.setdefault(org_did, {})
        for inner in _iter_dicts(canonical.get("evidence", [])):
            cs = inner.get("credentialSubject")
            if not isinstance(cs, dict):
                continue
            credential_type = cs.get("type")
            if (
                not isinstance(credential_type, str)
                or credential_type not in INPUT_FILES
            ):
                continue
            if credential_type in bundle:
                raise ValueError(
                    f"self-signed organization {org_did} bundles more than one "
                    f"{credential_type} VC ({canonical_path.name})"
                )
            bundle[credential_type] = inner
    return sources


def _resolve_referent(
    ref: dict, inputs: dict[str, dict], self_signed: dict[str, dict[str, dict]]
) -> dict:
    """The gx VC a reference's digestSRI is taken over.

    A reference whose ``@id`` names a self-signed org resolves ONLY against that
    org's own bundle. It never falls back to the Example-Corp input VC, which
    describes a different organization. Any other reference resolves to the
    input VC for its credentialType.

    Raises:
        ValueError: there is no source VC for the reference.
    """
    credential_type = ref.get(_CREDENTIAL_TYPE_KEY)
    org_did = str(ref.get("@id", "")).split("#", 1)[0]
    if org_did in self_signed:
        bundle = self_signed[org_did]
        if credential_type not in bundle:
            raise ValueError(
                f"self-signed organization {org_did} bundles no "
                f"{credential_type!r} VC in its evidence "
                f"(bundled: {', '.join(sorted(bundle)) or 'none'})"
            )
        return bundle[credential_type]
    if credential_type not in inputs:
        raise ValueError(
            f"no source-of-truth input VC for credentialType {credential_type!r} "
            f"(@id {ref.get('@id')!r})"
        )
    return inputs[credential_type]


def render_filled(
    path: Path, inputs: dict[str, dict], self_signed: dict[str, dict[str, dict]]
) -> tuple[str, str]:
    """Return ``(original, updated)`` text of *path* with real digestSRI values.

    Also rewrites each inline embedded VC to its canonical source. Nothing is
    written; ``--write`` renders every file first and only then writes, so an
    unresolvable reference leaves the tree untouched.

    Raises:
        ValueError: a reference has no source VC (see ``_resolve_referent``).
    """
    original = path.read_text(encoding="utf-8")
    obj = json.loads(original)

    for ref in iter_reference_nodes(obj):
        try:
            referent = _resolve_referent(ref, inputs, self_signed)
        except ValueError as exc:
            raise ValueError(f"{path.name}: {exc}") from None
        ref[_DIGEST_KEY] = compute_digest_sri(referent)
        if _EMBEDDED_KEY in ref:
            ref[_EMBEDDED_KEY] = canonical_json(referent)

    return original, json.dumps(obj, indent=2, ensure_ascii=False) + "\n"


def check_file(
    path: Path, inputs: dict[str, dict], self_signed: dict[str, dict[str, dict]]
) -> tuple[list[str], int]:
    """Verify every digestSRI in *path*.

    Returns ``(errors, reference_count)`` where *errors* is a list of
    human-readable mismatch descriptions.
    """
    obj = json.loads(path.read_text(encoding="utf-8"))
    errors: list[str] = []
    refs = list(iter_reference_nodes(obj))

    for ref in refs:
        credential_type = ref.get(_CREDENTIAL_TYPE_KEY)
        stored = ref.get(_DIGEST_KEY)
        try:
            referent = _resolve_referent(ref, inputs, self_signed)
        except ValueError as exc:
            errors.append(f"{path.name}: {exc}")
            continue

        if not verify_digest_sri(referent, stored):
            errors.append(
                f"{path.name}: {credential_type} digestSRI does not match its "
                f"source VC\n"
                f"      stored:   {stored}\n"
                f"      expected: {compute_digest_sri(referent)}"
            )
            continue

        # Embedded pattern: the inline credential must also match the digest.
        embedded = ref.get(_EMBEDDED_KEY)
        if embedded is not None:
            try:
                embedded_vc = json.loads(embedded)
            except (TypeError, json.JSONDecodeError) as exc:
                errors.append(
                    f"{path.name}: {credential_type} embeddedCredential is not "
                    f"valid JSON ({exc})"
                )
                continue
            if not verify_digest_sri(embedded_vc, stored):
                errors.append(
                    f"{path.name}: {credential_type} embeddedCredential content "
                    f"does not match its digestSRI ({stored})"
                )

    return errors, len(refs)


def collect_target_files(gaiax_dir: Path) -> list[Path]:
    """All gaiax example files that may carry digestSRI references (excludes inputs)."""
    input_names = set(INPUT_FILES.values())
    return [
        p
        for p in sorted(gaiax_dir.glob("*.json"))
        if p.name not in input_names and p.parent.name != "signed"
    ]


def main() -> None:
    """CLI entry point: verify (default) or fill example digestSRI hashes."""
    parser = argparse.ArgumentParser(
        prog="credentials.digest_sri_examples",
        description=(
            "Fill (--write) or verify (--check, default) the digestSRI integrity "
            "hashes in the Gaia-X examples against the source-of-truth input VCs."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m credentials.digest_sri_examples           # verify all (used by `just story`)
  python -m credentials.digest_sri_examples --write   # recompute and write hashes
        """,
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help="Verify digestSRI values without writing (default)",
    )
    mode.add_argument(
        "--write",
        action="store_true",
        help="Recompute and write digestSRI values into the examples",
    )
    parser.add_argument(
        "--gaiax-dir",
        type=Path,
        default=None,
        help="Path to the examples/gaiax directory (default: auto-detect)",
    )
    args = parser.parse_args()

    gaiax_dir = args.gaiax_dir or (_find_repo_root() / "examples" / "gaiax")
    if not gaiax_dir.is_dir():
        print(
            f"ERROR: gaiax examples directory not found: {gaiax_dir}", file=sys.stderr
        )
        sys.exit(1)

    inputs = load_input_vcs(gaiax_dir)
    try:
        self_signed = load_self_signed_sources(gaiax_dir)
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
    targets = collect_target_files(gaiax_dir)

    if args.write:
        print(f"Filling digestSRI hashes in {gaiax_dir}/ ...")
        for credential_type, vc in inputs.items():
            print(f"  {credential_type}: {compute_digest_sri(vc)}")
        for org_did, by_type in self_signed.items():
            for credential_type, vc in by_type.items():
                print(
                    f"  [self-signed {org_did[-8:]}] {credential_type}: {compute_digest_sri(vc)}"
                )
        try:
            rendered = [
                (path, *render_filled(path, inputs, self_signed)) for path in targets
            ]
        except ValueError as exc:
            print(f"FAIL: {exc}\nNo files were written.", file=sys.stderr)
            sys.exit(1)
        changed = 0
        for path, original, updated in rendered:
            if updated != original:
                path.write_text(updated, encoding="utf-8")
                changed += 1
                print(f"  updated {path.name}")
        print(f"Done. {changed} file(s) updated.")
        return

    # check (default)
    print(f"Verifying digestSRI hashes in {gaiax_dir}/ ...")
    all_errors: list[str] = []
    total_refs = 0
    for path in targets:
        errors, ref_count = check_file(path, inputs, self_signed)
        total_refs += ref_count
        if ref_count:
            status = "FAIL" if errors else "ok"
            print(f"  [{status}] {path.name} ({ref_count} reference(s))")
        all_errors.extend(errors)

    if all_errors:
        print(f"\nFAIL: {len(all_errors)} digestSRI mismatch(es):", file=sys.stderr)
        for err in all_errors:
            print(f"  - {err}", file=sys.stderr)
        print(
            "\nRun `python -m credentials.digest_sri_examples --write` to repair.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"OK: {total_refs} digestSRI reference(s) verified.")


if __name__ == "__main__":
    main()
