"""Fill and verify ``digestSRI`` integrity hashes in the Gaia-X examples.

The three plain Gaia-X input VCs are the single source of truth:

    gx:LegalPerson -> examples/gaiax/gx-legal-person.json
    gx:VatID       -> examples/gaiax/gx-registration-number.json
    gx:Issuer      -> examples/gaiax/gx-terms-and-conditions.json

Every ``harbour.gx:CompliantCredentialReference`` in the example credentials
references one of these by ``harbour.gx:credentialType``. Its ``harbour.gx:digestSRI``
is the Subresource Integrity hash of the referenced credential
(:mod:`harbour.digest_sri`).

Every ``harbour.gx:digestSRI`` is taken over the source-of-truth **input VC**
for its ``credentialType`` -- in every file, including presentations. This keeps
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
    provably the same credential.
  * ``--check`` (default) recomputes and verifies every digestSRI without
    modifying any file, failing if a value is stale or tampered. This is the
    integrity step run by ``make story``.

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


def fill_file(path: Path, inputs: dict[str, dict]) -> bool:
    """Rewrite *path* with real digestSRI values (and canonical embedded VCs).

    Returns ``True`` if the file content changed.
    """
    original = path.read_text(encoding="utf-8")
    obj = json.loads(original)

    for ref in iter_reference_nodes(obj):
        credential_type = ref[_CREDENTIAL_TYPE_KEY]
        if credential_type not in inputs:
            raise ValueError(
                f"{path.name}: reference to unknown credentialType "
                f"{credential_type!r} (no input VC source of truth)"
            )
        source_vc = inputs[credential_type]
        ref[_DIGEST_KEY] = compute_digest_sri(source_vc)
        if _EMBEDDED_KEY in ref:
            ref[_EMBEDDED_KEY] = canonical_json(source_vc)

    updated = json.dumps(obj, indent=2, ensure_ascii=False) + "\n"
    if updated != original:
        path.write_text(updated, encoding="utf-8")
        return True
    return False


def check_file(path: Path, inputs: dict[str, dict]) -> tuple[list[str], int]:
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
        if credential_type not in inputs:
            errors.append(
                f"{path.name}: reference to unknown credentialType {credential_type!r}"
            )
            continue
        source_vc = inputs[credential_type]

        # The digest must match the source-of-truth input VC.
        if not verify_digest_sri(source_vc, stored):
            errors.append(
                f"{path.name}: {credential_type} digestSRI does not match "
                f"{INPUT_FILES[credential_type]}\n"
                f"      stored:   {stored}\n"
                f"      expected: {compute_digest_sri(source_vc)}"
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
  python -m credentials.digest_sri_examples           # verify all (used by `make story`)
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
    targets = collect_target_files(gaiax_dir)

    if args.write:
        print(f"Filling digestSRI hashes in {gaiax_dir}/ ...")
        for credential_type, vc in inputs.items():
            print(f"  {credential_type}: {compute_digest_sri(vc)}")
        changed = 0
        for path in targets:
            if fill_file(path, inputs):
                changed += 1
                print(f"  updated {path.name}")
        print(f"Done. {changed} file(s) updated.")
        return

    # check (default)
    print(f"Verifying digestSRI hashes in {gaiax_dir}/ ...")
    all_errors: list[str] = []
    total_refs = 0
    for path in targets:
        errors, ref_count = check_file(path, inputs)
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
