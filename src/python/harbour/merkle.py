"""Merkle batches for passkey evidence: one WebAuthn assertion, many payloads.

An approver who authorizes N credentials (or instructions) at once signs a
single WebAuthn assertion whose challenge is the Merkle root over the N
payload digests. Each credential then carries the shared assertion plus its
own ``merklePath`` (see ``docs/specs/passkey-evidence.md`` §5):

- **leaf**  the payload digest itself, ``SHA-256(JCS(payload without
  "evidence"/"proof"))`` — exactly the challenge of single-payload evidence;
- **node**  ``SHA-256(0x01 ‖ left ‖ right)``;
- a **lone (odd) node is promoted** unchanged to the next level, never
  duplicated (duplicating it would let two different batches share a root,
  CVE-2012-2459);
- the **challenge** is the root, so a batch of one has an empty path and its
  challenge is the leaf: single-payload evidence is a batch of size 1.

Leaves carry no ``0x00`` prefix (unlike RFC 6962 §2.1) so that size-1 batches
stay byte-identical to single-payload evidence. Domain separation still holds:
a leaf preimage is RFC 8785 JSON text, which always starts with ``{``
(``0x7B``), and a node preimage is exactly 65 bytes starting with ``0x01``, so
no input can be read as both. A verifier never accepts a bare leaf; it always
recomputes it from a payload.

A path lists the sibling digests from the leaf up to the root, each tagged with
the side the sibling sits on. ``position`` alone determines the fold, so no
leaf index is carried. A level at which the node was promoted contributes no
element.

CLI Usage::

    python -m harbour.merkle --help
    python -m harbour.merkle root payloads.json
    python -m harbour.merkle batch payloads.json
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import re
import sys
from pathlib import Path
from typing import Any

from harbour.digest_sri import canonical_json

__all__ = [
    "NODE_PREFIX",
    "EXCLUDED_DIGEST_KEYS",
    "MAX_PATH_LENGTH",
    "MerklePathError",
    "b64url_encode",
    "b64url_decode",
    "payload_digest_bytes",
    "hash_node",
    "merkle_root",
    "inclusion_path",
    "fold_path",
    "verify_inclusion",
    "build_batch",
]

NODE_PREFIX = b"\x01"

# Top-level members left out of a payload digest: the evidence cannot commit to
# itself, and a data-integrity proof would be computed over the digest.
EXCLUDED_DIGEST_KEYS = ("evidence", "proof")

# 2^32 payloads per assertion is far beyond any approval screen; the bound keeps
# a hostile path from costing a verifier unbounded hashing.
MAX_PATH_LENGTH = 32

_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")


class MerklePathError(ValueError):
    """A ``merklePath`` that is not a well-formed list of path elements."""


def b64url_encode(data: bytes) -> str:
    """Base64url-encode *data* without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    """Decode unpadded base64url strictly: padding or other characters fail."""
    if not isinstance(value, str) or not _B64URL.match(value) or len(value) % 4 == 1:
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def payload_digest_bytes(payload: dict[str, Any]) -> bytes:
    """``SHA-256(UTF-8(JCS(payload without evidence/proof)))``: the leaf, and
    the WebAuthn challenge of single-payload evidence."""
    signed = {k: v for k, v in payload.items() if k not in EXCLUDED_DIGEST_KEYS}
    return hashlib.sha256(canonical_json(signed).encode("utf-8")).digest()


def hash_node(left: bytes, right: bytes) -> bytes:
    """Return the internal-node hash ``SHA-256(0x01 ‖ left ‖ right)``."""
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _build_levels(leaves: list[bytes]) -> list[list[bytes]]:
    """Every tree level bottom-up; level 0 is the leaves, the last the root."""
    if not leaves:
        raise ValueError("cannot build a Merkle tree over an empty batch")
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        current = levels[-1]
        nxt = [
            hash_node(current[i], current[i + 1]) for i in range(0, len(current) - 1, 2)
        ]
        if len(current) % 2:
            nxt.append(current[-1])  # lone node promoted, never duplicated
        levels.append(nxt)
    return levels


def merkle_root(leaves: list[bytes]) -> bytes:
    """Return the Merkle root over *leaves* (raw 32 bytes)."""
    return _build_levels(leaves)[-1][0]


def inclusion_path(leaves: list[bytes], index: int) -> list[dict[str, str]]:
    """Return the ``merklePath`` of the leaf at *index*.

    Each element is ``{"hash": <b64url sibling>, "position": "left"|"right"}``,
    where ``position`` is the side the sibling occupies in ``hash_node``.
    """
    if not 0 <= index < len(leaves):
        raise IndexError(f"leaf index {index} out of range for batch of {len(leaves)}")
    path: list[dict[str, str]] = []
    idx = index
    for level in _build_levels(leaves)[:-1]:
        if idx % 2 == 0:
            if idx + 1 < len(level):
                path.append(
                    {"hash": b64url_encode(level[idx + 1]), "position": "right"}
                )
            # else: lone node promoted at this level, no element
        else:
            path.append({"hash": b64url_encode(level[idx - 1]), "position": "left"})
        idx //= 2
    return path


def fold_path(leaf: bytes, path: Any) -> bytes:
    """Fold *leaf* up *path* and return the root it commits to.

    ``None`` or an empty list is the path of a batch of one (the root is the
    leaf). Raises :class:`MerklePathError` for anything that is not a list of at
    most :data:`MAX_PATH_LENGTH` elements ``{"hash": <32 bytes b64url>,
    "position": "left"|"right"}``.
    """
    if path is None:
        return leaf
    if not isinstance(path, list):
        raise MerklePathError("merklePath must be a list")
    if len(path) > MAX_PATH_LENGTH:
        raise MerklePathError(f"merklePath longer than {MAX_PATH_LENGTH}")
    acc = leaf
    for step in path:
        if not isinstance(step, dict):
            raise MerklePathError("merklePath element must be an object")
        try:
            sibling = b64url_decode(step.get("hash"))
        except ValueError as e:
            raise MerklePathError("merklePath hash is not base64url") from e
        if len(sibling) != 32:
            raise MerklePathError("merklePath hash must be 32 bytes")
        position = step.get("position")
        if position == "left":
            acc = hash_node(sibling, acc)
        elif position == "right":
            acc = hash_node(acc, sibling)
        else:
            raise MerklePathError(f"invalid merklePath position: {position!r}")
    return acc


def verify_inclusion(leaf: bytes, path: Any, root: bytes) -> bool:
    """Fold *leaf* through *path* and compare (constant time) with *root*."""
    try:
        return hmac.compare_digest(fold_path(leaf, path), root)
    except MerklePathError:
        return False


def build_batch(payloads: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute the challenge and every ``merklePath`` for a batch of payloads.

    Returns ``{"challenge": <b64url root>, "leaves": [<b64url>, ...],
    "paths": [[{hash, position}, ...], ...]}`` with ``leaves[i]`` and
    ``paths[i]`` aligned to ``payloads[i]``. ``challenge`` is what the approver's
    passkey signs (``clientDataJSON.challenge``).
    """
    leaves = [payload_digest_bytes(p) for p in payloads]
    return {
        "challenge": b64url_encode(merkle_root(leaves)),
        "leaves": [b64url_encode(leaf) for leaf in leaves],
        "paths": [inclusion_path(leaves, i) for i in range(len(leaves))],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _load_payloads(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data
    raise ValueError("input must be a payload object or a list of them")


def main() -> None:
    """CLI entry point for Merkle batch operations."""
    parser = argparse.ArgumentParser(
        prog="harbour.merkle",
        description=(
            "Compute the shared WebAuthn challenge and the per-payload merklePath "
            "for batched passkey evidence (docs/specs/passkey-evidence.md §5)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Input is a JSON payload object or a list of them: unsigned SD-JWT issuer
payloads (with their _sd digests) or instruction objects.

Examples:
  python -m harbour.merkle root payloads.json    # the challenge to sign
  python -m harbour.merkle batch payloads.json   # challenge, leaves and paths
        """,
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")
    root_p = sub.add_parser("root", help="Print the base64url challenge (Merkle root)")
    root_p.add_argument("file", help="JSON payload or list of payloads")
    batch_p = sub.add_parser("batch", help="Print challenge, leaves and all paths")
    batch_p.add_argument("file", help="JSON payload or list of payloads")

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        sys.exit(0)

    payloads = _load_payloads(Path(args.file))
    if args.command == "root":
        print(build_batch(payloads)["challenge"])
    elif args.command == "batch":
        print(json.dumps(build_batch(payloads), indent=2))


if __name__ == "__main__":
    main()
