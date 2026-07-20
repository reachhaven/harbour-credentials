"""Merkle tree for batched credential evidence.

Implements the commitment construction specified in
``docs/specs/batched-credential-evidence.md`` §4:

- **leaf**  ``SHA-256( 0x00 ‖ JCS(credential payload without "evidence"/"proof") )``
- **node**  ``SHA-256( 0x01 ‖ left ‖ right )``
- a **lone (odd) node is promoted** unchanged to the next level — it is *never*
  duplicated (forbidding last-node duplication closes CVE-2012-2459);
- the **root** is encoded base64url without padding and carried in the
  statement line of the authorization message, whose SHA-256 hex is the
  KB-JWT ``nonce`` (spec §4.3.1).

The ``0x00`` / ``0x01`` domain-separation prefixes are taken from RFC 6962 §2.1
(they prevent an internal node from being presented as a leaf). The tree *shape*
is the simple level-by-level promotion above, which — together with the prefixes —
is second-preimage safe; it is not RFC 6962's largest-power-of-two split.

An inclusion proof is the ordered list of sibling digests from the leaf up to the
root, each tagged with the sibling's ``position`` ("left" | "right"). ``position``
alone fully determines the fold, so no leaf index is carried. A level at which the
node was promoted (no sibling) contributes no proof element.

CLI Usage::

    python -m harbour.merkle --help
    python -m harbour.merkle root credentials.json
    python -m harbour.merkle proof credentials.json --index 2
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path
from typing import Any

from harbour.digest_sri import canonical_json

__all__ = [
    "LEAF_PREFIX",
    "NODE_PREFIX",
    "EXCLUDED_LEAF_KEYS",
    "compute_leaf",
    "hash_node",
    "merkle_root",
    "merkle_root_b64url",
    "inclusion_proof",
    "verify_inclusion",
    "build_batch",
    "b64url_encode",
    "b64url_decode",
]

# RFC 6962 §2.1 domain-separation prefixes.
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

# Members removed from a credential before canonicalizing it into a leaf.
# ``evidence`` carries the inclusion proof (so it cannot commit to itself);
# ``proof`` is excluded so the leaf is independent of any embedded data-integrity
# proof. (A ``dc+sd-jwt`` credential has no ``proof`` member; excluding it is
# harmless and keeps the rule format-independent.)
EXCLUDED_LEAF_KEYS = ("evidence", "proof")


def b64url_encode(data: bytes) -> str:
    """Base64url-encode *data* without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    """Decode an unpadded base64url string."""
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def compute_leaf(credential: dict[str, Any]) -> bytes:
    """Return the leaf hash for *credential* (§4.1).

    The credential's ``evidence`` and ``proof`` members are removed, the result
    is canonicalized with RFC 8785 (JCS), and hashed with the leaf prefix:
    ``SHA-256(0x00 ‖ JCS(payload))``.
    """
    payload = {k: v for k, v in credential.items() if k not in EXCLUDED_LEAF_KEYS}
    return hashlib.sha256(
        LEAF_PREFIX + canonical_json(payload).encode("utf-8")
    ).digest()


def hash_node(left: bytes, right: bytes) -> bytes:
    """Return the internal-node hash ``SHA-256(0x01 ‖ left ‖ right)`` (§4.2)."""
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _build_levels(leaves: list[bytes]) -> list[list[bytes]]:
    """Build every tree level bottom-up; level 0 is the leaves, last is the root."""
    if not leaves:
        raise ValueError("cannot build a Merkle tree over an empty batch")
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        current = levels[-1]
        nxt: list[bytes] = []
        i = 0
        while i < len(current):
            if i + 1 < len(current):
                nxt.append(hash_node(current[i], current[i + 1]))
                i += 2
            else:
                nxt.append(current[i])  # lone node promoted, never duplicated
                i += 1
        levels.append(nxt)
    return levels


def merkle_root(leaves: list[bytes]) -> bytes:
    """Return the Merkle root over *leaves* (raw 32 bytes)."""
    return _build_levels(leaves)[-1][0]


def merkle_root_b64url(leaves: list[bytes]) -> str:
    """Return the Merkle root base64url-encoded (as committed in the
    authorization message's statement line, spec §4.3.1)."""
    return b64url_encode(merkle_root(leaves))


def inclusion_proof(leaves: list[bytes], index: int) -> list[dict[str, str]]:
    """Return the inclusion proof for the leaf at *index*.

    Each element is ``{"hash": <b64url sibling>, "position": "left"|"right"}``,
    where ``position`` is the side the sibling occupies in ``hash_node(left, right)``.
    """
    if not 0 <= index < len(leaves):
        raise IndexError(f"leaf index {index} out of range for batch of {len(leaves)}")
    levels = _build_levels(leaves)
    proof: list[dict[str, str]] = []
    idx = index
    for level in levels[:-1]:  # every level except the root
        if idx % 2 == 0:
            sibling = idx + 1
            if sibling < len(level):
                proof.append(
                    {"hash": b64url_encode(level[sibling]), "position": "right"}
                )
            # else: lone node promoted at this level — no proof element
        else:
            proof.append({"hash": b64url_encode(level[idx - 1]), "position": "left"})
        idx //= 2
    return proof


def verify_inclusion(leaf: bytes, proof: list[dict[str, str]], root: bytes) -> bool:
    """Fold *leaf* through *proof* and compare (constant-time) to *root*."""
    acc = leaf
    for step in proof:
        sibling = b64url_decode(step["hash"])
        position = step.get("position")
        if position == "left":
            acc = hash_node(sibling, acc)
        elif position == "right":
            acc = hash_node(acc, sibling)
        else:
            raise ValueError(f"invalid proof position: {position!r}")
    return hmac.compare_digest(acc, root)


def build_batch(credentials: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute the root and every per-credential inclusion proof for a batch.

    Returns ``{"root": <b64url>, "leaves": [<b64url>, ...],
    "proofs": [[{hash, position}, ...], ...]}`` with ``leaves[i]``/``proofs[i]``
    aligned to ``credentials[i]``.
    """
    leaves = [compute_leaf(c) for c in credentials]
    root = merkle_root(leaves)
    return {
        "root": b64url_encode(root),
        "leaves": [b64url_encode(leaf) for leaf in leaves],
        "proofs": [inclusion_proof(leaves, i) for i in range(len(leaves))],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _load_credentials(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data
    raise ValueError("input must be a credential object or a list of them")


def main() -> None:
    """CLI entry point for Merkle batch operations."""
    parser = argparse.ArgumentParser(
        prog="harbour.merkle",
        description=(
            "Compute Merkle roots and inclusion proofs for batched credential "
            "evidence (see docs/specs/batched-credential-evidence.md)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m harbour.merkle root credentials.json
  python -m harbour.merkle proof credentials.json --index 2
  python -m harbour.merkle batch credentials.json   # root + all proofs
        """,
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    root_p = sub.add_parser("root", help="Print the base64url Merkle root")
    root_p.add_argument("file", help="JSON credential or list of credentials")

    proof_p = sub.add_parser("proof", help="Print the inclusion proof for one leaf")
    proof_p.add_argument("file", help="JSON list of credentials")
    proof_p.add_argument("--index", type=int, required=True, help="0-based leaf index")

    batch_p = sub.add_parser("batch", help="Print root, leaves, and all proofs")
    batch_p.add_argument("file", help="JSON list of credentials")

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        sys.exit(0)

    credentials = _load_credentials(Path(args.file))

    if args.command == "root":
        print(merkle_root_b64url([compute_leaf(c) for c in credentials]))
    elif args.command == "proof":
        leaves = [compute_leaf(c) for c in credentials]
        print(json.dumps(inclusion_proof(leaves, args.index), indent=2))
    elif args.command == "batch":
        print(json.dumps(build_batch(credentials), indent=2))


if __name__ == "__main__":
    main()
