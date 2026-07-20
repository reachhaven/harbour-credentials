"""Generate the batched-credential-evidence test vectors.

Deterministic generator for ``tests/fixtures/batched-evidence-vectors.json`` —
the canonical reference for the Merkle commitment described in
``docs/specs/batched-credential-evidence.md`` §10. Re-run after changing the
Merkle construction:

    PYTHONPATH=src/python python tests/fixtures/gen_batched_evidence_vectors.py

``tests/python/harbour/test_merkle.py`` checks the committed file against a fresh
recomputation, so the vectors cannot silently drift from the implementation.
"""

from __future__ import annotations

import argparse
import json
from copy import deepcopy
from pathlib import Path

from harbour.merkle import (
    b64url_decode,
    b64url_encode,
    build_batch,
    compute_leaf,
    hash_node,
    merkle_root,
    verify_inclusion,
)

OUT = Path(__file__).resolve().parent / "batched-evidence-vectors.json"

# A batch of four employee credentials an organization authorizes at once
# (ADR-006 sovereign issuers: the org issues its own members' credentials,
# memberOf == issuer, one issuer-operated CRSetEntry). Each carries a
# placeholder ``evidence`` member to demonstrate that the leaf excludes it
# (leaf invariance to evidence content).
_ORG = (
    "did:ethr:0x14a34:0xa682b9044de0a1ad3429e8c6a0be0ed45d01da93"  # issuer + authorizer
)


def _credential(n: int, subject_addr: str, status_index: str) -> dict:
    return {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://w3id.org/reachhaven/harbour/core/v1/",
        ],
        "type": ["VerifiableCredential", "harbour:NaturalPersonCredential"],
        "id": f"urn:uuid:00000000-0000-4000-8000-00000000000{n}",
        "issuer": _ORG,
        "validFrom": "2026-01-01T00:00:00Z",
        "credentialSubject": {
            "id": f"did:ethr:0x14a34:{subject_addr}",
            "type": "harbour:NaturalPerson",
            "harbour:memberOf": _ORG,
        },
        "credentialStatus": [
            {
                "type": "harbour:CRSetEntry",
                "statusPurpose": "revocation",
                "statusServiceOperator": _ORG,
                "statusIndex": status_index,
            },
        ],
        # Stripped before hashing — present here to prove leaf invariance.
        "evidence": [{"type": ["harbour:CredentialEvidenceBatch"], "_placeholder": n}],
    }


BATCH = [
    _credential(1, "0x272c04206c826047add586cbf7f4ffc4386da129", "np00000000000001"),
    _credential(2, "0x1111111111111111111111111111111111111111", "np00000000000002"),
    _credential(3, "0x2222222222222222222222222222222222222222", "np00000000000003"),
    _credential(4, "0x3333333333333333333333333333333333333333", "np00000000000004"),
]


def main() -> None:
    argparse.ArgumentParser(
        prog="gen_batched_evidence_vectors",
        description=(
            "Regenerate tests/fixtures/batched-evidence-vectors.json — the "
            "canonical Merkle-commitment vectors of "
            "docs/specs/batched-credential-evidence.md §10."
        ),
    ).parse_args()

    # --- N = 4 batch ---------------------------------------------------------
    batch = build_batch(BATCH)
    # Sanity: every proof folds to the root.
    root_bytes = b64url_decode(batch["root"])
    for i, cred in enumerate(BATCH):
        assert verify_inclusion(compute_leaf(cred), batch["proofs"][i], root_bytes)

    # --- N = 1 degenerate batch (empty proof path) ---------------------------
    single = build_batch([BATCH[0]])
    assert single["proofs"][0] == []
    assert single["root"] == single["leaves"][0]  # root is the lone leaf

    # --- Evidence invariance: leaf is independent of the evidence member -----
    with_ev = deepcopy(BATCH[0])
    without_ev = {k: v for k, v in with_ev.items() if k != "evidence"}
    invariance = {
        "leaf_with_evidence": b64url_encode(compute_leaf(with_ev)),
        "leaf_without_evidence": b64url_encode(compute_leaf(without_ev)),
        "equal": compute_leaf(with_ev) == compute_leaf(without_ev),
    }
    assert invariance["equal"]

    # --- Negative vectors ----------------------------------------------------
    leaf0 = compute_leaf(BATCH[0])
    proof0 = batch["proofs"][0]

    # tampered leaf: flip one byte
    tampered = bytearray(leaf0)
    tampered[0] ^= 0x01
    tampered_ok = verify_inclusion(bytes(tampered), proof0, root_bytes)

    # swapped position on the first proof step
    swapped = deepcopy(proof0)
    swapped[0]["position"] = "left" if swapped[0]["position"] == "right" else "right"
    swapped_ok = verify_inclusion(leaf0, swapped, root_bytes)

    # wrong root
    wrong_root = bytearray(root_bytes)
    wrong_root[0] ^= 0x01
    wrong_root_ok = verify_inclusion(leaf0, proof0, bytes(wrong_root))

    negatives = {
        "tampered_leaf_verifies": tampered_ok,
        "swapped_position_verifies": swapped_ok,
        "wrong_root_verifies": wrong_root_ok,
        "_note": (
            "all three MUST be false; duplicated-node forgery is structurally "
            "impossible because lone nodes are promoted, not duplicated (§9.2)"
        ),
    }
    assert not (tampered_ok or swapped_ok or wrong_root_ok)

    vectors = {
        "_description": (
            "Batched credential evidence test vectors — see "
            "docs/specs/batched-credential-evidence.md §10. Regenerate with "
            "tests/fixtures/gen_batched_evidence_vectors.py."
        ),
        "construction": {
            "leaf": "SHA-256(0x00 || JCS(credential without evidence/proof))",
            "node": "SHA-256(0x01 || left || right)",
            "lone_node": "promoted unchanged (never duplicated)",
            "root_encoding": (
                "base64url, no padding — committed in the statement line of "
                "the authorization message, whose SHA-256 hex is the KB-JWT "
                "nonce (spec §4.3.1)"
            ),
        },
        "batch_n4": {
            "credentials": BATCH,
            "leaves": batch["leaves"],
            "root": batch["root"],
            "proofs": batch["proofs"],
            "internal_nodes": _internal_nodes(batch["leaves"]),
        },
        "batch_n1_degenerate": {
            "credential": BATCH[0],
            "root": single["root"],
            "proof": single["proofs"][0],
        },
        "evidence_invariance": invariance,
        "negatives": negatives,
    }

    OUT.write_text(
        json.dumps(vectors, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"wrote {OUT}")
    print(f"  N=4 root: {batch['root']}")
    print(f"  N=1 root: {single['root']}")


def _internal_nodes(leaves_b64: list[str]) -> dict[str, str]:
    """Return the level-1 and root nodes for a 4-leaf tree, for documentation."""
    leaves = [b64url_decode(x) for x in leaves_b64]
    n01 = hash_node(leaves[0], leaves[1])
    n23 = hash_node(leaves[2], leaves[3])
    root = hash_node(n01, n23)
    assert root == merkle_root(leaves)
    return {
        "node(0,1)": b64url_encode(n01),
        "node(2,3)": b64url_encode(n23),
        "root=node(node(0,1),node(2,3))": b64url_encode(root),
    }


if __name__ == "__main__":
    main()
