"""Tests for the batched-credential-evidence Merkle construction.

Covers the spec (docs/specs/batched-credential-evidence.md §4, §9) and pins the
implementation to the committed test vectors so they cannot silently drift.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from harbour.merkle import (
    b64url_decode,
    b64url_encode,
    build_batch,
    compute_leaf,
    hash_node,
    inclusion_proof,
    merkle_root,
    merkle_root_b64url,
    verify_inclusion,
)

VECTORS_PATH = (
    Path(__file__).resolve().parents[2] / "fixtures" / "batched-evidence-vectors.json"
)


@pytest.fixture(scope="module")
def vectors() -> dict:
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def test_vectors_match_recomputation(vectors):
    """Committed vectors must equal a fresh recomputation from the credentials."""
    n4 = vectors["batch_n4"]
    fresh = build_batch(n4["credentials"])
    assert fresh["root"] == n4["root"]
    assert fresh["leaves"] == n4["leaves"]
    assert fresh["proofs"] == n4["proofs"]


def test_all_proofs_fold_to_root(vectors):
    n4 = vectors["batch_n4"]
    root = b64url_decode(n4["root"])
    for cred, proof in zip(n4["credentials"], n4["proofs"]):
        assert verify_inclusion(compute_leaf(cred), proof, root)


def test_leaf_domain_separation():
    """A leaf is prefixed 0x00 and an internal node 0x01 — they never collide."""
    cred = {"type": ["VerifiableCredential"], "issuer": "did:ethr:0x14a34:0xabc"}
    leaf = compute_leaf(cred)
    # An internal node over two copies of the leaf must differ from any leaf.
    node = hash_node(leaf, leaf)
    assert leaf != node


def test_leaf_excludes_evidence_and_proof():
    base = {"type": ["VerifiableCredential"], "issuer": "did:ethr:0x14a34:0xabc"}
    with_extra = {
        **base,
        "evidence": [{"type": ["harbour:CredentialEvidenceBatch"]}],
        "proof": {"type": "DataIntegrityProof"},
    }
    assert compute_leaf(base) == compute_leaf(with_extra)


def test_evidence_invariance_vector(vectors):
    inv = vectors["evidence_invariance"]
    assert inv["equal"] is True
    assert inv["leaf_with_evidence"] == inv["leaf_without_evidence"]


def test_n1_degenerate_batch(vectors):
    n1 = vectors["batch_n1_degenerate"]
    fresh = build_batch([n1["credential"]])
    assert fresh["proofs"][0] == []  # empty path
    assert fresh["root"] == n1["root"]
    # Root of a single-leaf batch is the leaf itself.
    assert fresh["root"] == fresh["leaves"][0]


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 16, 17])
def test_round_trip_arbitrary_sizes(n):
    creds = [{"id": f"urn:{i}", "issuer": "did:ethr:0x14a34:0xabc"} for i in range(n)]
    leaves = [compute_leaf(c) for c in creds]
    root = merkle_root(leaves)
    assert merkle_root_b64url(leaves) == b64url_encode(root)
    for i in range(n):
        assert verify_inclusion(leaves[i], inclusion_proof(leaves, i), root)


def test_negative_tampered_leaf(vectors):
    n4 = vectors["batch_n4"]
    root = b64url_decode(n4["root"])
    leaf = compute_leaf(n4["credentials"][0])
    tampered = bytearray(leaf)
    tampered[0] ^= 0x01
    assert not verify_inclusion(bytes(tampered), n4["proofs"][0], root)
    assert vectors["negatives"]["tampered_leaf_verifies"] is False


def test_negative_swapped_position(vectors):
    n4 = vectors["batch_n4"]
    root = b64url_decode(n4["root"])
    leaf = compute_leaf(n4["credentials"][0])
    swapped = deepcopy(n4["proofs"][0])
    swapped[0]["position"] = "left" if swapped[0]["position"] == "right" else "right"
    assert not verify_inclusion(leaf, swapped, root)
    assert vectors["negatives"]["swapped_position_verifies"] is False


def test_negative_wrong_root(vectors):
    n4 = vectors["batch_n4"]
    root = bytearray(b64url_decode(n4["root"]))
    root[0] ^= 0x01
    leaf = compute_leaf(n4["credentials"][0])
    assert not verify_inclusion(leaf, n4["proofs"][0], bytes(root))


def test_wrong_credential_not_in_batch(vectors):
    """A credential that was never in the batch must not produce a valid proof."""
    n4 = vectors["batch_n4"]
    root = b64url_decode(n4["root"])
    intruder = {"id": "urn:uuid:deadbeef", "issuer": "did:ethr:0x14a34:0xevil"}
    # Reusing leaf 0's proof with a different leaf must fail.
    assert not verify_inclusion(compute_leaf(intruder), n4["proofs"][0], root)


def test_index_out_of_range():
    leaves = [compute_leaf({"id": f"urn:{i}"}) for i in range(3)]
    with pytest.raises(IndexError):
        inclusion_proof(leaves, 3)


def test_empty_batch_rejected():
    with pytest.raises(ValueError):
        merkle_root([])
