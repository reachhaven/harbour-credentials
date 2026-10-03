"""Tests for the Merkle batches behind batched passkey evidence."""

import hashlib
import json
from pathlib import Path

import pytest

from harbour.merkle import (
    MAX_PATH_LENGTH,
    MerklePathError,
    b64url_decode,
    b64url_encode,
    build_batch,
    fold_path,
    hash_node,
    inclusion_path,
    merkle_root,
    payload_digest_bytes,
    verify_inclusion,
)

VECTORS = (
    Path(__file__).resolve().parents[2]
    / "fixtures"
    / "evidence"
    / "merkle-vectors.json"
)


def _leaves(n: int) -> list[bytes]:
    return [payload_digest_bytes({"i": i}) for i in range(n)]


class TestDigest:
    def test_digest_is_sha256_of_jcs(self):
        payload = {"b": 1, "a": "x"}
        assert (
            payload_digest_bytes(payload) == hashlib.sha256(b'{"a":"x","b":1}').digest()
        )

    def test_evidence_and_proof_are_excluded(self):
        payload = {"a": 1}
        assert payload_digest_bytes({**payload, "evidence": [1], "proof": {}}) == (
            payload_digest_bytes(payload)
        )


class TestTree:
    def test_single_leaf_is_its_own_root(self):
        [leaf] = _leaves(1)
        assert merkle_root([leaf]) == leaf
        assert inclusion_path([leaf], 0) == []

    def test_two_leaves(self):
        a, b = _leaves(2)
        assert merkle_root([a, b]) == hash_node(a, b)

    def test_odd_node_is_promoted_not_duplicated(self):
        a, b, c = _leaves(3)
        assert merkle_root([a, b, c]) == hash_node(hash_node(a, b), c)
        assert merkle_root([a, b, c]) != merkle_root([a, b, c, c])

    def test_node_prefix(self):
        a, b = _leaves(2)
        assert hash_node(a, b) == hashlib.sha256(b"\x01" + a + b).digest()

    @pytest.mark.parametrize("n", range(1, 18))
    def test_every_path_folds_to_the_root(self, n):
        leaves = _leaves(n)
        root = merkle_root(leaves)
        for i in range(n):
            assert fold_path(leaves[i], inclusion_path(leaves, i)) == root

    def test_promoted_level_adds_no_element(self):
        leaves = _leaves(3)
        assert len(inclusion_path(leaves, 2)) == 1
        assert len(inclusion_path(leaves, 0)) == 2

    def test_empty_batch_rejected(self):
        with pytest.raises(ValueError):
            merkle_root([])

    def test_index_out_of_range(self):
        with pytest.raises(IndexError):
            inclusion_path(_leaves(2), 2)


class TestFold:
    def test_absent_and_empty_path(self):
        [leaf] = _leaves(1)
        assert fold_path(leaf, None) == leaf
        assert fold_path(leaf, []) == leaf

    def test_wrong_leaf_does_not_verify(self):
        leaves = _leaves(4)
        root = merkle_root(leaves)
        assert not verify_inclusion(leaves[1], inclusion_path(leaves, 0), root)

    def test_flipped_position_does_not_verify(self):
        leaves = _leaves(4)
        path = inclusion_path(leaves, 0)
        path[0]["position"] = "left"
        assert not verify_inclusion(leaves[0], path, merkle_root(leaves))

    @pytest.mark.parametrize(
        "path",
        [
            "not a list",
            [None],
            [{"hash": "!!", "position": "left"}],
            [{"hash": b64url_encode(b"x" * 31), "position": "left"}],
            [{"hash": b64url_encode(b"x" * 32), "position": "up"}],
            [{"hash": b64url_encode(b"x" * 32) + "=", "position": "left"}],
            [{"hash": b64url_encode(b"x" * 32), "position": "left"}]
            * (MAX_PATH_LENGTH + 1),
        ],
    )
    def test_malformed_path(self, path):
        [leaf] = _leaves(1)
        with pytest.raises(MerklePathError):
            fold_path(leaf, path)
        assert not verify_inclusion(leaf, path, leaf)


class TestBatch:
    def test_batch_of_one_challenge_is_the_digest(self):
        payload = {"iss": "did:web:x", "n": 1}
        batch = build_batch([payload])
        assert batch["challenge"] == b64url_encode(payload_digest_bytes(payload))
        assert batch["paths"] == [[]]

    def test_batch_aligns_leaves_and_paths(self):
        payloads = [{"n": i} for i in range(5)]
        batch = build_batch(payloads)
        root = b64url_decode(batch["challenge"])
        for payload, leaf, path in zip(payloads, batch["leaves"], batch["paths"]):
            assert b64url_decode(leaf) == payload_digest_bytes(payload)
            assert fold_path(payload_digest_bytes(payload), path) == root


class TestVectors:
    """Known answers shared with the TypeScript suite."""

    @pytest.fixture(scope="class")
    def vectors(self):
        return json.loads(VECTORS.read_text(encoding="utf-8"))["vectors"]

    def test_vectors(self, vectors):
        for v in vectors:
            batch = build_batch(v["payloads"])
            assert batch["challenge"] == v["challenge"], v["name"]
            assert batch["paths"] == v["paths"], v["name"]
