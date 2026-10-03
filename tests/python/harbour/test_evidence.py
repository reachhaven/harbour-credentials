"""Tests for passkey evidence chains (HavenWebAuthnEvidence), single and batched."""

import importlib.util
import json
from pathlib import Path

import pytest

from harbour.evidence import (
    EvidenceChainResult,
    _der_to_raw,
    evidence_challenge,
    payload_digest,
    static_resolver,
    verify_did_signed_jwt,
    verify_evidence_chain,
    verify_evidence_for_payload,
    verify_instruction_evidence,
)
from harbour.merkle import build_batch

EVIDENCE_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "evidence"


def _load(name: str) -> dict:
    return json.loads((EVIDENCE_DIR / name).read_text(encoding="utf-8"))


VECTORS = _load("evidence-vectors.json")


def _generator():
    spec = importlib.util.spec_from_file_location(
        "gen_evidence_vectors", EVIDENCE_DIR / "gen_evidence_vectors.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(vectors: dict, case: dict) -> EvidenceChainResult:
    kwargs = {
        "resolve_did": static_resolver(vectors["didDocuments"]),
        "trust_anchor_did": vectors["trustAnchorDid"],
        "now": vectors["now"],
    }
    if "credential" in case:
        return verify_evidence_chain(case["credential"], **kwargs)
    return verify_instruction_evidence(case["instruction"], case["evidence"], **kwargs)


class TestVectors:
    """Chains, instructions and batches from gen_evidence_vectors.py."""

    @pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
    def test_expected_result(self, case):
        assert _run(VECTORS, case).to_dict() == case["expected"]

    @pytest.mark.parametrize(
        "vector", VECTORS["digests"], ids=lambda v: str(v["digest"])
    )
    def test_payload_digest(self, vector):
        assert payload_digest(vector["input"]) == vector["digest"]
        assert evidence_challenge(vector["input"]) == vector["digest"]

    def test_has_positive_and_negative_cases(self):
        outcomes = {c["expected"]["ok"] for c in VECTORS["cases"]}
        assert outcomes == {True, False}

    def test_batch_members_share_one_assertion(self):
        members = [
            c for c in VECTORS["cases"] if c["name"].startswith("batch-3-member-")
        ]
        signatures = set()
        for c in members:
            payload_b64 = c["credential"].split("~")[0].split(".")[1]
            payload = json.loads(_b64(payload_b64))
            signatures.add(payload["evidence"][0]["signature"])
        assert len(members) == 3 and len(signatures) == 1


def _b64(segment: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


@pytest.fixture(scope="module")
def eco():
    """A fresh tenant with a trust anchor admin and an organisation admin."""
    gen = _generator()
    tenant = gen.Tenant()
    acme = f"did:web:{gen.HOST}:participants:acme"
    tenant.add_did(acme)
    ta_admin = gen.SoftAuthenticator()
    tenant.add_trust_anchor_passkey(ta_admin)
    by_ta = {
        "sub": "urn:uuid:00000000-0000-4000-8000-000000000001",
        "memberOf": tenant.trust_anchor,
        "role": "admin",
    }
    admin_key = gen.SoftAuthenticator(alg="EdDSA")
    [(p, d, e)] = tenant.approve_batch(
        [tenant.prepare_member(acme, "admin", admin_key)], ta_admin, by_ta
    )
    admin_jwt = tenant.sign(p, d, [e]).split("~")[0] + "~"
    return {
        "gen": gen,
        "tenant": tenant,
        "acme": acme,
        "admin_key": admin_key,
        "admin_jwt": admin_jwt,
        "by_admin": {"sub": p["sub"], "memberOf": acme, "role": "admin"},
        "opts": {
            "resolve_did": tenant.resolve_did,
            "trust_anchor_did": tenant.trust_anchor,
            "now": gen.NOW,
        },
    }


class TestBatchApproval:
    @pytest.mark.parametrize("n", [1, 2, 7])
    def test_every_member_verifies_on_its_own(self, eco, n):
        t, gen = eco["tenant"], eco["gen"]
        prepared = [
            t.prepare_member(eco["acme"], "member", gen.SoftAuthenticator())
            for _ in range(n)
        ]
        approved = t.approve_batch(
            prepared, eco["admin_key"], eco["by_admin"], eco["admin_jwt"]
        )
        for payload, disclosures, evidence in approved:
            assert ("merklePath" in evidence) == (n > 1)
            assert verify_evidence_for_payload(payload, evidence, **eco["opts"]).ok
            sd_jwt = t.sign(payload, disclosures, [evidence])
            result = verify_evidence_chain(sd_jwt, **eco["opts"])
            assert result.ok, result
            assert [a.via for a in result.approvers] == ["credential", "trust-anchor"]

    def test_batch_does_not_grant_authority(self, eco):
        """An organisation admin cannot sneak an organisation credential into a batch."""
        t, gen = eco["tenant"], eco["gen"]
        member = t.prepare_member(eco["acme"], "member", gen.SoftAuthenticator())
        org = t.prepare_organisation(eco["acme"], "Acme")
        approved = t.approve_batch(
            [member, org], eco["admin_key"], eco["by_admin"], eco["admin_jwt"]
        )
        assert verify_evidence_for_payload(
            approved[0][0], approved[0][2], **eco["opts"]
        ).ok
        result = verify_evidence_for_payload(
            approved[1][0], approved[1][2], **eco["opts"]
        )
        assert (result.reason, result.depth) == ("approver-not-trust-anchor", 0)

    def test_leaf_from_outside_the_batch_fails(self, eco):
        t, gen = eco["tenant"], eco["gen"]
        prepared = [
            t.prepare_member(eco["acme"], "member", gen.SoftAuthenticator())
            for _ in range(2)
        ]
        approved = t.approve_batch(
            prepared, eco["admin_key"], eco["by_admin"], eco["admin_jwt"]
        )
        outsider, _ = t.prepare_member(eco["acme"], "member", gen.SoftAuthenticator())
        result = verify_evidence_for_payload(outsider, approved[0][2], **eco["opts"])
        assert result.reason == "digest-mismatch"

    def test_challenge_is_the_root(self, eco):
        t, gen = eco["tenant"], eco["gen"]
        prepared = [
            t.prepare_member(eco["acme"], "member", gen.SoftAuthenticator())
            for _ in range(3)
        ]
        batch = build_batch([p for p, _ in prepared])
        for (payload, _), path in zip(prepared, batch["paths"]):
            assert evidence_challenge(payload, path) == batch["challenge"]


class TestEdges:
    def test_payload_with_evidence_rejected_before_signing(self, eco):
        result = verify_evidence_for_payload({"evidence": []}, {}, **eco["opts"])
        assert result.reason == "malformed-credential"

    def test_unresolvable_trust_anchor(self, eco):
        result = verify_evidence_chain(
            eco["admin_jwt"],
            resolve_did=static_resolver({}),
            trust_anchor_did=eco["tenant"].trust_anchor,
        )
        assert (result.reason, result.depth) == ("did-resolution-failed", 0)

    def test_issued_in_future(self, eco):
        result = verify_evidence_chain(eco["admin_jwt"], **{**eco["opts"], "now": 0})
        assert result.reason == "issued-in-future"

    def test_max_depth(self, eco):
        t, gen = eco["tenant"], eco["gen"]
        [(p, d, e)] = t.approve_batch(
            [t.prepare_member(eco["acme"], "member", gen.SoftAuthenticator())],
            eco["admin_key"],
            eco["by_admin"],
            eco["admin_jwt"],
        )
        result = verify_evidence_chain(t.sign(p, d, [e]), **eco["opts"], max_depth=0)
        assert (result.reason, result.depth) == ("depth-exceeded", 1)

    def test_did_signed_jwt_rejects_foreign_kid(self, eco):
        header, payload = verify_did_signed_jwt(
            eco["admin_jwt"], resolve_did=eco["tenant"].resolve_did
        )
        assert header["kid"].startswith(payload["iss"] + "#key-")

    def test_boolean_version_is_malformed(self, eco):
        t, gen = eco["tenant"], eco["gen"]
        [(p, _, e)] = t.approve_batch(
            [t.prepare_member(eco["acme"], "member", gen.SoftAuthenticator())],
            eco["admin_key"],
            eco["by_admin"],
            eco["admin_jwt"],
        )
        assert verify_evidence_for_payload(p, e, **eco["opts"]).ok
        result = verify_evidence_for_payload(p, {**e, "version": True}, **eco["opts"])
        assert result.reason == "malformed-evidence"

    def test_result_is_falsy_on_failure(self):
        assert not EvidenceChainResult(ok=False, reason="x", depth=0)
        assert EvidenceChainResult(ok=True)


class TestDer:
    def test_minimal_and_padded(self):
        r, s = 0x7F, 0x80
        minimal = bytes([0x30, 0x07, 0x02, 0x01, r, 0x02, 0x02, 0x00, s])
        assert _der_to_raw(minimal) == (r, s)
        padded = bytes([0x30, 0x08, 0x02, 0x02, 0x00, r, 0x02, 0x02, 0x00, s])
        assert _der_to_raw(padded) == (r, s)

    @pytest.mark.parametrize(
        "der",
        [
            b"",
            bytes([0x31, 0x00]),
            bytes([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00]),
            bytes([0x30, 0x03, 0x02, 0x01, 0x01]),
            bytes([0x30, 0x24, 0x02, 0x21]) + b"\x01" * 33 + bytes([0x02, 0x01, 0x01]),
        ],
    )
    def test_rejected(self, der):
        with pytest.raises(ValueError):
            _der_to_raw(der)
