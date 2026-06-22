"""Tests for harbour.batch_evidence — the authorization JWT + batch evidence."""

from __future__ import annotations

import copy

import pytest

from harbour.batch_evidence import (
    EVIDENCE_TYPE,
    build_batch_evidence,
    sign_authorization,
    verify_authorization,
    verify_batch_evidence,
)
from harbour.keys import generate_p256_keypair
from harbour.merkle import compute_leaf, merkle_root_b64url
from harbour.verifier import VerificationError

AUTHORIZER = "did:ethr:0x14a34:0xa682b9044de0a1ad3429e8c6a0be0ed45d01da93"
AUDIENCE = "did:ethr:0x14a34:0x31f1ca3dc5da9f83f360d805662d11a418950202"


def _payload(n: int) -> dict:
    return {
        "type": ["VerifiableCredential", "harbour:NaturalPersonCredential"],
        "id": f"urn:uuid:0000000{n}",
        "issuer": AUDIENCE,
        "vct": "https://w3id.org/reachhaven/harbour/gx/v1/NaturalPersonCredential",
        "validFrom": "2026-01-01T00:00:00Z",
        "credentialSubject": {"id": f"did:ethr:0x14a34:0x{n:040x}"},
    }


@pytest.fixture(scope="module")
def keypair():
    return generate_p256_keypair()


def test_authorization_round_trip(keypair):
    priv, pub = keypair
    root = merkle_root_b64url([compute_leaf(_payload(1))])
    token = sign_authorization(
        root, priv, authorizer_did=AUTHORIZER, audience=AUDIENCE, iat=1_800_000_000
    )
    payload = verify_authorization(
        token, pub, expected_audience=AUDIENCE, expected_authorizer=AUTHORIZER
    )
    assert payload["nonce"] == root
    assert payload["iss"] == AUTHORIZER
    assert payload["aud"] == AUDIENCE


def test_authorization_audience_mismatch(keypair):
    priv, pub = keypair
    token = sign_authorization(
        "AAAA", priv, authorizer_did=AUTHORIZER, audience=AUDIENCE
    )
    with pytest.raises(VerificationError):
        verify_authorization(token, pub, expected_audience="did:ethr:0x14a34:0xwrong")


def test_build_and_verify_batch(keypair):
    priv, pub = keypair
    payloads = [_payload(i) for i in range(1, 5)]  # N = 4
    evidence = build_batch_evidence(
        payloads, priv, authorizer_did=AUTHORIZER, audience=AUDIENCE
    )
    assert len(evidence) == 4
    # One signature shared across the whole batch.
    assert len({e["authorization"] for e in evidence}) == 1
    for payload, ev in zip(payloads, evidence):
        assert ev["type"] == [EVIDENCE_TYPE]
        assert ev["authorizer"] == AUTHORIZER
        full = {**payload, "evidence": [ev]}  # evidence attached as it would be issued
        auth = verify_batch_evidence(full, ev, pub, expected_audience=AUDIENCE)
        assert auth["aud"] == AUDIENCE


def test_n1_degenerate_batch(keypair):
    priv, pub = keypair
    payloads = [_payload(1)]
    evidence = build_batch_evidence(
        payloads, priv, authorizer_did=AUTHORIZER, audience=AUDIENCE
    )
    assert evidence[0]["merkleProof"]["path"] == []
    verify_batch_evidence({**payloads[0], "evidence": evidence}, evidence[0], pub)


def test_tampered_payload_fails(keypair):
    priv, pub = keypair
    payloads = [_payload(i) for i in range(1, 5)]
    evidence = build_batch_evidence(
        payloads, priv, authorizer_did=AUTHORIZER, audience=AUDIENCE
    )
    tampered = copy.deepcopy(payloads[0])
    tampered["credentialSubject"]["id"] = "did:ethr:0x14a34:0xdeadbeef"
    with pytest.raises(VerificationError):
        verify_batch_evidence(tampered, evidence[0], pub)


def test_wrong_authorizer_key_fails(keypair):
    priv, _ = keypair
    _, other_pub = generate_p256_keypair()
    payloads = [_payload(1)]
    evidence = build_batch_evidence(
        payloads, priv, authorizer_did=AUTHORIZER, audience=AUDIENCE
    )
    with pytest.raises(VerificationError):
        verify_batch_evidence(payloads[0], evidence[0], other_pub)


def test_evidence_excluded_from_leaf_so_proof_holds_after_attach(keypair):
    """Attaching evidence to the payload must not change the leaf/proof."""
    priv, pub = keypair
    payloads = [_payload(i) for i in range(1, 4)]
    evidence = build_batch_evidence(
        payloads, priv, authorizer_did=AUTHORIZER, audience=AUDIENCE
    )
    # The leaf computed with vs without evidence must match (evidence stripped).
    with_ev = {**payloads[2], "evidence": [evidence[2]]}
    assert compute_leaf(with_ev) == compute_leaf(payloads[2])
    verify_batch_evidence(with_ev, evidence[2], pub, expected_audience=AUDIENCE)
