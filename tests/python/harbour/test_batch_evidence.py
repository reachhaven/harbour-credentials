"""Tests for harbour.batch_evidence — the wallet KB-JWT + batch evidence.

Covers the spec §4.3/§4.3.1/§6 artifact: a KB-JWT (typ kb+jwt, no iss/kid)
whose nonce is SHA-256(authorizationMessage), a SIWE-style message whose
single statement line commits to the batch Merkle root, and per-credential
Merkle inclusion proofs.
"""

from __future__ import annotations

import copy
import hashlib

import pytest

from harbour.batch_evidence import (
    AUTHORIZATION_JWT_TYP,
    EVIDENCE_TYPE,
    STATEMENT_TEMPLATE,
    build_batch_evidence,
    compose_authorization_message,
    extract_root_from_message,
    sign_authorization,
    verify_authorization,
    verify_batch_evidence,
)
from harbour.keys import generate_p256_keypair
from harbour.merkle import compute_leaf, merkle_root_b64url
from harbour.verifier import VerificationError

AUTHORIZED_BY = "did:ethr:0x14a34:0xa682b9044de0a1ad3429e8c6a0be0ed45d01da93"
# The OID4VP intake verifier's client id (gatehouse did:key stand-in).
AUDIENCE = "did:key:zDnaefrde2MxCJfVoE1Z6RW6Zk6S91ot2w2x1c9Xwm5WiBMo9"
# Every KB-JWT carries an sd_hash (RFC 9901 §4.3); opaque to these tests.
SD_HASH = "c29tZS1oYXNo"


def _payload(n: int) -> dict:
    return {
        "type": ["VerifiableCredential", "harbour:NaturalPersonCredential"],
        "id": f"urn:uuid:0000000{n}",
        "issuer": AUTHORIZED_BY,
        "vct": "https://w3id.org/reachhaven/harbour/gx/v1/NaturalPersonCredential",
        "validFrom": "2026-01-01T00:00:00Z",
        "credentialSubject": {"id": f"did:ethr:0x14a34:0x{n:040x}"},
    }


def _message(root: str, n: int = 1) -> str:
    return compose_authorization_message(
        root,
        n,
        domain="harbour.local",
        address=AUTHORIZED_BY,
        nonce="deadbeefdeadbeef",
        issued_at="2026-07-07T00:00:00+00:00",
    )


@pytest.fixture(scope="module")
def keypair():
    return generate_p256_keypair()


# --- message grammar (§4.3.1) -------------------------------------------------


def test_message_contains_normative_statement():
    root = merkle_root_b64url([compute_leaf(_payload(1))])
    message = _message(root, 3)
    assert STATEMENT_TEMPLATE.format(n=3, root=root) in message
    extracted_root, n = extract_root_from_message(message)
    assert extracted_root == root
    assert n == 3


def test_extract_rejects_message_without_statement():
    with pytest.raises(VerificationError):
        extract_root_from_message("hello world\nNonce: abc")


def test_extract_rejects_message_with_two_statements():
    root = merkle_root_b64url([compute_leaf(_payload(1))])
    line = STATEMENT_TEMPLATE.format(n=1, root=root)
    with pytest.raises(VerificationError):
        extract_root_from_message(f"{line}\n{line}")


# --- authorization KB-JWT (§4.3) ---------------------------------------------


def test_authorization_round_trip(keypair):
    priv, pub = keypair
    root = merkle_root_b64url([compute_leaf(_payload(1))])
    message = _message(root)
    token = sign_authorization(
        message, priv, audience=AUDIENCE, sd_hash=SD_HASH, iat=1_800_000_000
    )
    payload = verify_authorization(
        token, pub, message=message, expected_audience=AUDIENCE
    )
    assert payload["nonce"] == hashlib.sha256(message.encode()).hexdigest()
    assert payload["aud"] == AUDIENCE
    assert payload["iat"] == 1_800_000_000
    # KB-JWT identifies its signer by key, not by claim (§4.3).
    assert "iss" not in payload


def test_authorization_typ_is_kb_jwt(keypair):
    import base64
    import json

    priv, _ = keypair
    token = sign_authorization(
        _message("A" * 43), priv, audience=AUDIENCE, sd_hash=SD_HASH
    )
    header_b64 = token.split(".")[0]
    header = json.loads(
        base64.urlsafe_b64decode(header_b64 + "=" * (-len(header_b64) % 4))
    )
    assert header["typ"] == AUTHORIZATION_JWT_TYP == "kb+jwt"
    assert "kid" not in header


def test_authorization_always_carries_sd_hash(keypair):
    """Every KB-JWT carries sd_hash (RFC 9901 §4.3); opaque downstream (§6)."""
    priv, pub = keypair
    message = _message("A" * 43)
    token = sign_authorization(message, priv, audience=AUDIENCE, sd_hash=SD_HASH)
    payload = verify_authorization(token, pub, message=message)
    assert payload["sd_hash"] == SD_HASH


def test_authorization_rejects_non_integer_iat(keypair):
    """Fractional and boolean iat are rejected identically in both runtimes."""
    import base64
    import json

    from joserfc import jws as _jws

    from harbour._crypto import import_private_key as _imp

    priv, pub = keypair
    message = _message("A" * 43)
    for bad_iat in (1_800_000_000.5, True):
        payload = {
            "iat": bad_iat,
            "aud": AUDIENCE,
            "nonce": hashlib.sha256(message.encode()).hexdigest(),
            "sd_hash": SD_HASH,
        }
        token = _jws.serialize_compact(
            {"alg": "ES256", "typ": "kb+jwt"},
            json.dumps(payload).encode(),
            _imp(priv, "ES256"),
            algorithms=["ES256"],
        )
        # sanity: the crafted token really carries the bad iat
        p_b64 = token.split(".")[1]
        crafted = json.loads(base64.urlsafe_b64decode(p_b64 + "=" * (-len(p_b64) % 4)))
        assert crafted["iat"] == bad_iat
        with pytest.raises(VerificationError, match="integer iat"):
            verify_authorization(token, pub, message=message)


def test_authorization_audience_mismatch(keypair):
    priv, pub = keypair
    message = _message("A" * 43)
    token = sign_authorization(message, priv, audience=AUDIENCE, sd_hash=SD_HASH)
    with pytest.raises(VerificationError):
        verify_authorization(
            token, pub, message=message, expected_audience="did:key:zWrong"
        )


def test_authorization_message_mismatch(keypair):
    """A tampered message no longer hashes to the signed nonce."""
    priv, pub = keypair
    message = _message("A" * 43)
    token = sign_authorization(message, priv, audience=AUDIENCE, sd_hash=SD_HASH)
    with pytest.raises(VerificationError):
        verify_authorization(token, pub, message=message + " ")


# --- batch evidence (§5, §6) ---------------------------------------------------


def test_build_and_verify_batch(keypair):
    priv, pub = keypair
    payloads = [_payload(i) for i in range(1, 5)]  # N = 4
    evidence = build_batch_evidence(
        payloads, priv, authorized_by=AUTHORIZED_BY, audience=AUDIENCE, sd_hash=SD_HASH
    )
    assert len(evidence) == 4
    # One signature and one message shared across the whole batch.
    assert len({e["authorization"] for e in evidence}) == 1
    assert len({e["authorizationMessage"] for e in evidence}) == 1
    root, n = extract_root_from_message(evidence[0]["authorizationMessage"])
    assert n == 4
    for payload, ev in zip(payloads, evidence):
        assert ev["type"] == [EVIDENCE_TYPE]
        assert ev["authorizedBy"] == AUTHORIZED_BY
        full = {**payload, "evidence": [ev]}  # evidence attached as issued
        auth = verify_batch_evidence(full, ev, pub, expected_audience=AUDIENCE)
        assert auth["aud"] == AUDIENCE


def test_n1_degenerate_batch(keypair):
    priv, pub = keypair
    payloads = [_payload(1)]
    evidence = build_batch_evidence(
        payloads, priv, authorized_by=AUTHORIZED_BY, audience=AUDIENCE, sd_hash=SD_HASH
    )
    assert evidence[0]["merkleProof"]["path"] == []
    verify_batch_evidence({**payloads[0], "evidence": evidence}, evidence[0], pub)


def test_tampered_payload_fails(keypair):
    priv, pub = keypair
    payloads = [_payload(i) for i in range(1, 5)]
    evidence = build_batch_evidence(
        payloads, priv, authorized_by=AUTHORIZED_BY, audience=AUDIENCE, sd_hash=SD_HASH
    )
    tampered = copy.deepcopy(payloads[0])
    tampered["credentialSubject"]["id"] = "did:ethr:0x14a34:0xdeadbeef"
    with pytest.raises(VerificationError):
        verify_batch_evidence(tampered, evidence[0], pub)


def test_tampered_message_fails(keypair):
    """Swapping the root inside the message breaks the nonce commitment."""
    priv, pub = keypair
    payloads = [_payload(1)]
    evidence = build_batch_evidence(
        payloads, priv, authorized_by=AUTHORIZED_BY, audience=AUDIENCE, sd_hash=SD_HASH
    )
    ev = copy.deepcopy(evidence[0])
    real_root, _ = extract_root_from_message(ev["authorizationMessage"])
    ev["authorizationMessage"] = ev["authorizationMessage"].replace(real_root, "B" * 43)
    with pytest.raises(VerificationError):
        verify_batch_evidence(payloads[0], ev, pub)


def test_missing_message_fails(keypair):
    priv, pub = keypair
    payloads = [_payload(1)]
    evidence = build_batch_evidence(
        payloads, priv, authorized_by=AUTHORIZED_BY, audience=AUDIENCE, sd_hash=SD_HASH
    )
    ev = {k: v for k, v in evidence[0].items() if k != "authorizationMessage"}
    with pytest.raises(VerificationError):
        verify_batch_evidence(payloads[0], ev, pub)


def test_wrong_wallet_key_fails(keypair):
    priv, _ = keypair
    _, other_pub = generate_p256_keypair()
    payloads = [_payload(1)]
    evidence = build_batch_evidence(
        payloads, priv, authorized_by=AUTHORIZED_BY, audience=AUDIENCE, sd_hash=SD_HASH
    )
    with pytest.raises(VerificationError):
        verify_batch_evidence(payloads[0], evidence[0], other_pub)


def test_evidence_excluded_from_leaf_so_proof_holds_after_attach(keypair):
    """Attaching evidence to the payload must not change the leaf/proof."""
    priv, pub = keypair
    payloads = [_payload(i) for i in range(1, 4)]
    evidence = build_batch_evidence(
        payloads, priv, authorized_by=AUTHORIZED_BY, audience=AUDIENCE, sd_hash=SD_HASH
    )
    # The leaf computed with vs without evidence must match (evidence stripped).
    with_ev = {**payloads[2], "evidence": [evidence[2]]}
    assert compute_leaf(with_ev) == compute_leaf(payloads[2])
    verify_batch_evidence(with_ev, evidence[2], pub, expected_audience=AUDIENCE)


def test_kb_jwt_not_replayable_across_ceremonies(keypair):
    """Same batch, two ceremonies: each message hash (and KB-JWT) differs."""
    priv, _ = keypair
    payloads = [_payload(1)]
    ev_a = build_batch_evidence(
        payloads, priv, authorized_by=AUTHORIZED_BY, audience=AUDIENCE, sd_hash=SD_HASH
    )
    ev_b = build_batch_evidence(
        payloads, priv, authorized_by=AUTHORIZED_BY, audience=AUDIENCE, sd_hash=SD_HASH
    )
    # The random ceremony nonce inside the hashed message makes each
    # ceremony's commitment unique even for an identical root (§9.6).
    assert ev_a[0]["authorizationMessage"] != ev_b[0]["authorizationMessage"]
