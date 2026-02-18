"""Tests for VC-JOSE-COSE signing (compact JWS)."""

import base64
import json

from harbour.jose.signer import sign_vc_jose, sign_vp_jose


# ---------------------------------------------------------------------------
# VC signing — P-256 (ES256)
# ---------------------------------------------------------------------------


def test_sign_vc_jose_returns_compact_jws(sample_vc, p256_private_key):
    token = sign_vc_jose(sample_vc, p256_private_key)
    parts = token.split(".")
    assert len(parts) == 3, f"Expected 3-part compact JWS, got {len(parts)} parts"
    assert all(len(p) > 0 for p in parts)


def test_sign_vc_jose_header_typ(sample_vc, p256_private_key):
    token = sign_vc_jose(sample_vc, p256_private_key)
    header = _decode_header(token)
    assert header["alg"] == "ES256"
    assert header["typ"] == "vc+ld+jwt"


def test_sign_vc_jose_header_kid(sample_vc, p256_private_key, p256_did_key_vm):
    token = sign_vc_jose(sample_vc, p256_private_key, kid=p256_did_key_vm)
    header = _decode_header(token)
    assert header["kid"] == p256_did_key_vm


def test_sign_vc_jose_header_x5c(sample_vc, p256_private_key):
    fake_cert = base64.b64encode(b"fake-cert-bytes").decode()
    token = sign_vc_jose(sample_vc, p256_private_key, x5c=[fake_cert])
    header = _decode_header(token)
    assert header["x5c"] == [fake_cert]


def test_sign_vc_jose_payload_matches_vc(sample_vc, p256_private_key):
    token = sign_vc_jose(sample_vc, p256_private_key)
    payload = _decode_payload(token)
    assert payload == sample_vc


def test_sign_vc_jose_does_not_modify_input(sample_vc, p256_private_key):
    import copy

    original = copy.deepcopy(sample_vc)
    sign_vc_jose(sample_vc, p256_private_key)
    assert sample_vc == original


# ---------------------------------------------------------------------------
# VC signing — Ed25519 (EdDSA)
# ---------------------------------------------------------------------------


def test_sign_vc_jose_eddsa(sample_vc, ed25519_private_key):
    token = sign_vc_jose(sample_vc, ed25519_private_key)
    header = _decode_header(token)
    assert header["alg"] == "EdDSA"
    assert header["typ"] == "vc+ld+jwt"


# ---------------------------------------------------------------------------
# VP signing
# ---------------------------------------------------------------------------


def test_sign_vp_jose_returns_compact_jws(sample_vp, p256_private_key):
    token = sign_vp_jose(sample_vp, p256_private_key)
    parts = token.split(".")
    assert len(parts) == 3


def test_sign_vp_jose_header_typ(sample_vp, p256_private_key):
    token = sign_vp_jose(sample_vp, p256_private_key)
    header = _decode_header(token)
    assert header["typ"] == "vp+ld+jwt"


def test_sign_vp_jose_nonce_and_audience(sample_vp, p256_private_key):
    token = sign_vp_jose(
        sample_vp,
        p256_private_key,
        nonce="challenge-123",
        audience="did:web:verifier.example.com",
    )
    payload = _decode_payload(token)
    assert payload["nonce"] == "challenge-123"
    assert payload["aud"] == "did:web:verifier.example.com"
    # Original VP fields are preserved
    assert payload["type"] == sample_vp["type"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _decode_header(token: str) -> dict:
    header_b64 = token.split(".")[0]
    header_bytes = base64.urlsafe_b64decode(header_b64 + "==")
    return json.loads(header_bytes)


def _decode_payload(token: str) -> dict:
    payload_b64 = token.split(".")[1]
    payload_bytes = base64.urlsafe_b64decode(payload_b64 + "==")
    return json.loads(payload_bytes)
