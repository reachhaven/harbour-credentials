"""Tests for VC-JOSE-COSE verification."""

import pytest
from harbour.keys import generate_p256_keypair
from harbour.signer import sign_vc_jose, sign_vp_jose
from harbour.verifier import VerificationError, verify_vc_jose, verify_vp_jose

# ---------------------------------------------------------------------------
# VC verification — P-256
# ---------------------------------------------------------------------------


def test_verify_vc_jose_valid(sample_vc, p256_private_key, p256_public_key):
    token = sign_vc_jose(sample_vc, p256_private_key)
    result = verify_vc_jose(token, p256_public_key)
    assert result == sample_vc


def test_verify_vc_jose_wrong_key_fails(sample_vc, p256_private_key):
    token = sign_vc_jose(sample_vc, p256_private_key)
    _, wrong_public = generate_p256_keypair()
    with pytest.raises(VerificationError):
        verify_vc_jose(token, wrong_public)


def test_verify_vc_jose_roundtrip_json(sample_vc, p256_private_key, p256_public_key):
    """Sign, transmit as string, then verify."""
    token = sign_vc_jose(sample_vc, p256_private_key)
    # Simulate string transmission
    token_copy = str(token)
    result = verify_vc_jose(token_copy, p256_public_key)
    assert result == sample_vc


# ---------------------------------------------------------------------------
# VC verification — Ed25519
# ---------------------------------------------------------------------------


def test_verify_vc_jose_eddsa(sample_vc, ed25519_private_key, ed25519_public_key):
    token = sign_vc_jose(sample_vc, ed25519_private_key)
    result = verify_vc_jose(token, ed25519_public_key)
    assert result == sample_vc


def test_verify_vc_jose_cross_alg_fails(
    sample_vc, p256_private_key, ed25519_public_key
):
    """P-256 signed token cannot be verified with Ed25519 key."""
    token = sign_vc_jose(sample_vc, p256_private_key)
    with pytest.raises(VerificationError):
        verify_vc_jose(token, ed25519_public_key)


# ---------------------------------------------------------------------------
# VP verification
# ---------------------------------------------------------------------------


def test_verify_vp_jose_valid(sample_vp, p256_private_key, p256_public_key):
    token = sign_vp_jose(
        sample_vp,
        p256_private_key,
        nonce="test-nonce",
        audience="did:ethr:0x14a34:0x6c6ddd7fb6c9732f30734a63db7e257987aed0e0",
    )
    result = verify_vp_jose(
        token,
        p256_public_key,
        expected_nonce="test-nonce",
        expected_audience="did:ethr:0x14a34:0x6c6ddd7fb6c9732f30734a63db7e257987aed0e0",
    )
    assert result["type"] == sample_vp["type"]
    assert result["nonce"] == "test-nonce"
    assert (
        result["aud"] == "did:ethr:0x14a34:0x6c6ddd7fb6c9732f30734a63db7e257987aed0e0"
    )


def test_verify_vp_jose_wrong_nonce_fails(sample_vp, p256_private_key, p256_public_key):
    token = sign_vp_jose(sample_vp, p256_private_key, nonce="real-nonce")
    with pytest.raises(VerificationError, match="Nonce mismatch"):
        verify_vp_jose(token, p256_public_key, expected_nonce="wrong-nonce")


def test_verify_vp_jose_wrong_audience_fails(
    sample_vp, p256_private_key, p256_public_key
):
    token = sign_vp_jose(
        sample_vp,
        p256_private_key,
        audience="did:ethr:0x14a34:0x6176cb54dc4498765590d7e5522523ef9e634906",
    )
    with pytest.raises(VerificationError, match="Audience mismatch"):
        verify_vp_jose(
            token,
            p256_public_key,
            expected_audience="did:ethr:0x14a34:0x81c6d42b1781bb3bb7a280f564d66ec9d41beace",
        )


def test_verify_vp_jose_no_nonce_check_if_not_expected(
    sample_vp, p256_private_key, p256_public_key
):
    """If expected_nonce is None, no nonce check is performed."""
    token = sign_vp_jose(sample_vp, p256_private_key)
    result = verify_vp_jose(token, p256_public_key)
    assert result["type"] == sample_vp["type"]
