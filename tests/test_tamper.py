"""Tests that tampering with a VC-JOSE-COSE JWS causes verification to fail."""

import base64
import json

import pytest

from harbour.jose.signer import sign_vc_jose
from harbour.jose.verifier import VerificationError, verify_vc_jose


def test_tamper_payload(sample_vc, p256_private_key, p256_public_key):
    """Modifying the payload after signing should fail verification."""
    token = sign_vc_jose(sample_vc, p256_private_key)
    parts = token.split(".")

    # Decode payload, tamper, re-encode
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    payload["credentialSubject"]["id"] = "did:web:did.ascs.digital:participants:evil"
    tampered_payload = (
        base64.urlsafe_b64encode(
            json.dumps(payload, ensure_ascii=False).encode("utf-8")
        )
        .rstrip(b"=")
        .decode()
    )

    tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"
    with pytest.raises(VerificationError):
        verify_vc_jose(tampered_token, p256_public_key)


def test_tamper_signature(sample_vc, p256_private_key, p256_public_key):
    """Corrupting the signature should fail verification."""
    token = sign_vc_jose(sample_vc, p256_private_key)
    parts = token.split(".")

    sig = parts[2]
    corrupted = sig[:-1] + ("A" if sig[-1] != "A" else "B")
    tampered_token = f"{parts[0]}.{parts[1]}.{corrupted}"

    with pytest.raises(VerificationError):
        verify_vc_jose(tampered_token, p256_public_key)


def test_tamper_header(sample_vc, p256_private_key, p256_public_key):
    """Modifying the header should fail verification."""
    token = sign_vc_jose(sample_vc, p256_private_key)
    parts = token.split(".")

    # Decode header, tamper alg
    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    header["kid"] = "did:web:evil.example.com#key-1"
    tampered_header = (
        base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    )

    tampered_token = f"{tampered_header}.{parts[1]}.{parts[2]}"
    with pytest.raises(VerificationError):
        verify_vc_jose(tampered_token, p256_public_key)


def test_truncated_token(p256_public_key):
    """A truncated token should fail."""
    with pytest.raises(VerificationError):
        verify_vc_jose("eyJhbGciOiJFUzI1NiJ9.eyJ0ZXN0IjoxfQ", p256_public_key)
