"""Sign and verify all example credentials from examples/."""

import pytest

from harbour.signer import sign_vc_jose
from harbour.verifier import VerificationError, verify_vc_jose

# ---------------------------------------------------------------------------
# VC-JOSE-COSE (ES256) — current format
# ---------------------------------------------------------------------------


def test_sign_and_verify_example_jose(
    example_vc, p256_private_key, p256_public_key, p256_did_key_vm
):
    """Sign an example VC as VC-JOSE-COSE JWT, then verify."""
    token = sign_vc_jose(example_vc, p256_private_key, kid=p256_did_key_vm)
    result = verify_vc_jose(token, p256_public_key)
    assert result["id"] == example_vc["id"]
    assert result["type"] == example_vc["type"]


def test_tamper_detection_jose(
    example_vc, p256_private_key, p256_public_key, p256_did_key_vm
):
    """Sign, tamper with JWT payload, verify detection."""
    import base64
    import json

    token = sign_vc_jose(example_vc, p256_private_key, kid=p256_did_key_vm)
    parts = token.split(".")

    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    payload["credentialSubject"]["id"] = (
        "did:ethr:0x14a34:0x81c6d42b1781bb3bb7a280f564d66ec9d41beace"
    )
    tampered_payload = (
        base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    )
    tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"

    with pytest.raises(VerificationError):
        verify_vc_jose(tampered_token, p256_public_key)


def test_verify_signed_jwt(signed_jwt):
    """Verify a pre-generated signed JWT from examples/signed/.

    Uses the role keyring to resolve the correct public key from the
    JWT's kid header, proving that each credential was signed by the
    expected role.
    """
    import base64
    import json

    from credentials.example_signer import load_role_keyring, load_test_p256_keypair
    from credentials.verify_signed_examples import KeyResolver

    keyring = load_role_keyring()
    _, fallback_pub = load_test_p256_keypair()
    resolver = KeyResolver(keyring, fallback_pub)

    parts = signed_jwt.split(".")
    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    kid = header.get("kid")
    pub = resolver.resolve(kid)

    result = verify_vc_jose(signed_jwt, pub)
    assert "type" in result
    assert "VerifiableCredential" in result["type"]
