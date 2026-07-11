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


def test_verify_signed_sd_jwt(signed_sd_jwt):
    """Verify a pre-generated dc+sd-jwt artifact from a signed/ dir.

    Resolves the proof key strictly from the issuer's DID document via the
    kid header (ADR-006) — proving each artifact was signed by a mandate key
    the issuer actually publishes, with no fallback.
    """
    from credentials.example_signer import _find_repo_root
    from credentials.verify_signed_examples import (
        _issuer_header,
        _load_did_vm_keys,
        _raw_issuer_payload,
    )
    from harbour.sd_jwt import verify_sd_jwt_vc

    vm_keys = _load_did_vm_keys(_find_repo_root())
    assert vm_keys, "example DID documents must be present"

    issuer_did = _raw_issuer_payload(signed_sd_jwt).get("issuer", "")
    kid = _issuer_header(signed_sd_jwt).get("kid")
    assert isinstance(kid, str) and kid.startswith(f"{issuer_did}#"), (
        f"proof kid {kid!r} must name a method of issuer {issuer_did}"
    )
    pub = vm_keys.get(kid)
    assert pub is not None, f"kid {kid!r} not published in the issuer's DID document"

    result = verify_sd_jwt_vc(signed_sd_jwt, pub)
    assert "type" in result
    assert "VerifiableCredential" in result["type"]
