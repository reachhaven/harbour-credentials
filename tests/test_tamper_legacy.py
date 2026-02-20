"""Legacy tests for tampering detection with Ed25519Signature2018 (deprecated)."""

import pytest
from harbour.signer import sign_vc
from harbour.verifier import VerificationError, verify_vc

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


def test_tamper_subject_id(sample_vc, private_key, public_key, did_key_vm):
    signed = sign_vc(sample_vc, private_key, did_key_vm)
    signed["credentialSubject"]["id"] = "did:web:did.ascs.digital:participants:evil"
    with pytest.raises(VerificationError):
        verify_vc(signed, public_key)


def test_tamper_issuer(sample_vc, private_key, public_key, did_key_vm):
    signed = sign_vc(sample_vc, private_key, did_key_vm)
    signed["issuer"]["id"] = "did:web:evil.example.com"
    with pytest.raises(VerificationError):
        verify_vc(signed, public_key)


def test_tamper_add_field(sample_vc, private_key, public_key, did_key_vm):
    signed = sign_vc(sample_vc, private_key, did_key_vm)
    signed["malicious"] = "injected"
    with pytest.raises(VerificationError):
        verify_vc(signed, public_key)


def test_tamper_proof_jws(sample_vc, private_key, public_key, did_key_vm):
    signed = sign_vc(sample_vc, private_key, did_key_vm)
    jws_val = signed["proof"]["jws"]
    # Corrupt the signature by flipping a character
    parts = jws_val.split("..")
    corrupted_sig = parts[1][:-1] + ("A" if parts[1][-1] != "A" else "B")
    signed["proof"]["jws"] = f"{parts[0]}..{corrupted_sig}"
    with pytest.raises(VerificationError):
        verify_vc(signed, public_key)
