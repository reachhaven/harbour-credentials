"""Legacy tests for Ed25519Signature2018 VC signing (deprecated)."""

import warnings

import pytest

from harbour.jose.signer import sign_vc

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


def test_sign_adds_proof(sample_vc, private_key, did_key_vm):
    signed = sign_vc(sample_vc, private_key, did_key_vm)
    proof = signed["proof"]
    assert proof["type"] == "Ed25519Signature2018"
    assert proof["proofPurpose"] == "assertionMethod"
    assert proof["verificationMethod"] == did_key_vm
    assert "created" in proof
    assert "jws" in proof


def test_sign_jws_structure(sample_vc, private_key, did_key_vm):
    signed = sign_vc(sample_vc, private_key, did_key_vm)
    jws_value = signed["proof"]["jws"]
    # Detached JWS: header..signature (no payload in the middle)
    parts = jws_value.split("..")
    assert (
        len(parts) == 2
    ), f"Expected detached JWS (header..sig), got: {jws_value[:60]}"
    assert len(parts[0]) > 0  # header
    assert len(parts[1]) > 0  # signature


def test_sign_preserves_vc(sample_vc, private_key, did_key_vm):
    signed = sign_vc(sample_vc, private_key, did_key_vm)
    # All original fields should still be present
    assert signed["@context"] == sample_vc["@context"]
    assert signed["type"] == sample_vc["type"]
    assert signed["id"] == sample_vc["id"]
    assert signed["issuer"] == sample_vc["issuer"]
    assert signed["credentialSubject"] == sample_vc["credentialSubject"]


def test_sign_does_not_modify_original(sample_vc, private_key, did_key_vm):
    import copy

    original = copy.deepcopy(sample_vc)
    sign_vc(sample_vc, private_key, did_key_vm)
    assert sample_vc == original, "sign_vc should not mutate the input"


def test_sign_vc_emits_deprecation_warning(sample_vc, private_key, did_key_vm):
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        sign_vc(sample_vc, private_key, did_key_vm)
    assert any(issubclass(x.category, DeprecationWarning) for x in w)
