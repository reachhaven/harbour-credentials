"""Legacy tests for Ed25519Signature2018 VC verification (deprecated)."""

import json

import pytest
from harbour.keys import generate_ed25519_keypair
from harbour.signer import sign_vc
from harbour.verifier import VerificationError, verify_vc

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


def test_verify_valid_signature(sample_vc, private_key, public_key, did_key_vm):
    signed = sign_vc(sample_vc, private_key, did_key_vm)
    assert verify_vc(signed, public_key) is True


def test_verify_wrong_key_fails(sample_vc, private_key, did_key_vm):
    signed = sign_vc(sample_vc, private_key, did_key_vm)
    _, wrong_public = generate_ed25519_keypair()
    with pytest.raises(VerificationError):
        verify_vc(signed, wrong_public)


def test_verify_roundtrip(sample_vc, private_key, public_key, did_key_vm):
    """Sign, serialize to JSON, deserialize, then verify."""
    signed = sign_vc(sample_vc, private_key, did_key_vm)
    json_str = json.dumps(signed)
    deserialized = json.loads(json_str)
    assert verify_vc(deserialized, public_key) is True
