"""End-to-end tests for the example_signer evidence signing flow.

Verifies:
1. Expanded examples with evidence VPs can be signed
2. Outer VC JWT is valid and verifiable
3. Evidence VP JWT is valid with signed inner VCs
4. The full chain: inner VC → VP → outer VC
"""

from pathlib import Path

import pytest
from credentials.example_signer import (
    decode_evidence_vp,
    load_test_p256_keypair,
    process_example,
    sign_evidence_vp,
)
from harbour.keys import p256_public_key_to_did_key
from harbour.verifier import verify_vc_jose, verify_vp_jose

_REPO_ROOT = Path(__file__).resolve().parent
while _REPO_ROOT.name != "harbour-credentials" and _REPO_ROOT != _REPO_ROOT.parent:
    _REPO_ROOT = _REPO_ROOT.parent

EXAMPLES_DIR = _REPO_ROOT / "examples"


@pytest.fixture(scope="module")
def signing_key():
    """Load the test P-256 keypair."""
    private_key, public_key = load_test_p256_keypair()
    did = p256_public_key_to_did_key(public_key)
    kid = f"{did}#{did.split(':')[-1]}"
    return private_key, public_key, kid


@pytest.fixture(
    params=(
        [p for p in sorted(EXAMPLES_DIR.glob("*.json"))]
        if EXAMPLES_DIR.exists()
        else []
    ),
    ids=lambda p: p.name,
)
def example_path(request):
    return request.param


class TestEvidenceSigning:
    """Test the evidence VP signing flow."""

    def test_sign_evidence_vp(self, signing_key):
        """Sign an evidence VP with inner VCs and verify the chain."""
        private_key, public_key, kid = signing_key

        vp = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "holder": "did:webs:participants.example.com:legal-persons:bmw_ag:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe",
            "verifiableCredential": [
                {
                    "@context": ["https://www.w3.org/ns/credentials/v2"],
                    "type": ["VerifiableCredential"],
                    "issuer": "did:web:notary.example.com",
                    "validFrom": "2024-01-10T00:00:00Z",
                    "credentialSubject": {
                        "id": "did:webs:participants.example.com:legal-persons:bmw_ag:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe",
                        "type": "gx:LegalPerson",
                    },
                }
            ],
        }

        vp_jwt = sign_evidence_vp(vp, private_key, kid)

        assert isinstance(vp_jwt, str)
        assert vp_jwt.count(".") == 2

        # Verify the VP JWT
        vp_payload = verify_vp_jose(vp_jwt, public_key)
        assert "VerifiablePresentation" in vp_payload["type"]

        # Inner VCs should be JWT strings
        inner_vcs = vp_payload.get("verifiableCredential", [])
        assert len(inner_vcs) == 1
        assert isinstance(inner_vcs[0], str)

        # Verify inner VC JWT
        inner_vc = verify_vc_jose(inner_vcs[0], public_key)
        assert "VerifiableCredential" in inner_vc["type"]

    def test_decode_evidence_vp(self, signing_key):
        """Decode an evidence VP JWT and verify inner VCs are decoded."""
        private_key, public_key, kid = signing_key

        vp = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": [
                {
                    "@context": ["https://www.w3.org/ns/credentials/v2"],
                    "type": ["VerifiableCredential"],
                    "issuer": "did:web:notary.example.com",
                    "validFrom": "2024-01-10T00:00:00Z",
                    "credentialSubject": {"id": "did:example:sub"},
                }
            ],
        }

        vp_jwt = sign_evidence_vp(vp, private_key, kid)
        decoded = decode_evidence_vp(vp_jwt)

        assert "header" in decoded
        assert "payload" in decoded
        assert decoded["header"]["typ"] == "vp+ld+jwt"

        inner_vcs = decoded["payload"]["verifiableCredential"]
        assert len(inner_vcs) == 1
        assert "_jwt" in inner_vcs[0]
        assert "_decoded" in inner_vcs[0]


class TestProcessExample:
    """Test the full example processing pipeline."""

    def test_process_example_with_evidence(self, signing_key, tmp_path):
        """Process an example with evidence VP through the full pipeline."""
        private_key, public_key, kid = signing_key

        # Load legal person example (has evidence)
        example_path = EXAMPLES_DIR / "legal-person-credential.json"
        if not example_path.exists():
            pytest.skip("examples/ not populated")

        output_dir = tmp_path / "signed"
        jwt_path = process_example(example_path, private_key, kid, output_dir)

        # Verify output files exist
        assert jwt_path.exists()
        assert (output_dir / "legal-person-credential.decoded.json").exists()
        assert (output_dir / "legal-person-credential.evidence-vp.jwt").exists()
        assert (
            output_dir / "legal-person-credential.evidence-vp.decoded.json"
        ).exists()

        # Verify outer VC JWT
        vc_jwt = jwt_path.read_text().strip()
        vc_payload = verify_vc_jose(vc_jwt, public_key)
        assert vc_payload["id"] == "urn:uuid:a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        assert "harbour:LegalPersonCredential" in vc_payload["type"]

        # Evidence should now be a JWT string
        evidence = vc_payload["evidence"][0]
        vp_jwt_str = evidence["verifiablePresentation"]
        assert isinstance(vp_jwt_str, str)
        assert vp_jwt_str.count(".") == 2

        # Verify evidence VP
        vp_payload = verify_vp_jose(vp_jwt_str, public_key)
        assert "VerifiablePresentation" in vp_payload["type"]

    def test_process_example_without_evidence(self, signing_key, tmp_path):
        """Process an example without evidence VP."""
        private_key, public_key, kid = signing_key

        example_path = EXAMPLES_DIR / "service-offering-credential.json"
        if not example_path.exists():
            pytest.skip("examples/ not populated")

        output_dir = tmp_path / "signed"
        jwt_path = process_example(example_path, private_key, kid, output_dir)

        # Verify output files exist
        assert jwt_path.exists()
        assert (output_dir / "service-offering-credential.decoded.json").exists()
        # No evidence VP files
        assert not (output_dir / "service-offering-credential.evidence-vp.jwt").exists()

        # Verify outer VC JWT
        vc_jwt = jwt_path.read_text().strip()
        vc_payload = verify_vc_jose(vc_jwt, public_key)
        assert "harbour:ServiceOfferingCredential" in vc_payload["type"]

    def test_process_delegated_signing_receipt(self, signing_key, tmp_path):
        """Process the delegated signing receipt with DelegatedSignatureEvidence."""
        private_key, public_key, kid = signing_key

        example_path = EXAMPLES_DIR / "delegated-signing-receipt.json"
        if not example_path.exists():
            pytest.skip("examples/ not populated")

        output_dir = tmp_path / "signed"
        jwt_path = process_example(example_path, private_key, kid, output_dir)

        # Verify output files exist
        assert jwt_path.exists()
        assert (output_dir / "delegated-signing-receipt.decoded.json").exists()
        assert (output_dir / "delegated-signing-receipt.evidence-vp.jwt").exists()

        # Verify outer VC JWT
        vc_jwt = jwt_path.read_text().strip()
        vc_payload = verify_vc_jose(vc_jwt, public_key)
        assert "harbour:DelegatedSigningReceipt" in vc_payload["type"]

        # Evidence should contain DelegatedSignatureEvidence with transaction_data
        evidence = vc_payload["evidence"][0]
        assert evidence["type"] == "harbour:DelegatedSignatureEvidence"
        assert "transaction_data" in evidence
        assert evidence["transaction_data"]["type"] == "harbour_delegate:data.purchase"
        assert evidence["delegatedTo"] == "did:web:signing-service.envited.io"

        # Evidence VP should be a signed JWT
        vp_jwt_str = evidence["verifiablePresentation"]
        assert isinstance(vp_jwt_str, str)
        assert vp_jwt_str.count(".") == 2

    def test_process_all_examples(self, signing_key, tmp_path):
        """Process all examples and verify each produces a valid JWT."""
        private_key, public_key, kid = signing_key

        example_files = sorted(EXAMPLES_DIR.glob("*-credential.json"))
        if not example_files:
            pytest.skip("examples/ not populated")

        output_dir = tmp_path / "signed"
        for path in example_files:
            jwt_path = process_example(path, private_key, kid, output_dir)
            vc_jwt = jwt_path.read_text().strip()
            vc_payload = verify_vc_jose(vc_jwt, public_key)
            assert "VerifiableCredential" in vc_payload["type"]
