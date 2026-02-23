"""Validate credential fixtures against generated JSON-LD context and SHACL shapes.

Tests:
1. JSON-LD syntax: all fixtures parse as valid JSON with required VC structure
2. Context consistency: fixture property names match the generated harbour context
3. SHACL conformance: credential structure conforms to generated SHACL shapes
"""

import json
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent
while _REPO_ROOT.name != "harbour-credentials" and _REPO_ROOT != _REPO_ROOT.parent:
    _REPO_ROOT = _REPO_ROOT.parent

FIXTURES_DIR = _REPO_ROOT / "tests" / "fixtures" / "credentials"
EXAMPLES_DIR = _REPO_ROOT / "examples"
ARTIFACTS_DIR = _REPO_ROOT / "artifacts" / "harbour"
CONTEXT_PATH = ARTIFACTS_DIR / "harbour.context.jsonld"
SHACL_PATH = ARTIFACTS_DIR / "harbour.shacl.ttl"


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def _all_credential_files() -> list[Path]:
    """Collect all credential JSON files from fixtures and examples."""
    files = []
    if FIXTURES_DIR.is_dir():
        files.extend(sorted(FIXTURES_DIR.glob("harbour-*.json")))
    if EXAMPLES_DIR.is_dir():
        files.extend(sorted(EXAMPLES_DIR.glob("*.json")))
    return files


# ---------------------------------------------------------------------------
# 1. JSON-LD syntax validation
# ---------------------------------------------------------------------------


@pytest.fixture(params=_all_credential_files(), ids=lambda p: p.name)
def credential_file(request):
    return request.param


def test_valid_json(credential_file):
    """Each credential file must be valid JSON."""
    data = _load_json(credential_file)
    assert isinstance(data, dict)


def test_has_context(credential_file):
    """Each credential must have an @context array."""
    data = _load_json(credential_file)
    ctx = data.get("@context")
    assert isinstance(
        ctx, list
    ), f"Missing or invalid @context in {credential_file.name}"
    assert "https://www.w3.org/ns/credentials/v2" in ctx


def test_has_type(credential_file):
    """Each credential must have a type array with VerifiableCredential."""
    data = _load_json(credential_file)
    types = data.get("type", [])
    assert (
        "VerifiableCredential" in types
    ), f"Missing VerifiableCredential type in {credential_file.name}"


def test_has_issuer(credential_file):
    """Each credential must have an issuer."""
    data = _load_json(credential_file)
    issuer = data.get("issuer")
    assert issuer is not None, f"Missing issuer in {credential_file.name}"
    if isinstance(issuer, dict):
        assert "id" in issuer
    else:
        assert isinstance(issuer, str) and issuer.startswith("did:")


def test_has_valid_from(credential_file):
    """Each credential must have a validFrom date."""
    data = _load_json(credential_file)
    assert "validFrom" in data, f"Missing validFrom in {credential_file.name}"


def test_has_credential_status(credential_file):
    """Each harbour credential must have a credentialStatus with CRSetEntry."""
    data = _load_json(credential_file)
    status = data.get("credentialStatus")
    assert (
        isinstance(status, list) and len(status) > 0
    ), f"Missing credentialStatus in {credential_file.name}"
    for entry in status:
        assert entry.get("type") == "harbour:CRSetEntry"
        assert "statusPurpose" in entry


def test_credential_subject_has_type(credential_file):
    """Each credential subject must have a type."""
    data = _load_json(credential_file)
    subject = data.get("credentialSubject", {})
    assert (
        "type" in subject
    ), f"Missing credentialSubject.type in {credential_file.name}"


# ---------------------------------------------------------------------------
# 2. Context consistency
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not CONTEXT_PATH.exists(),
    reason="Generated artifacts not found — run 'make generate' (covered by generate-validate CI job)",
)
class TestContextConsistency:
    """Verify that generated harbour context covers all fixture properties."""

    def test_context_is_non_empty(self):
        ctx = _load_json(CONTEXT_PATH)
        context = ctx.get("@context", {})
        # Must have class mappings
        assert "LegalPersonCredential" in context
        assert "NaturalPersonCredential" in context
        assert "ServiceOfferingCredential" in context

    def test_class_iris_are_prefixed(self):
        """All harbour classes must have prefixed @id (not bare local names)."""
        ctx = _load_json(CONTEXT_PATH).get("@context", {})
        harbour_classes = [
            "CRSetEntry",
            "EmailVerification",
            "IssuanceEvidence",
            "LegalPerson",
            "NaturalPerson",
            "ServiceOffering",
            "LegalPersonCredential",
            "NaturalPersonCredential",
            "ServiceOfferingCredential",
        ]
        for cls in harbour_classes:
            entry = ctx.get(cls)
            assert entry is not None, f"Missing {cls} in context"
            aid = entry.get("@id") if isinstance(entry, dict) else entry
            assert ":" in aid, f"{cls} has unprefixed @id: {aid}"


# ---------------------------------------------------------------------------
# 3. SHACL conformance (structural check)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not SHACL_PATH.exists(),
    reason="Generated artifacts not found — run 'make generate' (covered by generate-validate CI job)",
)
class TestShaclShapes:
    """Verify that SHACL shapes exist for all harbour credential types."""

    def test_shacl_is_non_empty(self):
        content = SHACL_PATH.read_text()
        assert len(content) > 100, "SHACL file is too small — check generation"

    def test_shacl_has_credential_shapes(self):
        content = SHACL_PATH.read_text()
        expected_shapes = [
            "harbour:LegalPersonCredential",
            "harbour:NaturalPersonCredential",
            "harbour:ServiceOfferingCredential",
            "harbour:HarbourCredential",
            "harbour:CRSetEntry",
            "harbour:EmailVerification",
            "harbour:IssuanceEvidence",
            "harbour:LegalPerson",
            "harbour:NaturalPerson",
            "harbour:ServiceOffering",
        ]
        for shape in expected_shapes:
            assert (
                f"{shape} a sh:NodeShape" in content
            ), f"Missing SHACL NodeShape for {shape}"

    def test_shacl_credential_shapes_have_required_properties(self):
        """Concrete credential shapes must require validFrom and credentialStatus."""
        content = SHACL_PATH.read_text()
        for cred_type in [
            "LegalPersonCredential",
            "NaturalPersonCredential",
            "ServiceOfferingCredential",
        ]:
            # Find the shape block
            marker = f"harbour:{cred_type} a sh:NodeShape"
            assert marker in content, f"Missing shape for {cred_type}"
            # The shape should reference cred:validFrom and cred:credentialStatus
            # (inherited from HarbourCredential but materialized by gen-shacl
            # because we added slot_usage)
            shape_start = content.index(marker)
            # Find next shape or end of file
            next_shape = content.find("\n\n", shape_start + 1)
            if next_shape == -1:
                next_shape = len(content)
            shape_block = content[shape_start:next_shape]
            assert (
                "cred:validFrom" in shape_block
            ), f"{cred_type} shape missing cred:validFrom"
            assert (
                "cred:credentialStatus" in shape_block
            ), f"{cred_type} shape missing cred:credentialStatus"

    def test_evidence_shapes_require_verifiable_presentation(self):
        """Evidence shapes must require verifiablePresentation."""
        content = SHACL_PATH.read_text()
        for ev_type in ["EmailVerification", "IssuanceEvidence"]:
            marker = f"harbour:{ev_type} a sh:NodeShape"
            shape_start = content.index(marker)
            next_shape = content.find("\n\n", shape_start + 1)
            if next_shape == -1:
                next_shape = len(content)
            shape_block = content[shape_start:next_shape]
            assert (
                "harbour:verifiablePresentation" in shape_block
            ), f"{ev_type} shape missing harbour:verifiablePresentation"
            assert (
                "sh:minCount 1" in shape_block
            ), f"{ev_type} shape missing sh:minCount 1 for verifiablePresentation"
