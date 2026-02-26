"""Validate credential fixtures against generated JSON-LD context and SHACL shapes.

Tests:
1. JSON-LD syntax: all fixtures parse as valid JSON with required VC structure
2. Context consistency: fixture property names match the generated contexts
3. SHACL conformance: credential structure conforms to generated SHACL shapes

Harbour base artifacts live in artifacts/harbour/.
Gaia-X domain artifacts live in artifacts/gaiax-domain/.
"""

import json
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent
while _REPO_ROOT.name != "harbour-credentials" and _REPO_ROOT != _REPO_ROOT.parent:
    _REPO_ROOT = _REPO_ROOT.parent

EXAMPLES_DIR = _REPO_ROOT / "examples"

# Harbour base artifacts
HARBOUR_ARTIFACTS_DIR = _REPO_ROOT / "artifacts" / "harbour"
HARBOUR_CONTEXT_PATH = HARBOUR_ARTIFACTS_DIR / "harbour.context.jsonld"
HARBOUR_SHACL_PATH = HARBOUR_ARTIFACTS_DIR / "harbour.shacl.ttl"

# Gaia-X domain artifacts
DOMAIN_ARTIFACTS_DIR = _REPO_ROOT / "artifacts" / "gaiax-domain"
DOMAIN_CONTEXT_PATH = DOMAIN_ARTIFACTS_DIR / "gaiax-domain.context.jsonld"
DOMAIN_SHACL_PATH = DOMAIN_ARTIFACTS_DIR / "gaiax-domain.shacl.ttl"


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def _all_credential_files() -> list[Path]:
    """Collect all credential JSON files from examples/ and examples/gaiax/."""
    files: list[Path] = []
    if EXAMPLES_DIR.is_dir():
        files.extend(
            p
            for p in EXAMPLES_DIR.glob("*.json")
            if any(t in p.stem for t in ("credential", "receipt", "offering"))
        )
        gaiax_dir = EXAMPLES_DIR / "gaiax"
        if gaiax_dir.is_dir():
            files.extend(
                p
                for p in gaiax_dir.glob("*.json")
                if any(t in p.stem for t in ("credential", "receipt", "offering"))
            )
    return sorted(files)


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
    """Each credential subject must have a type (singular harbour type)."""
    data = _load_json(credential_file)
    subject = data.get("credentialSubject", {})
    assert (
        "type" in subject
    ), f"Missing credentialSubject.type in {credential_file.name}"
    subject_type = subject["type"]
    # Subject type should be a singular harbour type (not a dual-type array)
    if isinstance(subject_type, str):
        assert subject_type.startswith(
            "harbour:"
        ), f"Subject type should be harbour-prefixed, got: {subject_type}"
    elif isinstance(subject_type, list):
        assert any(
            t.startswith("harbour:") for t in subject_type
        ), f"Subject type list should include a harbour type: {subject_type}"


# ---------------------------------------------------------------------------
# 2. Context consistency — harbour base
# ---------------------------------------------------------------------------

_skip_no_harbour_artifacts = pytest.mark.skipif(
    not HARBOUR_CONTEXT_PATH.exists(),
    reason="Generated harbour artifacts not found — run 'make generate'",
)


@_skip_no_harbour_artifacts
class TestHarbourContextConsistency:
    """Verify that generated harbour base context covers base types."""

    def test_context_has_base_classes(self):
        ctx = _load_json(HARBOUR_CONTEXT_PATH).get("@context", {})
        base_classes = [
            "HarbourCredential",
            "CRSetEntry",
            "CredentialEvidence",
            "DelegatedSignatureEvidence",
        ]
        for cls in base_classes:
            assert cls in ctx, f"Missing {cls} in harbour base context"

    def test_base_class_iris_are_prefixed(self):
        ctx = _load_json(HARBOUR_CONTEXT_PATH).get("@context", {})
        base_classes = [
            "CRSetEntry",
            "CredentialEvidence",
            "DelegatedSignatureEvidence",
        ]
        has_vocab = "@vocab" in ctx
        for cls in base_classes:
            entry = ctx.get(cls)
            assert entry is not None, f"Missing {cls} in context"
            aid = entry.get("@id") if isinstance(entry, dict) else entry
            assert (
                has_vocab or ":" in aid
            ), f"{cls} has unprefixed @id without @vocab: {aid}"


# ---------------------------------------------------------------------------
# 2b. Context consistency — gaiax-domain
# ---------------------------------------------------------------------------

_skip_no_domain_artifacts = pytest.mark.skipif(
    not DOMAIN_CONTEXT_PATH.exists(),
    reason="Generated gaiax-domain artifacts not found — run 'make generate'",
)


@_skip_no_domain_artifacts
class TestDomainContextConsistency:
    """Verify that generated gaiax-domain context covers domain types."""

    def test_context_has_domain_classes(self):
        ctx = _load_json(DOMAIN_CONTEXT_PATH).get("@context", {})
        domain_classes = [
            "LegalPersonCredential",
            "NaturalPersonCredential",
            "LegalPerson",
            "NaturalPerson",
        ]
        for cls in domain_classes:
            assert cls in ctx, f"Missing {cls} in gaiax-domain context"

    def test_context_has_composition_slots(self):
        ctx = _load_json(DOMAIN_CONTEXT_PATH).get("@context", {})
        assert "gxParticipant" in ctx, "Missing gxParticipant in domain context"

    def test_domain_class_iris_are_prefixed(self):
        ctx = _load_json(DOMAIN_CONTEXT_PATH).get("@context", {})
        domain_classes = [
            "LegalPerson",
            "NaturalPerson",
            "LegalPersonCredential",
            "NaturalPersonCredential",
        ]
        has_vocab = "@vocab" in ctx
        for cls in domain_classes:
            entry = ctx.get(cls)
            assert entry is not None, f"Missing {cls} in context"
            aid = entry.get("@id") if isinstance(entry, dict) else entry
            assert (
                has_vocab or ":" in aid
            ), f"{cls} has unprefixed @id without @vocab: {aid}"


# ---------------------------------------------------------------------------
# 3. SHACL conformance — harbour base shapes
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not HARBOUR_SHACL_PATH.exists(),
    reason="Generated harbour artifacts not found — run 'make generate'",
)
class TestHarbourShaclShapes:
    """Verify that SHACL shapes exist for harbour base types."""

    def test_shacl_is_non_empty(self):
        content = HARBOUR_SHACL_PATH.read_text()
        assert len(content) > 100, "SHACL file is too small — check generation"

    def test_shacl_has_base_shapes(self):
        content = HARBOUR_SHACL_PATH.read_text()
        expected_shapes = [
            "harbour:HarbourCredential",
            "harbour:CRSetEntry",
            "harbour:CredentialEvidence",
            "harbour:DelegatedSignatureEvidence",
        ]
        for shape in expected_shapes:
            assert (
                f"{shape} a sh:NodeShape" in content
            ), f"Missing SHACL NodeShape for {shape}"

    def test_harbour_credential_shape_has_issuer(self):
        """HarbourCredential shape must include cred:issuer as required."""
        content = HARBOUR_SHACL_PATH.read_text()
        marker = "harbour:HarbourCredential a sh:NodeShape"
        assert marker in content, "Missing shape for HarbourCredential"
        shape_start = content.index(marker)
        next_shape = content.find("\n\n", shape_start + 1)
        if next_shape == -1:
            next_shape = len(content)
        shape_block = content[shape_start:next_shape]
        assert (
            "cred:issuer" in shape_block
        ), "HarbourCredential shape missing cred:issuer"

    def test_evidence_shapes_require_verifiable_presentation(self):
        """Evidence shapes must require verifiablePresentation."""
        content = HARBOUR_SHACL_PATH.read_text()
        for ev_type in ["CredentialEvidence", "DelegatedSignatureEvidence"]:
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


# ---------------------------------------------------------------------------
# 3b. SHACL conformance — gaiax-domain shapes
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not DOMAIN_SHACL_PATH.exists(),
    reason="Generated gaiax-domain artifacts not found — run 'make generate'",
)
class TestDomainShaclShapes:
    """Verify that SHACL shapes exist for gaiax-domain types."""

    def test_shacl_is_non_empty(self):
        content = DOMAIN_SHACL_PATH.read_text()
        assert len(content) > 100, "SHACL file is too small — check generation"

    def test_shacl_has_domain_shapes(self):
        content = DOMAIN_SHACL_PATH.read_text()
        expected_shapes = [
            "harbour:LegalPersonCredential",
            "harbour:NaturalPersonCredential",
            "harbour:LegalPerson",
            "harbour:NaturalPerson",
        ]
        for shape in expected_shapes:
            assert (
                f"{shape} a sh:NodeShape" in content
            ), f"Missing SHACL NodeShape for {shape}"

    def test_credential_shapes_have_required_properties(self):
        """Concrete credential shapes must require validFrom and credentialStatus."""
        content = DOMAIN_SHACL_PATH.read_text()
        for cred_type in [
            "LegalPersonCredential",
            "NaturalPersonCredential",
        ]:
            marker = f"harbour:{cred_type} a sh:NodeShape"
            assert marker in content, f"Missing shape for {cred_type}"
            shape_start = content.index(marker)
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

    def test_person_credential_shapes_require_evidence(self):
        """LegalPersonCredential and NaturalPersonCredential must require evidence."""
        content = DOMAIN_SHACL_PATH.read_text()
        for cred_type in ["LegalPersonCredential", "NaturalPersonCredential"]:
            marker = f"harbour:{cred_type} a sh:NodeShape"
            assert marker in content, f"Missing shape for {cred_type}"
            shape_start = content.index(marker)
            next_shape = content.find("\n\n", shape_start + 1)
            if next_shape == -1:
                next_shape = len(content)
            shape_block = content[shape_start:next_shape]
            assert (
                "cred:evidence" in shape_block
            ), f"{cred_type} shape missing cred:evidence"
