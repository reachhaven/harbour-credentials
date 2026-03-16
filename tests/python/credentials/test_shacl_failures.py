"""SHACL validation failure tests — verify shapes catch invalid credentials.

This test suite programmatically mutates valid credential examples and
asserts that SHACL validation catches each specific error. Every test
starts from a known-good credential, applies a single mutation, and
checks that pyshacl reports the expected violation.

The test output is designed for debuggability:
- Each test ID clearly describes the mutation (e.g., "LegalPerson-missing-issuer")
- Assertion messages show the full SHACL results text on unexpected outcomes
- The ``ShaclViolation`` helper formats violations in a human-readable way

Run with::

    pytest tests/python/credentials/test_shacl_failures.py -v

To debug a single test::

    pytest tests/python/credentials/test_shacl_failures.py -v -k "missing_issuer"

Requires generated artifacts (``make generate``) and pyshacl.
"""

import copy
import json
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pytest
import rdflib
from rdflib import RDF, Namespace

# ---------------------------------------------------------------------------
# Repository paths
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent
while _REPO_ROOT.name != "harbour-credentials" and _REPO_ROOT != _REPO_ROOT.parent:
    _REPO_ROOT = _REPO_ROOT.parent

_OMB = _REPO_ROOT / "submodules" / "ontology-management-base"

_CORE_SHACL = (
    _REPO_ROOT / "artifacts/harbour-core-credential/harbour-core-credential.shacl.ttl"
)
_GX_SHACL = (
    _REPO_ROOT / "artifacts/harbour-gx-credential/harbour-gx-credential.shacl.ttl"
)
_EXAMPLES = _REPO_ROOT / "examples"

# SHACL namespace for result graph queries
SH = Namespace("http://www.w3.org/ns/shacl#")
CRED = Namespace("https://www.w3.org/2018/credentials#")
HARBOUR = Namespace("https://w3id.org/reachhaven/harbour/core/v1/")
HARBOUR_GX = Namespace("https://w3id.org/reachhaven/harbour/gx/v1/")

# ---------------------------------------------------------------------------
# Skip if artifacts haven't been generated
# ---------------------------------------------------------------------------

_skip_no_artifacts = pytest.mark.skipif(
    not _GX_SHACL.exists(),
    reason="Generated artifacts not found — run 'make generate' first",
)

_skip_no_omb = pytest.mark.skipif(
    not (_OMB / "src" / "tools" / "utils" / "context_resolver.py").exists(),
    reason="ontology-management-base submodule not initialised",
)


# ---------------------------------------------------------------------------
# Structured violation helper
# ---------------------------------------------------------------------------


@dataclass
class ShaclViolation:
    """Human-readable representation of a single SHACL validation result."""

    focus_node: str
    result_path: Optional[str]
    constraint: str
    severity: str
    message: str

    def __str__(self) -> str:
        path_str = f" path={self.result_path}" if self.result_path else ""
        return (
            f"[{self.severity}]{path_str} constraint={self.constraint} — {self.message}"
        )


def _extract_violations(results_graph: rdflib.Graph) -> list[ShaclViolation]:
    """Extract structured violations from a pyshacl results graph."""
    violations = []
    for result in results_graph.subjects(RDF.type, SH.ValidationResult):
        paths = list(results_graph.objects(result, SH.resultPath))
        severities = list(results_graph.objects(result, SH.resultSeverity))
        components = list(results_graph.objects(result, SH.sourceConstraintComponent))
        messages = list(results_graph.objects(result, SH.resultMessage))
        focus_nodes = list(results_graph.objects(result, SH.focusNode))

        violations.append(
            ShaclViolation(
                focus_node=str(focus_nodes[0]) if focus_nodes else "?",
                result_path=str(paths[0]) if paths else None,
                constraint=str(components[0]).split("#")[-1] if components else "?",
                severity=str(severities[0]).split("#")[-1] if severities else "?",
                message=str(messages[0]) if messages else "(no message)",
            )
        )
    return violations


def _format_violations(violations: list[ShaclViolation]) -> str:
    """Format violations for assertion messages."""
    if not violations:
        return "(no violations)"
    return "\n".join(f"  • {v}" for v in violations)


# ---------------------------------------------------------------------------
# JSON-LD → RDF parsing with local context resolution
# ---------------------------------------------------------------------------


def _build_context_url_map() -> dict[str, Path]:
    """Build URL → local file mapping for offline JSON-LD parsing."""
    sys.path.insert(0, str(_OMB))
    from src.tools.utils.context_resolver import discover_context_files

    artifact_dirs = [
        _REPO_ROOT / "artifacts/harbour-core-credential",
        _REPO_ROOT / "artifacts/harbour-gx-credential",
        _REPO_ROOT / "artifacts/harbour-core-delegation",
        _OMB / "artifacts/gx",
    ]
    url_map = discover_context_files(artifact_dirs)

    # Add OMB import contexts (W3C credentials/v2, status, did, schema.org)
    catalog_path = _OMB / "imports" / "catalog-v001.xml"
    if catalog_path.exists():
        tree = ET.parse(catalog_path)
        cat_ns = {"c": "urn:oasis:names:tc:entity:xmlns:xml:catalog"}
        for uri_elem in tree.getroot().findall(".//c:uri", cat_ns):
            name = uri_elem.get("name", "")
            val = uri_elem.get("uri", "")
            if val.endswith(".context.jsonld"):
                abs_path = (_OMB / "imports" / val).resolve()
                if abs_path.exists():
                    url_map[name] = abs_path

    return url_map


# ---------------------------------------------------------------------------
# Session-scoped fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def context_url_map():
    """URL → local file map for offline JSON-LD context resolution."""
    return _build_context_url_map()


@pytest.fixture(scope="session")
def shacl_graph():
    """Combined SHACL shapes graph (core + gx)."""
    g = rdflib.Graph()
    g.parse(str(_GX_SHACL), format="turtle")
    return g


# ---------------------------------------------------------------------------
# Validation helper
# ---------------------------------------------------------------------------


def _validate(
    credential: dict,
    url_map: dict[str, Path],
    shapes: rdflib.Graph,
) -> tuple[bool, list[ShaclViolation], str]:
    """Validate a credential dict against SHACL shapes.

    Returns:
        (conforms, violations, results_text)

    The results_text is the full pyshacl report — useful for debugging
    when a test fails unexpectedly.
    """
    sys.path.insert(0, str(_OMB))
    import pyshacl
    from src.tools.utils.context_resolver import inline_jsonld_with_local_contexts

    inlined_json = inline_jsonld_with_local_contexts(credential, url_map)
    dg = rdflib.Graph()
    dg.parse(data=inlined_json, format="json-ld")

    conforms, results_graph, results_text = pyshacl.validate(
        data_graph=dg,
        shacl_graph=shapes,
        inference="none",
    )
    violations = _extract_violations(results_graph)
    return conforms, violations, results_text


# ---------------------------------------------------------------------------
# Credential mutation helpers
# ---------------------------------------------------------------------------


def _load_example(name: str) -> dict:
    """Load an example credential by filename."""
    for subdir in ["gaiax", ""]:
        path = _EXAMPLES / subdir / name if subdir else _EXAMPLES / name
        if path.exists():
            return json.loads(path.read_text())
    raise FileNotFoundError(f"Example not found: {name}")


def _remove_field(data: dict, *keys: str) -> dict:
    """Return a copy with a nested field removed.

    Example: _remove_field(data, "credentialSubject", "type")
    removes data["credentialSubject"]["type"].
    """
    data = copy.deepcopy(data)
    target = data
    for key in keys[:-1]:
        target = target[key]
    del target[keys[-1]]
    return data


def _set_field(data: dict, value, *keys: str) -> dict:
    """Return a copy with a nested field set to a new value."""
    data = copy.deepcopy(data)
    target = data
    for key in keys[:-1]:
        target = target[key]
    target[keys[-1]] = value
    return data


def _add_field(data: dict, key: str, value) -> dict:
    """Return a copy with an extra top-level field added."""
    data = copy.deepcopy(data)
    data[key] = value
    return data


# ═══════════════════════════════════════════════════════════════════════════
# Test classes
# ═══════════════════════════════════════════════════════════════════════════


@_skip_no_artifacts
@_skip_no_omb
class TestPositiveBaseline:
    """Sanity check — valid examples must pass SHACL validation.

    If these fail, the shapes or examples are broken, not the test suite.
    """

    @pytest.mark.parametrize(
        "example_file",
        [
            "legal-person-credential.json",
            "natural-person-credential.json",
            "trust-anchor-credential.json",
        ],
        ids=[
            "LegalPersonCredential-valid",
            "NaturalPersonCredential-valid",
            "TrustAnchorCredential-valid",
        ],
    )
    def test_valid_credential_conforms(
        self, example_file, context_url_map, shacl_graph
    ):
        """A valid credential must pass SHACL validation with zero violations."""
        cred = _load_example(example_file)
        conforms, violations, text = _validate(cred, context_url_map, shacl_graph)
        assert conforms, (
            f"Valid {example_file} should conform but got {len(violations)} "
            f"violation(s):\n{_format_violations(violations)}\n\n"
            f"Full SHACL report:\n{text}"
        )


# ---------------------------------------------------------------------------
# C1: Missing mandatory fields  (sh:MinCountConstraintComponent)
# ---------------------------------------------------------------------------

# Each tuple: (example_file, field_path, expected_shacl_path, test_id)
# field_path is the key chain to remove, e.g. ("issuer",) or ("credentialSubject", "givenName")
_MISSING_FIELD_CASES = [
    # --- LegalPersonCredential envelope ---
    (
        "legal-person-credential.json",
        ("issuer",),
        str(CRED.issuer),
        "LegalPersonCredential-missing-issuer",
    ),
    (
        "legal-person-credential.json",
        ("validFrom",),
        str(CRED.validFrom),
        "LegalPersonCredential-missing-validFrom",
    ),
    (
        "legal-person-credential.json",
        ("credentialStatus",),
        str(CRED.credentialStatus),
        "LegalPersonCredential-missing-credentialStatus",
    ),
    (
        "legal-person-credential.json",
        ("evidence",),
        str(CRED.evidence),
        "LegalPersonCredential-missing-evidence",
    ),
    # --- LegalPerson subject (compliance slots) ---
    # Note: JSON keys use "harbour.gx:" prefix (compact IRI from JSON-LD context)
    (
        "legal-person-credential.json",
        ("credentialSubject", "harbour.gx:compliantLegalPersonVC"),
        str(HARBOUR_GX.compliantLegalPersonVC),
        "LegalPerson-missing-compliantLegalPersonVC",
    ),
    (
        "legal-person-credential.json",
        ("credentialSubject", "harbour.gx:compliantRegistrationVC"),
        str(HARBOUR_GX.compliantRegistrationVC),
        "LegalPerson-missing-compliantRegistrationVC",
    ),
    (
        "legal-person-credential.json",
        ("credentialSubject", "harbour.gx:compliantTermsVC"),
        str(HARBOUR_GX.compliantTermsVC),
        "LegalPerson-missing-compliantTermsVC",
    ),
    (
        "legal-person-credential.json",
        ("credentialSubject", "harbour.gx:labelLevel"),
        str(HARBOUR_GX.labelLevel),
        "LegalPerson-missing-labelLevel",
    ),
    (
        "legal-person-credential.json",
        ("credentialSubject", "harbour.gx:engineVersion"),
        str(HARBOUR_GX.engineVersion),
        "LegalPerson-missing-engineVersion",
    ),
    (
        "legal-person-credential.json",
        ("credentialSubject", "harbour.gx:rulesVersion"),
        str(HARBOUR_GX.rulesVersion),
        "LegalPerson-missing-rulesVersion",
    ),
    # --- NaturalPersonCredential envelope ---
    (
        "natural-person-credential.json",
        ("issuer",),
        str(CRED.issuer),
        "NaturalPersonCredential-missing-issuer",
    ),
    (
        "natural-person-credential.json",
        ("validFrom",),
        str(CRED.validFrom),
        "NaturalPersonCredential-missing-validFrom",
    ),
    (
        "natural-person-credential.json",
        ("credentialStatus",),
        str(CRED.credentialStatus),
        "NaturalPersonCredential-missing-credentialStatus",
    ),
    (
        "natural-person-credential.json",
        ("evidence",),
        str(CRED.evidence),
        "NaturalPersonCredential-missing-evidence",
    ),
    # Note: NaturalPerson subject has NO minCount constraints on givenName/familyName
    # (they are optional per SHACL). The shape IS sh:closed, so wrong property names
    # are caught by ClosedConstraintComponent tests instead.
]


@_skip_no_artifacts
@_skip_no_omb
class TestMissingMandatoryFields:
    """Removing a required field must trigger a sh:MinCountConstraintComponent violation.

    Each test removes exactly one mandatory field from a valid credential
    and asserts that SHACL reports a violation on the correct property path.

    To debug a failure, look at:
    1. The test ID — tells you which credential and which field
    2. The assertion message — shows the full SHACL report
    3. The ``expected_path`` — the IRI of the property that should be flagged
    """

    @pytest.mark.parametrize(
        "example_file, field_path, expected_path, test_id",
        _MISSING_FIELD_CASES,
        ids=[c[3] for c in _MISSING_FIELD_CASES],
    )
    def test_missing_field_detected(
        self,
        example_file,
        field_path,
        expected_path,
        test_id,
        context_url_map,
        shacl_graph,
    ):
        cred = _load_example(example_file)
        mutated = _remove_field(cred, *field_path)

        conforms, violations, text = _validate(mutated, context_url_map, shacl_graph)

        # Must not conform
        assert not conforms, (
            f"[{test_id}] Credential should FAIL without "
            f"'{'.'.join(field_path)}' but SHACL said it conforms.\n"
            f"This means the shape does not enforce this field as mandatory."
        )

        # Must have a MinCount violation on the expected path
        min_count_on_path = [
            v
            for v in violations
            if v.constraint == "MinCountConstraintComponent"
            and v.result_path == expected_path
        ]
        assert min_count_on_path, (
            f"[{test_id}] Expected MinCountConstraintComponent on "
            f"path <{expected_path}> but got:\n"
            f"{_format_violations(violations)}\n\n"
            f"Full SHACL report:\n{text}"
        )


# ---------------------------------------------------------------------------
# C2: Wrong type violations  (sh:ClassConstraintComponent / sh:DatatypeConstraintComponent)
# ---------------------------------------------------------------------------

# Each tuple: (example_file, mutation_fn, expected_constraint, test_id)
_WRONG_TYPE_CASES = [
    # evidence should be an array of objects — a string gets parsed but fails sh:class
    (
        "legal-person-credential.json",
        lambda d: _set_field(d, "not-an-object", "evidence"),
        "ClassConstraintComponent",
        "LegalPersonCredential-evidence-wrong-type",
    ),
    # validFrom must be xsd:dateTime, not an object
    (
        "legal-person-credential.json",
        lambda d: _set_field(d, {"broken": True}, "validFrom"),
        "DatatypeConstraintComponent",
        "LegalPersonCredential-validFrom-wrong-type",
    ),
    # credentialStatus must be CRSetEntry objects — a string fails sh:class
    (
        "legal-person-credential.json",
        lambda d: _set_field(d, "revoked", "credentialStatus"),
        "ClassConstraintComponent",
        "LegalPersonCredential-credentialStatus-wrong-type",
    ),
    # compliantLegalPersonVC must be a CompliantCredentialReference, not a string
    (
        "legal-person-credential.json",
        lambda d: _set_field(
            d, "just-a-string", "credentialSubject", "harbour.gx:compliantLegalPersonVC"
        ),
        "ClassConstraintComponent",
        "LegalPerson-compliantLegalPersonVC-wrong-type",
    ),
    # labelLevel must be a string, not an array (sh:maxCount 1)
    (
        "legal-person-credential.json",
        lambda d: _set_field(
            d, ["SC", "L1"], "credentialSubject", "harbour.gx:labelLevel"
        ),
        "MaxCountConstraintComponent",
        "LegalPerson-labelLevel-wrong-type",
    ),
]


@_skip_no_artifacts
@_skip_no_omb
class TestWrongTypes:
    """Setting a field to the wrong type must trigger a type-related violation.

    Each test replaces a field value with an incompatible type and asserts
    that SHACL catches the mismatch. The expected constraint component
    varies — e.g., putting a string where an object is expected may trigger
    MinCount (the string doesn't create a valid node) or Class violations.

    Debugging: check the constraint in the assertion message to understand
    which SHACL rule caught the error.
    """

    @pytest.mark.parametrize(
        "example_file, mutate_fn, expected_constraint, test_id",
        _WRONG_TYPE_CASES,
        ids=[c[3] for c in _WRONG_TYPE_CASES],
    )
    def test_wrong_type_detected(
        self,
        example_file,
        mutate_fn,
        expected_constraint,
        test_id,
        context_url_map,
        shacl_graph,
    ):
        cred = _load_example(example_file)
        mutated = mutate_fn(cred)

        conforms, violations, text = _validate(mutated, context_url_map, shacl_graph)

        assert not conforms, (
            f"[{test_id}] Credential with wrong type should FAIL "
            f"but SHACL said it conforms."
        )

        matching = [v for v in violations if v.constraint == expected_constraint]
        assert matching, (
            f"[{test_id}] Expected {expected_constraint} violation but got:\n"
            f"{_format_violations(violations)}\n\n"
            f"Full SHACL report:\n{text}"
        )


# ---------------------------------------------------------------------------
# C3: Closed shape violations  (sh:ClosedConstraintComponent)
# ---------------------------------------------------------------------------

_CLOSED_SHAPE_CASES = [
    (
        "legal-person-credential.json",
        "unknownField",
        "surprise!",
        "LegalPersonCredential-unexpected-property",
    ),
    (
        "natural-person-credential.json",
        "extraData",
        {"foo": "bar"},
        "NaturalPersonCredential-unexpected-property",
    ),
    # Extra field on the credential subject (closed LegalPerson shape)
    (
        "legal-person-credential.json",
        None,  # special handling — add to credentialSubject
        None,
        "LegalPerson-subject-unexpected-property",
    ),
]


@_skip_no_artifacts
@_skip_no_omb
class TestClosedShapeViolations:
    """Adding an unexpected property to a closed shape must be caught.

    Harbour credential shapes use ``sh:closed true`` — any property not
    declared in the shape is a violation. This protects against typos
    and schema drift.

    Debugging: if a test passes unexpectedly, the shape may not be closed
    (check ``sh:closed true`` in the SHACL TTL).
    """

    @pytest.mark.parametrize(
        "example_file, field_name, field_value, test_id",
        _CLOSED_SHAPE_CASES,
        ids=[c[3] for c in _CLOSED_SHAPE_CASES],
    )
    def test_unexpected_property_detected(
        self,
        example_file,
        field_name,
        field_value,
        test_id,
        context_url_map,
        shacl_graph,
    ):
        cred = _load_example(example_file)

        if field_name is None:
            # Add to credentialSubject instead of top level
            mutated = copy.deepcopy(cred)
            mutated["credentialSubject"]["harbour.gx:unexpectedField"] = "surprise"
        else:
            mutated = _add_field(cred, field_name, field_value)

        conforms, violations, text = _validate(mutated, context_url_map, shacl_graph)

        assert not conforms, (
            f"[{test_id}] Credential with unexpected property should FAIL "
            f"but SHACL said it conforms.\n"
            f"Check that the shape has sh:closed true."
        )

        closed_violations = [
            v for v in violations if v.constraint == "ClosedConstraintComponent"
        ]
        assert closed_violations, (
            f"[{test_id}] Expected ClosedConstraintComponent but got:\n"
            f"{_format_violations(violations)}\n\n"
            f"Full SHACL report:\n{text}"
        )


# ---------------------------------------------------------------------------
# C4: Cardinality violations  (sh:MaxCountConstraintComponent)
# ---------------------------------------------------------------------------


@_skip_no_artifacts
@_skip_no_omb
class TestCardinalityViolations:
    """Exceeding sh:maxCount on a property must be caught.

    Certain fields like ``issuer`` and ``validFrom`` are constrained to
    exactly one value (sh:minCount 1, sh:maxCount 1). Providing multiple
    values must trigger a MaxCountConstraintComponent.
    """

    def test_multiple_issuers(self, context_url_map, shacl_graph):
        """Two issuers should violate sh:maxCount 1."""
        cred = _load_example("legal-person-credential.json")
        # JSON-LD doesn't naturally support duplicate keys, but we can
        # test by making issuer an array (which expands to multiple values)
        mutated = _set_field(
            cred,
            ["did:ethr:0x14a34:0xaaaa", "did:ethr:0x14a34:0xbbbb"],
            "issuer",
        )
        conforms, violations, text = _validate(mutated, context_url_map, shacl_graph)
        assert not conforms, (
            "Two issuers should violate maxCount but SHACL said it conforms.\n"
            f"Full report:\n{text}"
        )

    def test_multiple_valid_from(self, context_url_map, shacl_graph):
        """Two validFrom dates should violate sh:maxCount 1."""
        cred = _load_example("natural-person-credential.json")
        mutated = _set_field(
            cred,
            ["2025-01-15T00:00:00Z", "2025-06-01T00:00:00Z"],
            "validFrom",
        )
        conforms, violations, text = _validate(mutated, context_url_map, shacl_graph)
        assert not conforms, (
            "Two validFrom values should violate maxCount but SHACL said it conforms.\n"
            f"Full report:\n{text}"
        )

    def test_multiple_label_levels(self, context_url_map, shacl_graph):
        """Two labelLevel values should violate sh:maxCount 1."""
        cred = _load_example("legal-person-credential.json")
        mutated = _set_field(
            cred,
            ["SC", "L1"],
            "credentialSubject",
            "harbour.gx:labelLevel",
        )
        conforms, violations, text = _validate(mutated, context_url_map, shacl_graph)
        assert not conforms, (
            "Two labelLevel values should violate maxCount "
            f"but SHACL said it conforms.\nFull report:\n{text}"
        )
