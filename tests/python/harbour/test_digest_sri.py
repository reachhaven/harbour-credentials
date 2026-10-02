"""Tests for harbour.digest_sri (W3C SRI digestSRI compute + verify).

The known-answer ``LEGAL_PERSON_SRI`` is shared verbatim with the TypeScript
suite (``tests/typescript/harbour/digest-sri.test.ts``) to guarantee the two
runtimes canonicalize and hash byte-identically. The referenced VC contains
non-ASCII content ("München" / "Musterstraße"), which is exactly where the
``ensure_ascii=False`` canonicalization choice matters for parity. The value is
**standard base64** (RFC 4648 §4) per W3C Subresource Integrity — not hex.
"""

import base64
import json
from pathlib import Path

import pytest

from harbour.digest_sri import (
    DigestSRIError,
    canonical_json,
    compute_digest_sri,
    parse_digest_sri,
    verify_digest_sri,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
GAIAX = REPO_ROOT / "examples" / "gaiax"

# Cross-runtime known-answer vector (keep in sync with the TypeScript suite).
# Standard base64 (RFC 4648 §4) per W3C SRI — NOT lowercase hex.
LEGAL_PERSON_SRI = "sha256-96CWnj0WFnepzcQhvBmXHu0U1nq3W6/Os+0VUKfvByw="


def _load(name: str) -> dict:
    return json.loads((GAIAX / name).read_text(encoding="utf-8"))


class TestCanonicalJson:
    def test_keys_sorted_no_whitespace(self):
        assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'

    def test_nested_keys_sorted(self):
        assert canonical_json({"x": {"b": 1, "a": 2}}) == '{"x":{"a":2,"b":1}}'

    def test_non_ascii_kept_verbatim(self):
        # Must NOT escape to \\u00fc — parity with TS JSON.stringify.
        assert canonical_json({"city": "München"}) == '{"city":"München"}'


class TestComputeDigestSri:
    def test_known_answer_matches_typescript(self):
        assert compute_digest_sri(_load("gx-legal-person.json")) == LEGAL_PERSON_SRI

    def test_format_is_standard_base64_sha256(self):
        # W3C SRI: "<alg>-<standard base64 digest>". For SHA-256 (32 bytes) the
        # standard base64 is 44 chars including one '=' pad character.
        alg, digest = compute_digest_sri({"a": 1}).split("-", 1)
        assert alg == "sha256"
        assert len(digest) == 44
        assert len(base64.b64decode(digest)) == 32  # valid standard base64 -> 32 bytes

    def test_encoding_is_not_hex(self):
        # Guard against regressing to the non-SRI-compliant hex encoding.
        _, digest = compute_digest_sri({"a": 1}).split("-", 1)
        assert len(digest) != 64 or not all(c in "0123456789abcdef" for c in digest)

    def test_key_order_independent(self):
        assert compute_digest_sri({"a": 1, "b": 2}) == compute_digest_sri(
            {"b": 2, "a": 1}
        )

    def test_string_input_equivalent_to_object(self):
        obj = {"z": 1, "a": [1, 2, {"k": "v"}]}
        assert compute_digest_sri(obj) == compute_digest_sri(json.dumps(obj))

    def test_supported_algorithms(self):
        assert compute_digest_sri({"a": 1}, "sha384").startswith("sha384-")
        assert compute_digest_sri({"a": 1}, "sha512").startswith("sha512-")
        # Tokens with a dash are normalized.
        assert compute_digest_sri({"a": 1}, "sha-256").startswith("sha256-")

    def test_unsupported_algorithm_raises(self):
        with pytest.raises(DigestSRIError):
            compute_digest_sri({"a": 1}, "md5")


class TestParseDigestSri:
    def test_parse(self):
        alg, digest = parse_digest_sri("sha256-abcDEF123")
        assert alg == "sha256"
        assert digest == "abcDEF123"

    def test_missing_separator_raises(self):
        with pytest.raises(DigestSRIError):
            parse_digest_sri("sha256")

    def test_empty_digest_raises(self):
        with pytest.raises(DigestSRIError):
            parse_digest_sri("sha256-")


class TestVerifyDigestSri:
    def test_roundtrip_true(self):
        vc = _load("gx-legal-person.json")
        assert verify_digest_sri(vc, compute_digest_sri(vc)) is True

    def test_known_answer_true(self):
        assert (
            verify_digest_sri(_load("gx-legal-person.json"), LEGAL_PERSON_SRI) is True
        )

    def test_tampered_credential_false(self):
        vc = _load("gx-legal-person.json")
        sri = compute_digest_sri(vc)
        vc["issuer"] = "did:ethr:0x14a34:0xdeadbeef"
        assert verify_digest_sri(vc, sri) is False

    def test_malformed_digest_raises(self):
        with pytest.raises(DigestSRIError):
            verify_digest_sri({"a": 1}, "sha256")


class TestExamplesConsistency:
    """The committed examples must stay verifiable against the input VCs.

    This fails if an input VC is edited without re-running
    ``python -m credentials.digest_sri_examples --write``.
    """

    def test_all_example_digests_verify(self):
        from credentials.digest_sri_examples import (
            check_file,
            collect_target_files,
            load_input_vcs,
            load_self_signed_sources,
        )

        inputs = load_input_vcs(GAIAX)
        self_signed = load_self_signed_sources(GAIAX)
        all_errors: list[str] = []
        for path in collect_target_files(GAIAX):
            errors, _ = check_file(path, inputs, self_signed)
            all_errors.extend(errors)
        assert all_errors == [], "\n".join(all_errors)


_TRUST_ANCHOR = "did:ethr:0x14a34:0x4d6246a7d1e60caa44b75e3af9b37ac8d6442774"
_TA_TERMS_VC = "urn:uuid:1d10aed1-3f1b-4d8d-8d37-0453149a8d62#cs"


def _copy_gaiax(tmp_path: Path) -> Path:
    import shutil

    target = tmp_path / "gaiax"
    shutil.copytree(GAIAX, target, ignore=shutil.ignore_patterns("signed"))
    return target


def _edit_subjects(path: Path, match, edit) -> int:
    """Apply *edit* to every credentialSubject in *path* that *match* accepts."""
    obj = json.loads(path.read_text(encoding="utf-8"))
    hits = 0

    def walk(node):
        nonlocal hits
        if isinstance(node, dict):
            cs = node.get("credentialSubject")
            if isinstance(cs, dict) and match(cs):
                edit(cs)
                hits += 1
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(obj)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", "utf-8")
    return hits


def _retype_trust_anchor_terms_vc(gaiax: Path) -> None:
    """Typo the trust anchor's bundled gx:Issuer VC type in every copy."""
    hits = sum(
        _edit_subjects(
            path,
            lambda cs: cs.get("id") == _TA_TERMS_VC,
            lambda cs: cs.update(type="gx:Isser"),
        )
        for path in gaiax.glob("*.json")
    )
    assert hits == 5  # the trust anchor file + four embedded copies


class TestSelfSignedSources:
    """The trust anchor's bundle has one canonical source and no fallback."""

    def test_canonical_copy_is_the_trust_anchor_file(self, tmp_path):
        from credentials.digest_sri_examples import load_self_signed_sources

        gaiax = _copy_gaiax(tmp_path)
        # Edit only the canonical file: every embedded copy is now stale.
        assert _edit_subjects(
            gaiax / "trust-anchor-credential.json",
            lambda cs: cs.get("gx:vatID") == "DE298765432",
            lambda cs: cs.update({"gx:vatID": "DE000000000"}),
        )
        with pytest.raises(ValueError, match="differs from trust-anchor-credential"):
            load_self_signed_sources(gaiax)

    def test_drifted_embedded_copy_is_detected(self, tmp_path):
        from credentials.digest_sri_examples import load_self_signed_sources

        gaiax = _copy_gaiax(tmp_path)
        assert _edit_subjects(
            gaiax / "legal-person-credential.json",
            lambda cs: cs.get("gx:vatID") == "DE298765432",
            lambda cs: cs.update({"gx:vatID": "DE000000000"}),
        )
        with pytest.raises(ValueError, match="embedded in legal-person-credential"):
            load_self_signed_sources(gaiax)

    def test_missing_bundled_type_does_not_fall_back(self, tmp_path):
        from credentials.digest_sri_examples import (
            check_file,
            load_input_vcs,
            load_self_signed_sources,
            render_filled,
        )

        gaiax = _copy_gaiax(tmp_path)
        _retype_trust_anchor_terms_vc(gaiax)
        inputs = load_input_vcs(gaiax)
        self_signed = load_self_signed_sources(gaiax)
        assert "gx:Issuer" not in self_signed[_TRUST_ANCHOR]

        errors, _ = check_file(
            gaiax / "trust-anchor-credential.json", inputs, self_signed
        )
        assert any("bundles no 'gx:Issuer'" in e for e in errors), errors
        with pytest.raises(ValueError, match="bundles no 'gx:Issuer'"):
            render_filled(gaiax / "trust-anchor-credential.json", inputs, self_signed)

    def test_write_aborts_without_touching_files(self, tmp_path, monkeypatch):
        import sys

        from credentials import digest_sri_examples

        gaiax = _copy_gaiax(tmp_path)
        _retype_trust_anchor_terms_vc(gaiax)
        before = {p.name: p.read_bytes() for p in gaiax.glob("*.json")}

        monkeypatch.setattr(
            sys, "argv", ["digest_sri_examples", "--write", "--gaiax-dir", str(gaiax)]
        )
        with pytest.raises(SystemExit) as exc:
            digest_sri_examples.main()
        assert exc.value.code == 1
        assert {p.name: p.read_bytes() for p in gaiax.glob("*.json")} == before
