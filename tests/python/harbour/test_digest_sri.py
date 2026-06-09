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
LEGAL_PERSON_SRI = "sha256-dl7zg1RuG2HhA97FckTfjuXIUxhc0Cagbp2MD4B6JTw="


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
        )

        inputs = load_input_vcs(GAIAX)
        all_errors: list[str] = []
        for path in collect_target_files(GAIAX):
            errors, _ = check_file(path, inputs)
            all_errors.extend(errors)
        assert all_errors == [], "\n".join(all_errors)
