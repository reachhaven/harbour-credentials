"""Compute and verify ``digestSRI`` Subresource Integrity hashes for credentials.

A ``digestSRI`` binds a Gaia-X compliance credential to the verifiable
credentials it references (``harbour.gx:CompliantCredentialReference``), so a
verifier can confirm a referenced credential has not been modified. The value
follows the W3C Subresource Integrity [SRI] string form::

    <algorithm>-<digest>

Per the W3C Subresource Integrity [SRI] specification, ``<digest>`` is the
**standard base64** encoding (RFC 4648 §4 — the ``+`` / ``/`` alphabet with ``=``
padding, *not* base64url) of the binary hash, and the grammar is exactly
``hash-algorithm "-" base64-value`` (e.g. ``sha256-t2S5kF1q...=``). W3C VC Data
Model 2.0 (the ``sriString`` datatype, §B.3.1) and the Gaia-X Compliance Document
25.10 §10 both defer to [SRI] for this format.

  NOTE — encoding compliance: some third-party / earlier-example credentials in
  the wild used lowercase *hex* (e.g. ``sha256-29784869...``). Hex is **not**
  SRI-compliant; this module emits and verifies the standards-correct base64
  form. (The repo's lowercase-hex convention belongs to the *delegation
  challenge* mechanism — :mod:`harbour.delegation`,
  ``docs/specs/delegation-challenge-encoding.md`` — which is unrelated to SRI.)

W3C SRI hashes the raw bytes of the referenced resource. Harbour defines that
"resource" as the **RFC 8785 (JCS) canonical JSON** of the referenced credential,
produced by the ``rfc8785`` library (and, in TypeScript, the ``canonicalize``
library). Because RFC 8785 is deterministic, the two runtimes emit identical
bytes — so credential content such as ``"München"`` hashes the same everywhere,
regardless of how the source credential happens to be formatted.

[SRI]   W3C Subresource Integrity — https://www.w3.org/TR/SRI/ (§3.1, §3.2)
[VCDM2] W3C VC Data Model 2.0 — sriString datatype (§B.3.1), Integrity of
        Related Resources (§5.3) — https://www.w3.org/TR/vc-data-model-2.0/

CLI Usage:
    python -m harbour.digest_sri --help
    python -m harbour.digest_sri compute examples/gaiax/gx-legal-person.json
    python -m harbour.digest_sri verify examples/gaiax/gx-legal-person.json sha256-<base64>
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path
from typing import Any, Callable

import rfc8785

__all__ = [
    "DigestSRIError",
    "canonical_json",
    "compute_digest_sri",
    "parse_digest_sri",
    "verify_digest_sri",
]

# SRI hash algorithm tokens -> hashlib constructors.
# W3C Subresource Integrity permits sha256, sha384, and sha512.
_ALGORITHMS: dict[str, Callable[[bytes], Any]] = {
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}


class DigestSRIError(ValueError):
    """Raised when a digestSRI string is malformed or uses an unsupported algorithm."""


def _normalize_alg(algorithm: str) -> str:
    """Normalize an SRI algorithm token (``sha-256`` / ``SHA256`` -> ``sha256``)."""
    alg = algorithm.lower().replace("-", "")
    if alg not in _ALGORITHMS:
        raise DigestSRIError(
            f"unsupported hash algorithm {algorithm!r}; "
            f"expected one of {', '.join(sorted(_ALGORITHMS))}"
        )
    return alg


def canonical_json(credential: Any) -> str:
    """Return the RFC 8785 (JCS) canonical JSON serialization for hashing.

    Backed by the ``rfc8785`` library. RFC 8785 is a deterministic
    specification, so this is byte-identical to the TypeScript ``canonicalJson``
    helper (the ``canonicalize`` library) — credential content such as
    ``"München"`` therefore hashes the same in both runtimes.
    """
    return rfc8785.dumps(credential).decode("utf-8")


def compute_digest_sri(credential: Any, algorithm: str = "sha256") -> str:
    """Compute the ``digestSRI`` value for *credential*.

    Args:
        credential: A JSON-serializable credential (typically a ``dict``). If a
            ``str`` is passed it is parsed as JSON first, so an embedded
            credential string and its parsed object yield the same digest.
        algorithm: SRI hash algorithm token (``sha256`` | ``sha384`` | ``sha512``).

    Returns:
        The SRI string ``"<algorithm>-<base64-digest>"`` (standard base64 per
        W3C SRI / RFC 4648 §4, with ``=`` padding).
    """
    alg = _normalize_alg(algorithm)
    if isinstance(credential, str):
        credential = json.loads(credential)
    data = canonical_json(credential).encode("utf-8")
    digest = base64.b64encode(_ALGORITHMS[alg](data).digest()).decode("ascii")
    return f"{alg}-{digest}"


def parse_digest_sri(digest_sri: str) -> tuple[str, str]:
    """Split a digestSRI string into ``(algorithm, base64_digest)``.

    The standard base64 alphabet contains no ``-``, so the algorithm token is
    everything before the first ``-`` and the digest is the remainder.

    Raises:
        DigestSRIError: if the string is not ``<algorithm>-<digest>`` or the
            algorithm is unsupported.
    """
    if not isinstance(digest_sri, str) or "-" not in digest_sri:
        raise DigestSRIError(f"malformed digestSRI: {digest_sri!r}")
    algorithm, _, digest = digest_sri.partition("-")
    alg = _normalize_alg(algorithm)
    if not digest:
        raise DigestSRIError(f"malformed digestSRI (empty digest): {digest_sri!r}")
    return alg, digest


def verify_digest_sri(credential: Any, digest_sri: str) -> bool:
    """Return ``True`` iff *credential* matches the integrity hash *digest_sri*.

    The digest is recomputed from *credential* using the algorithm named in
    *digest_sri* and compared in constant time.

    Raises:
        DigestSRIError: if *digest_sri* is malformed or uses an unsupported
            algorithm.
    """
    alg, expected = parse_digest_sri(digest_sri)
    _, actual = parse_digest_sri(compute_digest_sri(credential, alg))
    # base64 is case-sensitive (RFC 4648 §4); compare verbatim in constant time.
    return hmac.compare_digest(actual, expected)


def main() -> None:
    """CLI entry point for computing and verifying digestSRI values."""
    parser = argparse.ArgumentParser(
        prog="harbour.digest_sri",
        description=(
            "Compute and verify W3C Subresource Integrity digestSRI hashes for "
            "Verifiable Credentials (SRI 'sha256-<base64>' form, RFC 4648 §4)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m harbour.digest_sri compute examples/gaiax/gx-legal-person.json
  python -m harbour.digest_sri verify  examples/gaiax/gx-legal-person.json sha256-<base64>
        """,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_compute = sub.add_parser(
        "compute", help="Compute the digestSRI for a credential JSON file"
    )
    p_compute.add_argument(
        "credential", type=Path, help="Path to a credential JSON file"
    )
    p_compute.add_argument(
        "--algorithm",
        "-a",
        default="sha256",
        choices=sorted(_ALGORITHMS),
        help="Hash algorithm (default: sha256)",
    )

    p_verify = sub.add_parser(
        "verify", help="Verify a credential JSON file against a digestSRI"
    )
    p_verify.add_argument(
        "credential", type=Path, help="Path to a credential JSON file"
    )
    p_verify.add_argument(
        "digest_sri", help='Expected digestSRI, e.g. "sha256-<base64>"'
    )

    args = parser.parse_args()
    credential = json.loads(args.credential.read_text(encoding="utf-8"))

    if args.command == "compute":
        print(compute_digest_sri(credential, args.algorithm))
        return

    # verify
    if verify_digest_sri(credential, args.digest_sri):
        print(f"OK: digestSRI matches ({args.digest_sri})")
        return
    alg, _ = parse_digest_sri(args.digest_sri)
    print(
        "FAIL: digestSRI mismatch\n"
        f"  expected: {args.digest_sri}\n"
        f"  actual:   {compute_digest_sri(credential, alg)}",
        file=sys.stderr,
    )
    sys.exit(1)


if __name__ == "__main__":
    main()
