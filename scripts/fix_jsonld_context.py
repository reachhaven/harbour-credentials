"""Post-process generated JSON-LD context to fix unprefixed harbour IRIs.

LinkML's gen-jsonld-context emits bare local names for classes/slots whose
IRI matches the default_prefix namespace when @vocab is set.  This script
replaces those bare @id values with explicit harbour:-prefixed IRIs and
removes the @vocab key so every term is self-contained.

Usage:
    python scripts/fix_jsonld_context.py artifacts/harbour/harbour.context.jsonld
"""

import json
import sys
from pathlib import Path

HARBOUR_PREFIX = "harbour:"
HARBOUR_NS = "https://w3id.org/reachhaven/harbour/credentials/v1/"

# Known prefixes whose terms should NOT be rewritten
EXTERNAL_PREFIXES = {
    "linkml:",
    "schema:",
    "cred:",
    "cs:",
    "gx:",
    "did:",
    "rdf:",
    "xsd:",
    "core:",
}

# Special JSON-LD keywords that should never be rewritten
JSONLD_KEYWORDS = {"@id", "@type", "@vocab", "@context", "@value", "@language"}


def _is_bare_local_name(value: str) -> bool:
    """Return True if the value looks like an unprefixed local name."""
    if not isinstance(value, str):
        return False
    if value.startswith(("http://", "https://")):
        return False
    if value.startswith("@"):
        return False
    if any(value.startswith(p) for p in EXTERNAL_PREFIXES):
        return False
    if ":" in value:
        return False
    return True


def fix_context(ctx: dict) -> dict:
    """Fix @id values that are bare local names by adding harbour: prefix."""
    for key, value in list(ctx.items()):
        if key.startswith("@"):
            continue

        if isinstance(value, dict):
            aid = value.get("@id")
            if aid and _is_bare_local_name(aid):
                value["@id"] = f"{HARBOUR_PREFIX}{aid}"
        elif isinstance(value, str) and _is_bare_local_name(value):
            ctx[key] = f"{HARBOUR_PREFIX}{value}"

    # Restore standard JSON-LD keyword aliases (LinkML maps these to rdf: URIs)
    ctx["id"] = "@id"
    ctx["type"] = "@type"

    # Remove @vocab — all terms are now explicitly mapped
    ctx.pop("@vocab", None)

    return ctx


def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <context.jsonld>", file=sys.stderr)
        sys.exit(1)

    path = Path(sys.argv[1])
    doc = json.loads(path.read_text())
    ctx = doc.get("@context", {})
    doc["@context"] = fix_context(ctx)
    path.write_text(json.dumps(doc, indent=3, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
