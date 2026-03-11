#!/usr/bin/env python3
"""Generate downstream artifacts (OWL ontology, SHACL shapes, JSON-LD context)
from Harbour LinkML schemas.

The custom HarbourShaclGenerator fixes the ``cred:issuer`` property shape:
LinkML maps ``range: string`` to ``sh:nodeKind sh:Literal``, but the W3C VC v2
context defines ``issuer`` with ``@type: @id``, so the RDF value is an IRI.
The generator patches the property shape to ``sh:nodeKind sh:IRIOrLiteral``
(accepting both IRIs from JSON-LD and literal strings from plain JSON).

The custom HarbourContextGenerator excludes terms imported from external
vocabularies (e.g. W3C VC v2) so the generated JSON-LD context does not
redefine ``@protected`` terms already provided by the W3C VC v2 context.
"""

import json
from pathlib import Path

from linkml.generators.jsonldcontextgen import ContextGenerator as _BaseContextGenerator
from linkml.generators.owlgen import OwlSchemaGenerator
from linkml.generators.shaclgen import ShaclGenerator as _BaseShaclGenerator
from linkml_runtime.linkml_model.meta import SlotDefinition
from rdflib import Namespace

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
LINKML_DIR = REPO_ROOT / "linkml"
ARTIFACTS_DIR = REPO_ROOT / "artifacts"

DOMAINS = ["harbour-core-credential", "harbour-gx-credential"]

SH = Namespace("http://www.w3.org/ns/shacl#")
XSD = Namespace("http://www.w3.org/2001/XMLSchema#")
CRED = Namespace("https://www.w3.org/2018/credentials#")
LINKML = Namespace("https://w3id.org/linkml/")


class HarbourShaclGenerator(_BaseShaclGenerator):
    """SHACL generator with importmap-aware initialisation and IRI fixes.

    Bypasses ``ShaclGenerator.__post_init__``'s ``SchemaView`` construction
    which ignores ``importmap`` / ``base_dir``, causing cross-directory
    imports to fail.
    See https://github.com/linkml/linkml/issues/2913

    Also corrects ``cred:issuer`` property shape (IRI, not Literal) and
    removes ``sh:class linkml:Any`` constraints.
    See https://github.com/linkml/linkml/issues/2914
    """

    uses_schemaloader = False

    def __post_init__(self) -> None:
        from linkml.utils.generator import Generator

        Generator.__post_init__(self)
        self.generate_header()

    def as_graph(self):
        g = super().as_graph()
        # Fix cred:issuer nodeKind (IRI, not Literal)
        for ps in g.subjects(SH.path, CRED.issuer):
            g.remove((ps, SH.nodeKind, SH.Literal))
            g.add((ps, SH.nodeKind, SH.IRIOrLiteral))
            for dt in list(g.objects(ps, SH.datatype)):
                g.remove((ps, SH.datatype, dt))
        # Fix cred:holder nodeKind (IRI, not Literal) — DIDs are IRIs
        for ps in g.subjects(SH.path, CRED.holder):
            g.remove((ps, SH.nodeKind, SH.Literal))
            g.add((ps, SH.nodeKind, SH.IRIOrLiteral))
            for dt in list(g.objects(ps, SH.datatype)):
                g.remove((ps, SH.datatype, dt))
        # Remove sh:class linkml:Any — meta-type not present in instance data
        for s, p, o in list(g.triples((None, SH["class"], LINKML.Any))):
            g.remove((s, p, o))
        return g


class HarbourContextGenerator(_BaseContextGenerator):
    """Context generator that excludes imported vocabulary terms.

    W3C VC v2 envelope terms (issuer, validFrom, validUntil, evidence,
    credentialStatus) are defined in ``w3c-vc.yaml`` and imported into
    harbour schemas. With ``mergeimports=False`` these slots are marked
    with ``imported_from``. This generator skips them so the harbour
    JSON-LD context does not redefine ``@protected`` terms already
    provided by ``https://www.w3.org/ns/credentials/v2``.
    """

    def visit_slot(self, aliased_slot_name: str, slot: SlotDefinition) -> None:
        if getattr(slot, "imported_from", None) and not str(
            slot.imported_from
        ).startswith("linkml"):
            return
        super().visit_slot(aliased_slot_name, slot)


def main() -> None:
    importmap_path = LINKML_DIR / "importmap.json"
    importmap = None
    if importmap_path.exists():
        raw = json.loads(importmap_path.read_text(encoding="utf-8"))
        # Resolve relative paths against the linkml directory
        importmap = {}
        for key, val in raw.items():
            p = Path(val)
            if not p.is_absolute():
                p = (LINKML_DIR / p).resolve()
            importmap[key] = str(p)

    for domain in DOMAINS:
        schema = str(LINKML_DIR / f"{domain}.yaml")
        base_dir = str(LINKML_DIR)
        out_dir = ARTIFACTS_DIR / domain
        out_dir.mkdir(parents=True, exist_ok=True)

        print(f"  Processing {domain}...")

        owl_gen = OwlSchemaGenerator(
            schema, mergeimports=False, importmap=importmap, base_dir=base_dir
        )
        (out_dir / f"{domain}.owl.ttl").write_text(
            owl_gen.serialize(), encoding="utf-8"
        )

        shacl_gen = HarbourShaclGenerator(
            schema, importmap=importmap, base_dir=base_dir
        )
        (out_dir / f"{domain}.shacl.ttl").write_text(
            shacl_gen.serialize(), encoding="utf-8"
        )

        ctx_gen = HarbourContextGenerator(
            schema, mergeimports=False, importmap=importmap, base_dir=base_dir
        )
        ctx_text = ctx_gen.serialize()

        # Ensure "type": "@type" is present in the generated context.
        # See harbour-core-credential.yaml §slots comment for rationale.
        ctx_data = json.loads(ctx_text)
        ctx_obj = ctx_data.get("@context", {})
        if isinstance(ctx_obj, dict) and "type" not in ctx_obj:
            ctx_obj["type"] = "@type"
            ctx_data["@context"] = ctx_obj
            ctx_text = json.dumps(ctx_data, indent=3, ensure_ascii=False)

        (out_dir / f"{domain}.context.jsonld").write_text(ctx_text, encoding="utf-8")

    print(f"\nDone: {ARTIFACTS_DIR}/")


if __name__ == "__main__":
    main()
