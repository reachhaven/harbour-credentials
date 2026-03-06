#!/usr/bin/env python3
"""Generate downstream artifacts (OWL ontology, SHACL shapes, JSON-LD context)
from Harbour LinkML schemas.

The custom HarbourShaclGenerator fixes the ``cred:issuer`` property shape:
LinkML maps ``range: string`` to ``sh:nodeKind sh:Literal``, but the W3C VC v2
context defines ``issuer`` with ``@type: @id``, so the RDF value is an IRI.
The generator patches the property shape to ``sh:nodeKind sh:IRIOrLiteral``
(accepting both IRIs from JSON-LD and literal strings from plain JSON).
"""

from pathlib import Path

from linkml.generators.jsonldcontextgen import ContextGenerator
from linkml.generators.owlgen import OwlSchemaGenerator
from linkml.generators.shaclgen import ShaclGenerator as _BaseShaclGenerator
from rdflib import Namespace

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
LINKML_DIR = REPO_ROOT / "linkml"
ARTIFACTS_DIR = REPO_ROOT / "artifacts"

DOMAINS = ["harbour-core-credential", "harbour-gx-credential"]

SH = Namespace("http://www.w3.org/ns/shacl#")
XSD = Namespace("http://www.w3.org/2001/XMLSchema#")
CRED = Namespace("https://www.w3.org/2018/credentials#")


class HarbourShaclGenerator(_BaseShaclGenerator):
    """SHACL generator that corrects IRI-valued property shapes.

    ``cred:issuer`` is defined as ``@type: @id`` in the W3C VC v2 context,
    meaning JSON-LD processors expand issuer values to IRIs. LinkML has no
    native IRI range type, so we patch the generated graph directly.
    """

    def as_graph(self):
        g = super().as_graph()
        # Find property shapes targeting cred:issuer and fix nodeKind
        for ps in g.subjects(SH.path, CRED.issuer):
            g.remove((ps, SH.nodeKind, SH.Literal))
            g.add((ps, SH.nodeKind, SH.IRIOrLiteral))
            # Remove sh:datatype — IRI nodes don't carry a datatype
            for dt in list(g.objects(ps, SH.datatype)):
                g.remove((ps, SH.datatype, dt))
        return g


def main() -> None:
    for domain in DOMAINS:
        schema = str(LINKML_DIR / f"{domain}.yaml")
        out_dir = ARTIFACTS_DIR / domain
        out_dir.mkdir(parents=True, exist_ok=True)

        print(f"  Processing {domain}...")

        owl_gen = OwlSchemaGenerator(schema)
        (out_dir / f"{domain}.owl.ttl").write_text(
            owl_gen.serialize(), encoding="utf-8"
        )

        shacl_gen = HarbourShaclGenerator(schema)
        (out_dir / f"{domain}.shacl.ttl").write_text(
            shacl_gen.serialize(), encoding="utf-8"
        )

        ctx_gen = ContextGenerator(schema)
        (out_dir / f"{domain}.context.jsonld").write_text(
            ctx_gen.serialize(), encoding="utf-8"
        )

    print(f"\nDone: {ARTIFACTS_DIR}/")


if __name__ == "__main__":
    main()
