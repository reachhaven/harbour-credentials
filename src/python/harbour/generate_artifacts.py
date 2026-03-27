#!/usr/bin/env python3
"""Generate downstream artifacts (OWL ontology, SHACL shapes, JSON-LD context)
from Harbour LinkML schemas.

Uses upstream ``ShaclGenerator`` (with ``uses_schemaloader=False`` and importmap
passthrough, linkml/linkml#2913 fixed in ASCS-eV/linkml PR #3293) and
``ContextGenerator`` (with ``mergeimports=False`` to skip external vocabulary
terms, ASCS-eV/linkml PR #3279) so harbour's JSON-LD context does not redefine
``@protected`` terms already provided by the W3C VC v2 context.

The ``xsd_anyuri_as_iri=True`` flag (ASCS-eV/linkml PR #3292) ensures
``range: uri`` slots produce ``@type: @id`` in the context, matching the SHACL
``sh:nodeKind sh:IRI`` constraint.

The ``normalize_prefixes=True`` flag (ASCS-eV/linkml PR #3308) maps
non-standard prefix aliases (e.g. ``sdo`` → ``schema``, ``dce`` → ``dc``)
to their canonical well-known names, producing cleaner and more portable
artifacts.
"""

import json
from pathlib import Path

from linkml.generators.jsonldcontextgen import ContextGenerator
from linkml.generators.owlgen import OwlSchemaGenerator
from linkml.generators.shaclgen import ShaclGenerator
from rdflib import OWL, RDFS, URIRef

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
LINKML_DIR = REPO_ROOT / "linkml"
ARTIFACTS_DIR = REPO_ROOT / "artifacts"

DOMAINS = [
    "harbour-core-credential",
    "harbour-gx-credential",
    "harbour-core-delegation",
]

# Domains where SHACL shapes should NOT be generated.
# harbour-core-delegation defines transaction data types used inside
# DelegatedSignatureEvidence.transaction_data — an opaque canonical JSON
# payload for OID4VP hash binding [OID4VP §5.1]. SHACL validation of its
# contents is inappropriate because the data is validated by SHA-256 hash
# binding (not RDF graph shape), and JSON-LD expansion would interfere
# with the canonical JSON used for hashing.
SHACL_SKIP_DOMAINS = {"harbour-core-delegation"}


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
            schema,
            mergeimports=False,
            deterministic=True,
            normalize_prefixes=True,
            importmap=importmap,
            base_dir=base_dir,
        )
        owl_text = owl_gen.serialize()

        # Post-process OWL: add owl:equivalentClass triples for classes
        # whose class_uri differs from the default OWL class IRI.
        # LinkML generates OWL class IRIs as default_prefix + ClassName,
        # but class_uri (used for SHACL targetClass and JSON-LD context)
        # may differ. Without equivalence, RDFS inference cannot chain
        # the subclass hierarchy through class_uri URIs.
        owl_text = _patch_owl_equivalences(owl_gen, owl_text)

        (out_dir / f"{domain}.owl.ttl").write_text(owl_text, encoding="utf-8")

        if domain not in SHACL_SKIP_DOMAINS:
            shacl_gen = ShaclGenerator(
                schema,
                deterministic=True,
                normalize_prefixes=True,
                importmap=importmap,
                base_dir=base_dir,
            )
            (out_dir / f"{domain}.shacl.ttl").write_text(
                shacl_gen.serialize(), encoding="utf-8"
            )

        ctx_gen = ContextGenerator(
            schema,
            mergeimports=False,
            exclude_external_imports=True,
            xsd_anyuri_as_iri=True,
            normalize_prefixes=True,
            deterministic=True,
            importmap=importmap,
            base_dir=base_dir,
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


def _patch_owl_equivalences(owl_gen: OwlSchemaGenerator, owl_text: str) -> str:
    """Add rdfs:subClassOf triples where class_uri differs from the
    default OWL class IRI (default_prefix + ClassName).

    LinkML generates OWL using default_prefix + class_name as the class IRI,
    but class_uri (which controls SHACL targetClass and JSON-LD type mapping)
    can be set to a different URI. Downstream validators that rely on RDFS
    inference need the subclass chain to be reachable from class_uri URIs.

    For each class where class_uri != owl_uri, we copy all rdfs:subClassOf
    triples from the owl_uri class to the class_uri URI. This ensures RDFS
    inference (which doesn't understand owl:equivalentClass) can resolve
    the type hierarchy via class_uri URIs used in instance data.
    """
    from rdflib import Graph

    sv = owl_gen.schemaview
    schema = sv.schema
    default_pfx = schema.default_prefix or ""
    pfx_map = {p.prefix_prefix: p.prefix_reference for p in schema.prefixes.values()}
    default_ns = pfx_map.get(default_pfx, "")

    equivalences: list[tuple[str, str]] = []
    for cls_name, cls_def in sv.all_classes().items():
        if cls_def.class_uri:
            class_uri_str = sv.get_uri(cls_def, expand=True)
            owl_uri = f"{default_ns}{cls_name}"
            if class_uri_str and class_uri_str != owl_uri:
                equivalences.append((owl_uri, class_uri_str))

    if not equivalences:
        return owl_text

    g = Graph()
    g.parse(data=owl_text, format="turtle")
    for owl_uri, class_uri_str in equivalences:
        owl_ref = URIRef(owl_uri)
        cu_ref = URIRef(class_uri_str)
        if (owl_ref, None, None) in g:
            # Copy rdfs:subClassOf triples from owl_uri to class_uri
            for _, _, parent in g.triples((owl_ref, RDFS.subClassOf, None)):
                if isinstance(parent, URIRef):
                    g.add((cu_ref, RDFS.subClassOf, parent))
            # Also add equivalence for OWL reasoners
            g.add((owl_ref, OWL.equivalentClass, cu_ref))

    return g.serialize(format="turtle")


if __name__ == "__main__":
    main()
