"""Guard the Gaia-X pin: submodule source vs. the shapes vendored by ``omb``.

``just generate`` compiles harbour's gx layer from the gaia-x LinkML source in
``submodules/service-characteristics``; ``just validate-shacl`` then validates the
result against the Gaia-X SHACL shapes vendored inside the installed
``ontology-management-base`` wheel. Those two only describe the same Gaia-X if the
submodule sits on the exact upstream commit OMB generated its shapes from — which the
wheel records in ``omb/data/artifacts/gx/UPSTREAM_COMMIT``.

Reading the expectation out of the wheel (rather than hard-coding a SHA here) means an
OMB bump cannot silently leave the submodule behind: the new wheel names a new commit
and this test fails until the gitlink follows. ``just check-gx-pin`` runs the same
comparison from the shell.

Run with::

    pytest tests/python/credentials/test_gx_pin.py -v
"""

import importlib.util
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent
while _REPO_ROOT.name != "harbour-credentials" and _REPO_ROOT != _REPO_ROOT.parent:
    _REPO_ROOT = _REPO_ROOT.parent

_SVC_SUBMODULE = _REPO_ROOT / "submodules" / "service-characteristics"

_skip_no_omb = pytest.mark.skipif(
    importlib.util.find_spec("omb") is None,
    reason="ontology-management-base (omb) package not installed",
)
_skip_no_submodule = pytest.mark.skipif(
    not (_SVC_SUBMODULE / "linkml" / "gaia-x.yaml").is_file(),
    reason="service-characteristics submodule not initialized — "
    "run 'just setup-submodules'",
)


def _omb_gx_file(name: str) -> str:
    """Read one of the gx provenance files vendored in the installed omb wheel."""
    import omb

    return (
        (Path(omb.__file__).parent / "data" / "artifacts" / "gx" / name)
        .read_text(encoding="utf-8")
        .strip()
    )


@_skip_no_omb
@_skip_no_submodule
def test_service_characteristics_matches_omb_gx_artifacts():
    """The submodule gitlink must equal the commit omb's gx shapes were built from."""
    expected = _omb_gx_file("UPSTREAM_COMMIT")
    actual = subprocess.run(
        ["git", "-C", str(_SVC_SUBMODULE), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()

    assert actual == expected, (
        f"submodules/service-characteristics is out of step with the installed omb.\n"
        f"  omb vendors gx {_omb_gx_file('UPSTREAM_REF')} "
        f"generated from {expected}\n"
        f"  submodule HEAD is                        {actual}\n"
        f"Repin the submodule to {expected} (see 'just check-gx-pin')."
    )
