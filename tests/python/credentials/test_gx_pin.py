"""Guard the Gaia-X pin: submodule source vs. the shapes vendored by ``omb``.

``just generate`` compiles harbour's gx layer from the gaia-x LinkML source in
``submodules/service-characteristics``; ``just validate-shacl`` then validates the
result against the Gaia-X SHACL shapes vendored inside the installed
``ontology-management-base`` wheel. Those two only describe the same Gaia-X if the
submodule sits on the exact upstream commit OMB generated its shapes from — which the
wheel records in ``omb/data/artifacts/gx/UPSTREAM_COMMIT``. Both halves of the pin are
checked: the gitlink recorded in the superproject index (what a commit stores and what
a fresh clone or CI checks out) and the commit the submodule working tree is on.

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

# tests/python/credentials/test_gx_pin.py -> repository root. Resolved positionally,
# not by directory name: a checkout cloned under any other name would otherwise walk
# up to "/" and make this guard skip itself instead of failing.
_REPO_ROOT = Path(__file__).resolve().parents[3]

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


def _recorded_gitlink() -> str:
    """The commit the superproject index records for the submodule.

    This — not the submodule's working-tree HEAD — is what a commit stores and what a
    fresh clone or CI checks out, so a repin that was checked out but never staged
    must not pass as up to date.
    """
    entry = subprocess.run(
        ["git", "-C", str(_REPO_ROOT), "ls-files", "-s", "--", str(_SVC_SUBMODULE)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert entry, "submodules/service-characteristics is not registered in the index"
    mode, sha, _rest = entry.split(maxsplit=2)
    assert mode == "160000", f"expected a gitlink entry, got mode {mode}"
    return sha


def _worktree_head() -> str:
    """The commit the submodule working tree is actually checked out at."""
    return subprocess.run(
        ["git", "-C", str(_SVC_SUBMODULE), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


@_skip_no_omb
@_skip_no_submodule
def test_service_characteristics_matches_omb_gx_artifacts():
    """Both halves of the pin must equal the commit omb's gx shapes were built from."""
    expected = _omb_gx_file("UPSTREAM_COMMIT")
    gitlink = _recorded_gitlink()
    worktree = _worktree_head()

    assert (gitlink, worktree) == (expected, expected), (
        f"submodules/service-characteristics is out of step with the installed omb.\n"
        f"  omb vendors gx {_omb_gx_file('UPSTREAM_REF')} "
        f"generated from {expected}\n"
        f"  recorded gitlink is                      {gitlink}\n"
        f"  submodule working tree HEAD is           {worktree}\n"
        f"Repin the submodule to {expected} (see 'just check-gx-pin')."
    )
