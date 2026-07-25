"""SECURITY.md claims a test proves each row. This checks that it still does.

A tested-attack matrix is only worth publishing if the citations are real, and
they rot the first time somebody renames a test. So the matrix is parsed and
every name it cites is looked up in the suite.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SECURITY = REPO / "SECURITY.md"
TESTS = REPO / "tests"

#: `path::test_name` and bare `` `test_name` `` both count as a citation.
_CITED = re.compile(r"::(test_\w+)|`(test_\w+)`")


def _cited_test_names() -> set[str]:
    text = SECURITY.read_text(encoding="utf-8")
    return {name for pair in _CITED.findall(text) for name in pair if name}


def _defined_test_names() -> set[str]:
    out: set[str] = set()
    for path in TESTS.glob("test_*.py"):
        out |= set(re.findall(r"^def (test_\w+)", path.read_text(encoding="utf-8"), re.M))
    return out


def test_security_matrix_exists() -> None:
    assert SECURITY.is_file(), "SECURITY.md is a deliverable, not optional"


def test_every_cited_test_exists() -> None:
    missing = sorted(_cited_test_names() - _defined_test_names())
    assert not missing, (
        f"SECURITY.md cites tests that no longer exist: {', '.join(missing)}. "
        "Rename the citation or restore the test — an unbacked row is the thing "
        "the matrix exists to avoid."
    )


def test_the_matrix_cites_a_meaningful_number_of_tests() -> None:
    """Guards against a refactor that quietly empties the tables."""
    assert len(_cited_test_names()) >= 20


def test_undefended_rows_are_still_published() -> None:
    """The rows whose result is 'succeeds' are the point of publishing this."""
    text = SECURITY.read_text(encoding="utf-8")
    assert "**succeeds" in text
    for residual in ("server_network: none", "secrets attach", "~/.claude"):
        assert residual in text, f"{residual} dropped out of the matrix"


def test_maturity_and_reporting_are_stated() -> None:
    text = SECURITY.read_text(encoding="utf-8")
    assert "has not had third-party security review" in text
    assert "security/advisories" in text
