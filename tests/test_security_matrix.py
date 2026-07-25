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


#: Files that get published — to GitHub, to the docs site, or both.
_PUBLISHED = ("README.md", "GUIDE.md", "QUICKSTART.md", "SECURITY.md")

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
#: An absolute macOS/Linux home path names the account it belongs to.
_HOME_PATH = re.compile(r"/(?:Users|home)/([\w.-]+)/")
#: Accounts that are not anybody's: the container's own user, and the
#: placeholders the docs use when a host path has to be shown in full.
_IMPERSONAL_ACCOUNTS = {"vscode", "root", "you", "user", "me", "youruser"}


def _published_files() -> list[Path]:
    return [REPO / name for name in _PUBLISHED] + sorted((REPO / "docs" / "notes").glob("*.md"))


def test_no_contact_email_is_published() -> None:
    """Reporting goes through GitHub advisories only; no address is exposed."""
    offenders = []
    for path in _published_files():
        if not path.is_file():
            continue
        for match in _EMAIL.findall(path.read_text(encoding="utf-8")):
            # Example env values and non-address strings are not contact details.
            if match.endswith("@users.noreply.github.com"):
                continue
            offenders.append(f"{path.name}: {match}")
    assert not offenders, (
        "published docs must not carry an email address — reporting is GitHub "
        f"advisories only: {', '.join(offenders)}"
    )


def test_no_home_directory_path_is_published() -> None:
    """An absolute home path names the account that ran the command.

    `/home/vscode` is the container's own user and `/Users/you` is a
    placeholder; a real account name is the leak.
    """
    offenders = [
        f"{path.name}: {account}"
        for path in _published_files()
        if path.is_file()
        for account in _HOME_PATH.findall(path.read_text(encoding="utf-8"))
        if account not in _IMPERSONAL_ACCOUNTS
    ]
    assert not offenders, (
        f"use ~/ rather than an absolute home path in published docs: {', '.join(offenders)}"
    )
