"""The interactive flows.

These exist because the first real `abox init` crashed in a path the rest of the
suite never touched: every other test drove `--yes`, so the picker's questionary
calls were entirely uncovered. questionary is stubbed here — the point is the
argument shaping and the empty-list edge cases, not questionary itself.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from abox import picker
from abox.catalog import Catalog, CatalogServer
from abox.errors import AboxError


class FakePrompt:
    """Stands in for a questionary prompt object; ``.ask()`` returns a scripted value."""

    def __init__(self, answer: Any) -> None:
        self._answer = answer

    def ask(self) -> Any:
        return self._answer


@pytest.fixture
def q(monkeypatch: pytest.MonkeyPatch):
    """Script questionary's answers and record what it was asked."""

    calls: dict[str, list[Any]] = {"checkbox": [], "text": [], "select": [], "confirm": []}
    answers: dict[str, Any] = {}

    def record(kind: str):
        def _call(message: str, **kwargs: Any) -> FakePrompt:
            calls[kind].append({"message": message, **kwargs})
            value = answers.get(kind)
            return FakePrompt(value() if callable(value) else value)

        return _call

    monkeypatch.setattr(picker.questionary, "checkbox", record("checkbox"))
    monkeypatch.setattr(picker.questionary, "text", record("text"))
    monkeypatch.setattr(picker.questionary, "select", record("select"))
    monkeypatch.setattr(picker.questionary, "confirm", record("confirm"))
    monkeypatch.setattr(picker.questionary, "print", lambda *a, **k: None)
    monkeypatch.setattr(picker, "interactive", lambda: True)
    return type("Q", (), {"calls": calls, "answers": answers})()


# -- the crash that shipped ------------------------------------------------


def test_egress_with_nothing_to_suggest_does_not_crash(q) -> None:
    """A project with no detected toolchain and no git remote has an empty
    suggestion list. questionary reads `pointed_at` before it exists when handed
    zero choices, which turned an ordinary state into a traceback."""
    q.answers["text"] = ""
    assert picker.pick_egress([], []) == []
    # It must not even try to render an empty checkbox.
    assert q.calls["checkbox"] == []


def test_empty_egress_still_offers_the_free_text_prompt(q) -> None:
    q.answers["text"] = "example.com, api.example.com"
    assert picker.pick_egress([], []) == ["example.com", "api.example.com"]


def test_checkbox_guard_returns_empty_for_no_choices(q) -> None:
    assert picker.checkbox("anything", []) == []
    assert q.calls["checkbox"] == []


def test_checkbox_passes_choices_through(q) -> None:
    q.answers["checkbox"] = ["a"]
    assert picker.checkbox("pick", [picker.questionary.Choice(title="a", value="a")]) == ["a"]
    assert len(q.calls["checkbox"]) == 1


def test_cancelling_a_checkbox_raises(q) -> None:
    q.answers["checkbox"] = None
    with pytest.raises(AboxError, match="cancelled"):
        picker.checkbox("pick", [picker.questionary.Choice(title="a", value="a")])


def test_cancelling_the_egress_text_raises(q) -> None:
    q.answers["checkbox"] = ["pypi.org"]
    q.answers["text"] = None
    with pytest.raises(AboxError, match="cancelled"):
        picker.pick_egress(["pypi.org"], [])


# -- suggestions -----------------------------------------------------------


def test_egress_merges_existing_and_suggested(q) -> None:
    q.answers["checkbox"] = ["pypi.org", "github.com"]
    q.answers["text"] = ""
    picker.pick_egress(["pypi.org"], ["github.com"])
    titles = [c.value for c in q.calls["checkbox"][0]["choices"]]
    assert titles == ["github.com", "pypi.org"]  # existing first, then suggested


def test_free_text_domains_are_appended_without_duplicates(q) -> None:
    q.answers["checkbox"] = ["pypi.org"]
    q.answers["text"] = "pypi.org example.com"
    assert picker.pick_egress(["pypi.org"], []) == ["pypi.org", "example.com"]


def test_suggestions_follow_a_hand_picked_toolchain(tmp_path: Path) -> None:
    """Picking `python` by hand in a repo with no pyproject.toml must still
    offer pypi.org — the suggestion has to come from the chosen toolchains, not
    from whatever was auto-detected before the picker ran."""
    bare = tmp_path / "bare"
    bare.mkdir()
    assert picker.detect_toolchains(bare) == []
    assert "pypi.org" in picker.suggest_egress(["python"], bare)


# -- servers and tools -----------------------------------------------------


def _catalog() -> Catalog:
    return Catalog(
        servers={
            "duckduckgo": CatalogServer(
                name="duckduckgo",
                description="Web search.",
                image="mcp/duckduckgo@sha256:" + "0" * 64,
                tools=("search", "fetch_content"),
            ),
            "github-official": CatalogServer(
                name="github-official",
                description="GitHub.",
                image="ghcr.io/github/github-mcp-server@sha256:" + "d" * 64,
                secrets=("github.personal_access_token",),
                tools=("list_issues",),
            ),
        }
    )


def test_server_choices_flag_secrets_and_unpinned(q) -> None:
    q.answers["checkbox"] = []
    picker.pick_servers(_catalog())
    titles = [c.title for c in q.calls["checkbox"][0]["choices"]]
    assert any("needs 1 secret(s)" in t for t in titles)


def test_empty_catalog_explains_itself(q) -> None:
    with pytest.raises(AboxError, match="catalog is empty") as exc:
        picker.pick_servers(Catalog())
    assert "custom-servers.yaml" in (exc.value.hint or "")


def test_declining_the_narrowing_prompt_returns_no_filter(q) -> None:
    q.answers["confirm"] = False
    assert picker.pick_tools(_catalog(), ["duckduckgo"]) == {}


def test_selecting_every_tool_records_no_filter(q) -> None:
    """Selecting all of them is the same as not filtering; recording it would
    make the manifest drift as the server gains tools."""
    q.answers["confirm"] = True
    q.answers["checkbox"] = ["search", "fetch_content"]
    assert picker.pick_tools(_catalog(), ["duckduckgo"]) == {}


def test_selecting_a_subset_records_the_filter(q) -> None:
    q.answers["confirm"] = True
    q.answers["checkbox"] = ["search"]
    assert picker.pick_tools(_catalog(), ["duckduckgo"]) == {"duckduckgo": ["search"]}


def test_a_server_with_no_known_tools_is_skipped(q) -> None:
    q.answers["confirm"] = True
    q.answers["checkbox"] = []
    catalog = Catalog(servers={"bare": CatalogServer(name="bare", image="x@sha256:" + "0" * 64)})
    assert picker.pick_tools(catalog, ["bare"]) == {}


# -- toolchains, profile, context, mode ------------------------------------


def test_toolchain_choices_preselect_the_detected_ones(q) -> None:
    q.answers["checkbox"] = ["python"]
    assert picker.pick_toolchains(["python"]) == ["python"]
    checked = {c.value for c in q.calls["checkbox"][0]["choices"] if c.checked}
    assert checked == {"python"}


def test_context_dirs_split_on_whitespace(q) -> None:
    q.answers["text"] = "~/notes  /srv/data"
    assert picker.pick_context_dirs() == ["~/notes", "/srv/data"]


def test_blank_context_dirs_means_none(q) -> None:
    q.answers["text"] = ""
    assert picker.pick_context_dirs() == []


def test_permission_mode_round_trips(q) -> None:
    q.answers["select"] = "bypassPermissions"
    assert picker.pick_permission_mode() == "bypassPermissions"


def test_cancelled_permission_mode_raises(q) -> None:
    q.answers["select"] = None
    with pytest.raises(AboxError, match="cancelled"):
        picker.pick_permission_mode()


def test_profile_selection(q, config) -> None:
    q.answers["select"] = "dev"
    assert picker.pick_profile(config) == "dev"


def test_new_profile_gets_a_free_port(q, config) -> None:
    q.answers["select"] = "__new__"
    q.answers["text"] = "research"
    name = picker.pick_profile(config)
    assert name == "research"
    used = {p.port for p in config.profiles.values()}
    assert config.profiles["research"].port not in (8811, 8812)
    assert len(used) == 3


# -- non-interactive guard -------------------------------------------------


def test_pickers_refuse_a_non_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(picker, "interactive", lambda: False)
    with pytest.raises(AboxError, match="interactive terminal") as exc:
        picker.pick_egress([], [])
    assert "flags instead" in (exc.value.hint or "")


def test_questionary_really_does_crash_on_zero_choices() -> None:
    """Pins the upstream behaviour the guard above exists for.

    If questionary ever fixes this, the guard becomes belt-and-braces rather
    than load-bearing — and this test tells us, instead of the guard quietly
    becoming folklore.
    """
    import questionary

    with pytest.raises((AttributeError, IndexError, ValueError)):
        questionary.checkbox("nothing to pick", choices=[])


# -- input validation ------------------------------------------------------


def test_context_dir_validation_rejects_relative_paths() -> None:
    """Correct the operator in place; a typo must not surface as a pydantic
    traceback after the whole flow has been answered."""
    assert picker._validate_context_input("notes") != True  # noqa: E712
    assert "absolute" in str(picker._validate_context_input("notes"))


def test_context_dir_validation_rejects_missing_paths(tmp_path: Path) -> None:
    assert "does not exist" in str(picker._validate_context_input(str(tmp_path / "nope")))


def test_context_dir_validation_accepts_a_real_dir(tmp_path: Path) -> None:
    assert picker._validate_context_input(str(tmp_path)) is True


def test_context_dir_validation_accepts_blank() -> None:
    assert picker._validate_context_input("") is True
