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

from abox import paths, picker
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
    assert any("needs 1 secret" in t for t in titles)


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


# -- the review screen -----------------------------------------------------


def scripted(*values: Any):
    """The ``q`` fixture calls a callable answer once per prompt; this scripts a run."""
    it = iter(values)
    return lambda: next(it)


def _ctx(tmp_path: Path, config, catalog: Catalog | None = None) -> picker.InitContext:
    return picker.InitContext(
        workspace=tmp_path,
        catalog=catalog if catalog is not None else _catalog(),
        config=config,
        manifest_path=tmp_path / "agentbox.yaml",
        detected=[],
    )


def _draft(**kw: Any) -> picker.InitDraft:
    base: dict[str, Any] = {"project": "demo", "profile": "dev"}
    return picker.InitDraft(**{**base, **kw})


def test_the_review_screen_shows_tools_and_context_the_old_summary_dropped(q, config, tmp_path):
    """InitAnswers carried both and confirm_summary rendered neither, so the one
    screen meant to show what you built showed less than you had answered."""
    draft = _draft(
        servers=["duckduckgo"], tools={"duckduckgo": ["search"]}, context=["/srv/data"]
    )
    titles = [c.title for c in picker._hub_choices(draft, _ctx(tmp_path, config))]
    assert any("duckduckgo: 1 of 2" in t for t in titles)
    assert any("/srv/data" in t for t in titles)


def test_every_row_renders_prose_rather_than_a_blank_when_unset(q, config, tmp_path):
    ctx = _ctx(tmp_path, config)
    draft = _draft()
    for row in picker.ROWS:
        value = row.value(draft, ctx)
        assert value, f"{row.key} rendered empty"
        assert value.strip() != "", f"{row.key} rendered whitespace"


def test_every_editable_field_has_a_row() -> None:
    assert {row.key for row in picker.ROWS} == {
        "profile", "servers", "secrets", "tools", "toolchains",
        "egress", "mask", "context", "server_network", "permission",
        "connectors", "output", "timeout",
    }


def test_saving_returns_true_and_edits_nothing(q, config, tmp_path) -> None:
    q.answers["select"] = picker.SAVE
    draft = _draft()
    assert picker.review_and_edit(draft, _ctx(tmp_path, config)) is True
    assert q.calls["checkbox"] == []


def test_cancelling_returns_false(q, config, tmp_path) -> None:
    q.answers["select"] = picker.CANCEL
    assert picker.review_and_edit(_draft(), _ctx(tmp_path, config)) is False


def test_the_screen_loops_until_save(q, config, tmp_path) -> None:
    q.answers["select"] = scripted("toolchains", picker.SAVE)
    q.answers["checkbox"] = ["python"]
    draft = _draft()
    assert picker.review_and_edit(draft, _ctx(tmp_path, config)) is True
    assert draft.toolchains == ["python"]
    assert len(q.calls["select"]) == 2


def test_a_cancelled_sub_prompt_returns_to_the_screen_with_the_row_unchanged(q, config, tmp_path):
    """The whole point: Ctrl-C inside one answer costs that answer, not all of them."""
    q.answers["select"] = scripted("toolchains", picker.SAVE)
    q.answers["checkbox"] = None  # Ctrl-C
    draft = _draft(toolchains=["go"])
    assert picker.review_and_edit(draft, _ctx(tmp_path, config)) is True
    assert draft.toolchains == ["go"]


def test_ctrl_c_at_the_review_screen_cancels_the_whole_init(q, config, tmp_path) -> None:
    q.answers["select"] = None
    with pytest.raises(AboxError, match="cancelled"):
        picker.review_and_edit(_draft(), _ctx(tmp_path, config))


def test_a_failing_sub_prompt_does_not_kill_the_screen(q, config, tmp_path) -> None:
    """An empty catalog is a real AboxError, not a cancel — it still must not
    destroy the eight answers already given."""
    q.answers["select"] = scripted("servers", picker.CANCEL)
    ctx = _ctx(tmp_path, config, catalog=Catalog())
    assert picker.review_and_edit(_draft(), ctx) is False


def test_the_screen_never_shells_out_to_docker_while_drawing(q, config, tmp_path, monkeypatch):
    """`docker mcp secret ls` has a 60s timeout; calling it to render a row
    would hang `abox init` for a minute on a stopped daemon."""
    def explode() -> set[str]:
        raise AssertionError("the review screen must not touch Docker")

    monkeypatch.setattr(picker.secrets_mod, "docker_secret_names", explode)
    draft = _draft(servers=["github-official"])
    assert picker._hub_choices(draft, _ctx(tmp_path, config))


# -- quick vs custom -------------------------------------------------------


def test_quick_is_the_default_for_a_fresh_project(q) -> None:
    q.answers["select"] = "quick"
    assert picker.choose_setup_mode("demo") == "quick"
    call = q.calls["select"][0]
    assert call["default"] == "quick"
    assert "New sandbox for demo" in call["message"]


def test_an_existing_manifest_offers_review_rather_than_quick(q) -> None:
    q.answers["select"] = "quick"
    picker.choose_setup_mode("demo", existing=True)
    call = q.calls["select"][0]
    assert "Editing demo" in call["message"]
    assert any("Review" in c.title for c in call["choices"])


def test_the_custom_walk_visits_every_row(q, config, tmp_path) -> None:
    q.answers["select"] = "dev"
    q.answers["checkbox"] = []
    q.answers["text"] = ""
    q.answers["confirm"] = False
    picker.walk_all(_draft(egress=["pypi.org"]), _ctx(tmp_path, config))
    asked = [c["message"] for kind in q.calls for c in q.calls[kind]]
    assert any("Gateway profile" in m for m in asked)
    assert any("MCP servers" in m for m in asked)
    assert any("Toolchains" in m for m in asked)
    assert any("Allowed outbound domains" in m for m in asked)
    assert any("Extra paths to hide" in m for m in asked)
    assert any("context dirs" in m for m in asked)
    assert any("Permission mode" in m for m in asked)


def test_a_cancelled_walk_keeps_what_was_already_answered(q, config, tmp_path) -> None:
    q.answers["select"] = "dev"
    q.answers["checkbox"] = None  # cancels at the servers question
    draft = _draft()
    picker.walk_all(draft, _ctx(tmp_path, config))
    assert draft.profile == "dev"  # the answer before the cancel survived


# -- seeding ---------------------------------------------------------------


def test_seed_draft_matches_what_the_non_interactive_path_writes(workspace, config) -> None:
    """Quick setup and `--yes` must start from the same place; they used to be
    two branches of one `if`, and only one remembered the mandatory hosts."""
    draft = picker.seed_draft(
        project="demo", workspace=workspace, config=config, existing=None
    )
    assert draft.toolchains == ["python"]
    assert "pypi.org" in draft.egress
    for host in picker.BASE_MANDATORY_EGRESS:
        assert host in draft.egress
    assert draft.profile == next(iter(config.profiles))


def test_seed_draft_prefers_the_existing_manifest_over_detection(workspace, config, manifest):
    draft = picker.seed_draft(
        project="demo", workspace=workspace, config=config, existing=manifest
    )
    assert draft.profile == "dev"
    assert draft.servers == ["github-official", "duckduckgo"]
    assert draft.mask == [".env*", "secrets/"]


def test_flags_seed_the_draft_but_leave_the_row_editable(workspace, config) -> None:
    draft = picker.seed_draft(
        project="demo", workspace=workspace, config=config, existing=None,
        profile="secops", servers=["duckduckgo"],
    )
    assert draft.profile == "secops"
    assert draft.servers == ["duckduckgo"]


# -- the orphan profile ----------------------------------------------------


def test_a_new_profile_is_not_saved_until_the_manifest_is(q, config) -> None:
    """Saving it here left an orphan profile, holding a port, behind every
    cancelled init."""
    q.answers["select"] = "__new__"
    q.answers["text"] = "research"
    sink: dict[str, Any] = {}
    assert picker.pick_profile(config, created=sink) == "research"
    assert set(sink) == {"research"}
    assert not paths.global_config_path().exists()


# -- grouping and search ---------------------------------------------------


def test_server_choices_are_grouped_with_separators(q) -> None:
    q.answers["checkbox"] = []
    picker.pick_servers(_catalog())
    choices = q.calls["checkbox"][0]["choices"]
    assert any(isinstance(c, picker.questionary.Separator) for c in choices)
    headings = [c.title for c in choices if isinstance(c, picker.questionary.Separator)]
    assert any("ready to use" in h for h in headings)
    assert any("needs a secret" in h for h in headings)


def test_already_chosen_servers_come_first(q) -> None:
    q.answers["checkbox"] = []
    picker.pick_servers(_catalog(), preselected=["github-official"])
    titles = [c.title for c in q.calls["checkbox"][0]["choices"]]
    assert "already in this project" in titles[0]
    assert "github-official" in titles[1]


def test_the_server_list_enables_search_and_disables_jk(q) -> None:
    """questionary refuses both — j/k become filter input once search is on —
    so passing search without turning j/k off raises at prompt construction."""
    q.answers["checkbox"] = []
    picker.pick_servers(_catalog())
    call = q.calls["checkbox"][0]
    assert call["use_search_filter"] is True
    assert call["use_jk_keys"] is False


def test_a_list_of_only_separators_counts_as_empty(q) -> None:
    """Separator is a Choice with disabled='-', so a heading-only list walks
    into the same crash the zero-choice guard exists for."""
    assert picker.checkbox("nothing", [picker.questionary.Separator("── none ──")]) == []
    assert q.calls["checkbox"] == []


# -- inline credentials ----------------------------------------------------


def _secret_ctx(tmp_path, config) -> picker.InitContext:
    return _ctx(tmp_path, config)


def test_no_secrets_needed_asks_nothing(q, config, tmp_path) -> None:
    picker.offer_secrets(_draft(servers=["duckduckgo"]), _secret_ctx(tmp_path, config))
    assert q.calls["confirm"] == []


def test_one_credential_reads_as_singular(q, config, tmp_path) -> None:
    """`secrets_for` counts credentials, not servers, so the old wording
    ("N of the servers you picked need a credential") both disagreed with its
    own verb at N=1 and named the wrong noun."""
    q.answers["confirm"] = False
    picker.offer_secrets(_draft(servers=["github-official"]), _secret_ctx(tmp_path, config))
    assert q.calls["confirm"][0]["message"] == (
        "the servers you picked need 1 credential — set it now?"
    )


def test_two_credentials_on_one_server_do_not_claim_two_servers(q, config, tmp_path) -> None:
    """One server declaring two secrets used to report "2 of the servers"."""
    q.answers["confirm"] = False
    catalog = Catalog(
        servers={
            "greedy": CatalogServer(
                name="greedy",
                description="Wants both.",
                image="mcp/greedy@sha256:" + "e" * 64,
                secrets=("greedy.token", "greedy.webhook"),
                tools=("go",),
            )
        }
    )
    picker.offer_secrets(_draft(servers=["greedy"]), _ctx(tmp_path, config, catalog))
    assert q.calls["confirm"][0]["message"] == (
        "the servers you picked need 2 credentials — set them now?"
    )


def test_declining_stores_nothing(q, config, tmp_path, monkeypatch) -> None:
    q.answers["confirm"] = False
    monkeypatch.setattr(
        picker.secrets_mod, "set_secret", lambda *a, **k: pytest.fail("stored anyway")
    )
    draft = _draft(servers=["github-official"])
    picker.offer_secrets(draft, _secret_ctx(tmp_path, config))
    assert draft.stored_secrets == []


def test_only_the_missing_secrets_are_asked_for(q, config, tmp_path, monkeypatch) -> None:
    q.answers["confirm"] = True
    q.answers["select"] = "type"
    monkeypatch.setattr(picker.secrets_mod, "docker_secret_names", lambda: set())
    asked: list[str] = []
    monkeypatch.setattr(
        picker.secrets_mod, "read_from_prompt", lambda name, **k: asked.append(name) or "v"
    )
    monkeypatch.setattr(picker.secrets_mod, "set_secret", lambda *a, **k: None)
    draft = _draft(servers=["github-official"])
    picker.offer_secrets(draft, _secret_ctx(tmp_path, config))
    assert asked == ["github.personal_access_token"]
    assert draft.stored_secrets == ["github.personal_access_token"]


def test_an_already_stored_secret_is_not_asked_for_again(q, config, tmp_path, monkeypatch):
    q.answers["confirm"] = True
    monkeypatch.setattr(
        picker.secrets_mod, "docker_secret_names", lambda: {"github.personal_access_token"}
    )
    monkeypatch.setattr(
        picker.secrets_mod, "read_from_prompt", lambda *a, **k: pytest.fail("asked anyway")
    )
    picker.offer_secrets(_draft(servers=["github-official"]), _secret_ctx(tmp_path, config))


def test_an_unreachable_secret_store_does_not_fail_the_picker(q, config, tmp_path, monkeypatch):
    """Docker not running is an ordinary state during `abox init`."""
    q.answers["confirm"] = True

    def unreachable() -> set[str]:
        raise AboxError("could not list docker secrets: daemon not running")

    monkeypatch.setattr(picker.secrets_mod, "docker_secret_names", unreachable)
    monkeypatch.setattr(
        picker.secrets_mod, "set_secret", lambda *a, **k: pytest.fail("stored anyway")
    )
    draft = _draft(servers=["github-official"])
    picker.offer_secrets(draft, _secret_ctx(tmp_path, config))
    assert draft.stored_secrets == []


def test_a_secret_value_never_reaches_a_prompt_or_the_draft(q, config, tmp_path, monkeypatch):
    q.answers["confirm"] = True
    q.answers["select"] = "type"
    monkeypatch.setattr(picker.secrets_mod, "docker_secret_names", lambda: set())
    monkeypatch.setattr(picker.secrets_mod, "read_from_prompt", lambda *a, **k: "hunter2")
    monkeypatch.setattr(picker.secrets_mod, "set_secret", lambda *a, **k: None)
    draft = _draft(servers=["github-official"])
    picker.offer_secrets(draft, _secret_ctx(tmp_path, config))
    blob = repr(q.calls) + repr(draft)
    assert "hunter2" not in blob


def test_skipping_the_rest_stops_asking(q, config, tmp_path, monkeypatch) -> None:
    q.answers["confirm"] = True
    q.answers["select"] = "stop"
    monkeypatch.setattr(picker.secrets_mod, "docker_secret_names", lambda: set())
    monkeypatch.setattr(
        picker.secrets_mod, "read_from_prompt", lambda *a, **k: pytest.fail("asked anyway")
    )
    picker.offer_secrets(_draft(servers=["github-official"]), _secret_ctx(tmp_path, config))


# -- validation ------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "needle"),
    [
        ("https://example.com", "not URLs"),
        ("example.com/path", "must not contain a path"),
        ("example.com:443", "must not contain a port"),
        ("*.example.com", "wildcard egress is not supported"),
    ],
)
def test_egress_validation_rejects_what_the_manifest_would(value: str, needle: str) -> None:
    assert needle in str(picker._validate_egress_input(value))


def test_egress_validation_accepts_a_comma_separated_list() -> None:
    assert picker._validate_egress_input("a.com, b.co.uk example.org") is True


def test_egress_validation_accepts_blank() -> None:
    assert picker._validate_egress_input("") is True


def test_the_egress_prompt_validates_what_you_type(q) -> None:
    q.answers["checkbox"] = []
    q.answers["text"] = ""
    picker.pick_egress([], [])
    assert q.calls["text"][0]["validate"] is picker._validate_egress_input


def test_mandatory_hosts_are_shown_but_not_untickable(q) -> None:
    """Offering a tickbox for something that cannot be turned off is a lie."""
    q.answers["checkbox"] = ["pypi.org"]
    q.answers["text"] = ""
    out = picker.pick_egress(["pypi.org"], [], always_on=["api.anthropic.com"])
    offered = [c.value for c in q.calls["checkbox"][0]["choices"]]
    assert "api.anthropic.com" not in offered
    assert "api.anthropic.com" in out


@pytest.mark.parametrize(
    ("value", "needle"),
    [("/etc/passwd", "workspace-relative"), ("../outside", "escape the workspace")],
)
def test_mask_validation_rejects_paths_the_model_would(value: str, needle: str) -> None:
    assert needle in str(picker._validate_mask_input(value))


def test_mask_validation_accepts_a_relative_glob() -> None:
    assert picker._validate_mask_input("secrets/ *.pem") is True


def test_the_mask_row_can_actually_be_set(q) -> None:
    """The old summary printed a `masked` line fed from global defaults while
    the picker never asked for a project mask."""
    q.answers["text"] = "secrets/ *.pem"
    assert picker.pick_masks([".env*"], []) == ["secrets/", "*.pem"]


# -- plain-language help ---------------------------------------------------


def test_every_prompt_explains_itself(q, config, tmp_path) -> None:
    q.answers["select"] = "dev"
    q.answers["checkbox"] = []
    q.answers["text"] = ""
    q.answers["confirm"] = False
    picker.walk_all(_draft(), _ctx(tmp_path, config))
    for kind in ("select", "checkbox", "confirm"):
        for call in q.calls[kind]:
            assert call.get("instruction"), f"{kind}: {call['message']!r} has no instruction"


def test_permission_mode_labels_line_up(q) -> None:
    q.answers["select"] = "default"
    picker.pick_permission_mode()
    titles = [c.title for c in q.calls["select"][0]["choices"]]
    dashes = {t.index("—") for t in titles}
    assert len(dashes) == 1, f"labels are ragged: {titles}"


def test_no_review_row_overflows_an_eighty_column_terminal(q, config, tmp_path) -> None:
    """A row that wraps makes prompt_toolkit's cursor jump on every keystroke."""
    draft = _draft(
        servers=["duckduckgo", "github-official"],
        egress=["a-very-long-registry-hostname.example.com"] * 12,
        context=["/some/deeply/nested/host/path/for/context"] * 4,
        mask=["a/very/long/glob/pattern/**/*.pem"] * 6,
    )
    for choice in picker._hub_choices(draft, _ctx(tmp_path, config)):
        assert len(str(choice.title)) <= picker.HUB_WIDTH, choice.title


# -- the settings that had no interface ------------------------------------


def test_connectors_reads_as_a_second_mcp_path(q, config, tmp_path) -> None:
    """Off by default, and the row has to say why that matters — those tool
    calls never reach the gateway log."""
    ctx = _ctx(tmp_path, config)
    row = next(r for r in picker.ROWS if r.key == "connectors")
    assert row.value(_draft(), ctx) == "off"
    assert "unmediated" in row.value(_draft(connectors=True), ctx)


def test_connectors_round_trips(q, config, tmp_path) -> None:
    q.answers["select"] = "on"
    draft = _draft()
    picker._edit_connectors(draft, _ctx(tmp_path, config))
    assert draft.connectors is True
    q.answers["select"] = "off"
    picker._edit_connectors(draft, _ctx(tmp_path, config))
    assert draft.connectors is False


def test_server_network_offers_only_declared_container_servers(q, config, tmp_path) -> None:
    q.answers["checkbox"] = ["duckduckgo"]
    out = picker.pick_server_network(_catalog(), ["duckduckgo", "github-official"])
    offered = [c.value for c in q.calls["checkbox"][0]["choices"]]
    assert offered == ["duckduckgo", "github-official"]
    assert out == {"duckduckgo": "none"}


def test_a_hosted_server_has_no_container_to_cut_off(q) -> None:
    catalog = Catalog(
        servers={
            "context7": CatalogServer(
                name="context7", remote_url="https://mcp.context7.com/mcp", kind="remote"
            )
        }
    )
    assert picker.pick_server_network(catalog, ["context7"]) == {}
    assert q.calls["checkbox"] == []


def test_the_server_network_row_names_the_default_honestly(q, config, tmp_path) -> None:
    """`shared` puts a server outside the agent's firewall, the SNI proxy and
    the scoped resolver — the row should not read as though it were contained."""
    ctx = _ctx(tmp_path, config)
    row = next(r for r in picker.ROWS if r.key == "server_network")
    assert "outside the firewall" in row.value(_draft(servers=["duckduckgo"]), ctx)
    assert "cut off" in row.value(
        _draft(servers=["duckduckgo"], server_network={"duckduckgo": "none"}), ctx
    )


@pytest.mark.parametrize(
    ("value", "ok"),
    [("3600", True), ("29", False), ("86401", False), ("30", True), ("abc", False), ("", True)],
)
def test_timeout_validation_follows_the_model_bounds(value: str, ok: bool) -> None:
    assert (picker._validate_timeout(value) is True) is ok


def test_a_blank_timeout_keeps_the_current_value(q, config, tmp_path) -> None:
    """A validated prompt still has to survive an empty answer; raising here
    would drop the whole walk."""
    q.answers["text"] = ""
    draft = _draft(timeout=120)
    picker._edit_timeout(draft, _ctx(tmp_path, config))
    assert draft.timeout == 120


def test_timeout_round_trips(q, config, tmp_path) -> None:
    q.answers["text"] = "900"
    draft = _draft()
    picker._edit_timeout(draft, _ctx(tmp_path, config))
    assert draft.timeout == 900


def test_output_round_trips(q, config, tmp_path) -> None:
    q.answers["select"] = "text"
    draft = _draft()
    picker._edit_output(draft, _ctx(tmp_path, config))
    assert draft.output == "text"


def test_seed_draft_carries_the_new_settings_from_an_existing_manifest(
    workspace, config, manifest
) -> None:
    manifest.run.connectors = True
    manifest.run.timeout = 120
    manifest.server_network = {"duckduckgo": "none"}
    draft = picker.seed_draft(
        project="demo", workspace=workspace, config=config, existing=manifest
    )
    assert draft.connectors is True
    assert draft.timeout == 120
    assert draft.server_network == {"duckduckgo": "none"}
