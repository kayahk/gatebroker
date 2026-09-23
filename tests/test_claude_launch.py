# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from unittest.mock import Mock

import pytest
from click.testing import CliRunner

import gatebroker.cli as cli
from gatebroker import claude_launch, profile

_CLAUDE_MODEL_VARIABLES = (
    claude_launch.MODEL_VARIABLE,
    claude_launch.SMALL_FAST_MODEL_VARIABLE,
    claude_launch.OPUS_MODEL_VARIABLE,
    claude_launch.SONNET_MODEL_VARIABLE,
    claude_launch.HAIKU_MODEL_VARIABLE,
    claude_launch.FABLE_MODEL_VARIABLE,
    claude_launch.SUBAGENT_MODEL_VARIABLE,
)


def test_is_claude_command_matches_basename_and_windows_exe() -> None:
    assert claude_launch.is_claude_command(["claude"])
    assert claude_launch.is_claude_command(["/opt/homebrew/bin/claude"])
    assert claude_launch.is_claude_command(["C:\\Tools\\claude.exe"])
    assert claude_launch.is_claude_command(["claude", "--dangerously-skip-permissions"])
    assert not claude_launch.is_claude_command(["codex"])
    assert not claude_launch.is_claude_command([])


def test_launching_claude_names_models_from_the_profile_when_nothing_is_discovered() -> None:
    merged = claude_launch.augment_claude_environment(["claude"], {})

    for variable in _CLAUDE_MODEL_VARIABLES:
        assert merged[variable] == profile.primary_model()


def test_every_claude_slot_names_the_same_allowed_model() -> None:
    """Family aliases are not a catalog. One allowed id prevents Plan Mode 403s."""
    merged = claude_launch.augment_claude_environment(["claude"], {})

    declared = {slug for slug, _label in profile.MODELS}
    named = {merged[variable] for variable in _CLAUDE_MODEL_VARIABLES}
    assert named <= declared
    assert len(named) == 1


def test_a_model_the_caller_pinned_is_preserved() -> None:
    merged = claude_launch.augment_claude_environment(
        ["claude"], {"ANTHROPIC_MODEL": "chosen-by-user"}
    )

    assert merged["ANTHROPIC_MODEL"] == "chosen-by-user"
    assert merged["ANTHROPIC_DEFAULT_OPUS_MODEL"] == profile.primary_model()
    assert merged["ANTHROPIC_SMALL_FAST_MODEL"] == profile.primary_model()
    assert merged["ANTHROPIC_DEFAULT_HAIKU_MODEL"] == profile.primary_model()


def test_discovered_models_take_precedence_over_the_profile() -> None:
    """The policy decides what is permitted; the profile only ranks and backstops."""
    merged = claude_launch.augment_claude_environment(
        ["claude"], {}, available_models=("policy-only",)
    )

    for variable in _CLAUDE_MODEL_VARIABLES:
        assert merged[variable] == "policy-only"


def test_claude_launch_pins_all_claude_aliases_to_entitled_models() -> None:
    merged = claude_launch.augment_claude_environment(
        ["claude"], {}, available_models=("allowed-primary", "allowed-fast")
    )

    named = {merged[variable] for variable in _CLAUDE_MODEL_VARIABLES}
    assert named == {"allowed-primary"}


@pytest.mark.parametrize("variable", _CLAUDE_MODEL_VARIABLES)
def test_claude_launch_rejects_unentitled_alias_pin(variable: str) -> None:
    merged = claude_launch.augment_claude_environment(
        ["claude"],
        {variable: "not-entitled"},
        available_models=("allowed-primary", "allowed-fast"),
    )

    assert merged[variable] != "not-entitled"
    assert merged[variable] in {"allowed-primary", "allowed-fast"}


def test_entitled_haiku_pin_wins_over_unentitled_small_fast_pin() -> None:
    merged = claude_launch.augment_claude_environment(
        ["claude"],
        {
            claude_launch.SMALL_FAST_MODEL_VARIABLE: "not-entitled",
            claude_launch.HAIKU_MODEL_VARIABLE: "allowed-fast",
        },
        available_models=("allowed-primary", "allowed-fast"),
    )

    assert merged[claude_launch.SMALL_FAST_MODEL_VARIABLE] == "allowed-fast"
    assert merged[claude_launch.HAIKU_MODEL_VARIABLE] == "allowed-fast"


def test_haiku_pin_also_fills_the_deprecated_small_fast_variable() -> None:
    merged = claude_launch.augment_claude_environment(
        ["claude"],
        {claude_launch.HAIKU_MODEL_VARIABLE: "chosen-by-user"},
    )

    assert merged[claude_launch.HAIKU_MODEL_VARIABLE] == "chosen-by-user"
    assert merged[claude_launch.SMALL_FAST_MODEL_VARIABLE] == "chosen-by-user"


def test_other_commands_are_left_alone() -> None:
    merged = claude_launch.augment_claude_environment(["codex"], {"KEEP": "value"})

    assert merged == {"KEEP": "value"}


@pytest.mark.parametrize("argv", [["claude"], ["claude", "--dangerously-skip-permissions"]])
def test_exec_claude_needs_no_shell_wrapper(monkeypatch, argv) -> None:
    """`gabro exec -- claude` must be enough on its own."""
    captured: dict[str, object] = {}
    monkeypatch.setattr(cli, "_acquire_access_token", lambda: "ephemeral-token")
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda command, check, env: captured.update({"command": command, "env": env})
        or Mock(returncode=0),
    )

    result = CliRunner().invoke(cli.main, ["exec", "--", *argv])

    assert result.exit_code == 0
    assert captured["command"] == argv
    environment = captured["env"]
    for variable in _CLAUDE_MODEL_VARIABLES:
        assert environment[variable] == profile.primary_model()
    assert environment["ANTHROPIC_AUTH_TOKEN"] == "ephemeral-token"


def test_the_profile_roles_are_models_the_profile_declares() -> None:
    declared = {slug for slug, _label in profile.MODELS}

    assert profile.primary_model() in declared
    assert profile.small_fast_model() in declared
