# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from unittest.mock import Mock

import pytest
from click.testing import CliRunner

import gatebroker.cli as cli
from gatebroker import claude_launch, profile


def test_is_claude_command_matches_basename_and_windows_exe() -> None:
    assert claude_launch.is_claude_command(["claude"])
    assert claude_launch.is_claude_command(["/opt/homebrew/bin/claude"])
    assert claude_launch.is_claude_command(["C:\\Tools\\claude.exe"])
    assert claude_launch.is_claude_command(["claude", "--dangerously-skip-permissions"])
    assert not claude_launch.is_claude_command(["codex"])
    assert not claude_launch.is_claude_command([])


def test_launching_claude_names_models_from_the_profile_when_nothing_is_discovered() -> None:
    merged = claude_launch.augment_claude_environment(["claude"], {})

    assert merged["ANTHROPIC_MODEL"] == profile.primary_model()
    assert merged["ANTHROPIC_SMALL_FAST_MODEL"] == profile.small_fast_model()


def test_both_models_are_set_because_background_work_uses_the_small_one() -> None:
    """With only the session model set, background requests fail while it looks healthy."""
    merged = claude_launch.augment_claude_environment(["claude"], {})

    assert "ANTHROPIC_MODEL" in merged
    assert "ANTHROPIC_SMALL_FAST_MODEL" in merged


def test_a_model_the_caller_pinned_is_preserved() -> None:
    merged = claude_launch.augment_claude_environment(
        ["claude"], {"ANTHROPIC_MODEL": "chosen-by-user"}
    )

    assert merged["ANTHROPIC_MODEL"] == "chosen-by-user"
    assert merged["ANTHROPIC_SMALL_FAST_MODEL"] == profile.small_fast_model()


def test_discovered_models_take_precedence_over_the_profile() -> None:
    """The policy decides what is permitted; the profile only ranks and backstops."""
    merged = claude_launch.augment_claude_environment(
        ["claude"], {}, available_models=("policy-only",)
    )

    assert merged["ANTHROPIC_MODEL"] == "policy-only"
    assert merged["ANTHROPIC_SMALL_FAST_MODEL"] == "policy-only"


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
    assert environment["ANTHROPIC_MODEL"] == profile.primary_model()
    assert environment["ANTHROPIC_SMALL_FAST_MODEL"] == profile.small_fast_model()
    assert environment["ANTHROPIC_AUTH_TOKEN"] == "ephemeral-token"


def test_the_profile_roles_are_models_the_profile_declares() -> None:
    declared = {slug for slug, _label in profile.MODELS}

    assert profile.primary_model() in declared
    assert profile.small_fast_model() in declared
