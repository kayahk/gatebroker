# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from unittest.mock import Mock

from click.testing import CliRunner

import gatebroker.cli as cli
from gatebroker import copilot_launch, profile


def test_is_copilot_command_matches_basename_and_windows_exe() -> None:
    assert copilot_launch.is_copilot_command(["copilot"])
    assert copilot_launch.is_copilot_command(["/opt/homebrew/bin/copilot"])
    assert copilot_launch.is_copilot_command(["C:\\Tools\\copilot.exe"])
    assert not copilot_launch.is_copilot_command(["codex"])
    assert not copilot_launch.is_copilot_command([])


def test_copilot_provider_environment_uses_byok_variables() -> None:
    env = copilot_launch.copilot_provider_environment(
        base_url="https://ai-gateway.example/v1", token="ephemeral-token"
    )
    assert env == {
        "COPILOT_PROVIDER_BASE_URL": "https://ai-gateway.example/v1",
        "COPILOT_PROVIDER_TYPE": "openai",
        "COPILOT_PROVIDER_API_KEY": "ephemeral-token",
        "COPILOT_MODEL": profile.default_model(),
    }


def test_augment_copilot_environment_injects_provider_for_copilot() -> None:
    merged = copilot_launch.augment_copilot_environment(
        ["copilot"],
        {"PATH": "/usr/bin", "OPENAI_API_KEY": "ephemeral-token"},
        base_url="https://ai-gateway.example/v1",
        token="ephemeral-token",
    )
    assert merged["COPILOT_PROVIDER_BASE_URL"] == "https://ai-gateway.example/v1"
    assert merged["COPILOT_PROVIDER_TYPE"] == "openai"
    assert merged["COPILOT_PROVIDER_API_KEY"] == "ephemeral-token"
    assert merged["COPILOT_MODEL"] == profile.default_model()
    # Unrelated variables are preserved.
    assert merged["PATH"] == "/usr/bin"


def test_augment_copilot_environment_preserves_user_model_override() -> None:
    merged = copilot_launch.augment_copilot_environment(
        ["copilot"],
        {"COPILOT_MODEL": "operator-pinned-model"},
        base_url="https://ai-gateway.example/v1",
        token="ephemeral-token",
    )
    assert merged["COPILOT_MODEL"] == "operator-pinned-model"


def test_augment_copilot_environment_leaves_non_copilot_unchanged() -> None:
    original = {"PATH": "/usr/bin"}
    merged = copilot_launch.augment_copilot_environment(
        ["codex", "exec"],
        original,
        base_url="https://ai-gateway.example/v1",
        token="ephemeral-token",
    )
    assert merged == original
    assert "COPILOT_PROVIDER_BASE_URL" not in merged


def test_exec_copilot_injects_gateway_provider_environment(monkeypatch, tmp_path) -> None:
    token = "ephemeral-access-token"
    captured: dict[str, object] = {}

    monkeypatch.setattr(cli, "_acquire_access_token", lambda: token)
    monkeypatch.setattr(cli, "_agents_file", lambda: tmp_path / "agents.json")
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda command, check, env: captured.update({"command": command, "env": env})
        or Mock(returncode=0),
    )

    result = CliRunner().invoke(cli.main, ["exec", "--", "copilot"])

    assert result.exit_code == 0
    assert captured["command"] == ["copilot"]
    env = captured["env"]
    assert env["COPILOT_PROVIDER_BASE_URL"] == profile.BASE_URL
    assert env["COPILOT_PROVIDER_TYPE"] == "openai"
    assert env["COPILOT_PROVIDER_API_KEY"] == token
    assert env["COPILOT_MODEL"] == profile.default_model()
    assert token not in result.output


def test_exec_non_copilot_command_has_no_provider_variables(monkeypatch, tmp_path) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(cli, "_acquire_access_token", lambda: "token")
    monkeypatch.setattr(cli, "_agents_file", lambda: tmp_path / "agents.json")
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda command, check, env: captured.update({"command": command, "env": env})
        or Mock(returncode=0),
    )

    result = CliRunner().invoke(cli.main, ["exec", "--", "claude", "--print"])

    assert result.exit_code == 0
    assert "COPILOT_PROVIDER_BASE_URL" not in captured["env"]
