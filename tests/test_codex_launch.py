# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock

from click.testing import CliRunner

import gatebroker.cli as cli
from gatebroker import codex_launch, profile


def test_is_codex_command_matches_basename_and_windows_exe() -> None:
    assert codex_launch.is_codex_command(["codex"])
    assert codex_launch.is_codex_command(["/opt/homebrew/bin/codex", "exec"])
    assert codex_launch.is_codex_command(["C:\\Tools\\codex.exe"])
    assert not codex_launch.is_codex_command(["claude"])
    assert not codex_launch.is_codex_command([])


def test_ensure_codex_model_catalog_uses_fallback_when_cache_missing(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(codex_launch, "codex_home", lambda: tmp_path / "missing-codex-home")
    catalog_path = codex_launch.ensure_codex_model_catalog(tmp_path / "gabro")

    payload = json.loads(catalog_path.read_text(encoding="utf-8"))
    slugs = [model["slug"] for model in payload["models"]]
    assert slugs == [slug for slug, _label in profile.MODELS]
    assert payload["models"][0]["display_name"] == profile.MODELS[0][1]
    assert "base_instructions" in payload["models"][0]


def test_ensure_codex_model_catalog_clones_metadata_from_models_cache(tmp_path, monkeypatch) -> None:
    codex_home = tmp_path / "codex"
    codex_home.mkdir()
    (codex_home / "models_cache.json").write_text(
        json.dumps(
            {
                "models": [
                    {
                        "slug": "gpt-template",
                        "display_name": "Template",
                        "description": "template",
                        "base_instructions": "Keep collaborating until the goal is handled.",
                        "shell_type": "shell_command",
                        "visibility": "list",
                        "supported_in_api": True,
                        "priority": 9,
                        "comp_hash": "drop-me",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(codex_launch, "codex_home", lambda: codex_home)

    catalog_path = codex_launch.ensure_codex_model_catalog(tmp_path / "gabro")
    payload = json.loads(catalog_path.read_text(encoding="utf-8"))

    assert payload["models"][0]["slug"] == profile.default_model()
    assert payload["models"][0]["display_name"] == profile.MODELS[0][1]
    assert payload["models"][0]["base_instructions"] == (
        "Keep collaborating until the goal is handled."
    )
    assert "comp_hash" not in payload["models"][0]


def test_catalog_models_shallow_copies_template_metadata(tmp_path, monkeypatch) -> None:
    nested_metadata = {"source": "models-cache"}
    template = {
        "slug": "gpt-template",
        "display_name": "Template",
        "nested_metadata": nested_metadata,
    }
    monkeypatch.setattr(codex_launch, "_template_model", lambda _: template)

    models = codex_launch._catalog_models(tmp_path / "models_cache.json")

    assert models[0]["nested_metadata"] is nested_metadata


def test_augment_codex_command_injects_provider_catalog_and_default_model(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(codex_launch, "codex_home", lambda: tmp_path / "codex-home")
    command = codex_launch.augment_codex_command(
        ["codex", "exec", "hello"],
        base_url="https://ai-gateway.example/v1",
        config_dir=tmp_path / "gabro",
    )

    assert command[0] == "codex"
    assert command[-2:] == ["exec", "hello"]
    joined = " ".join(command)
    assert 'model_provider="gabro"' in joined
    assert f'model="{profile.default_model()}"' in joined
    assert 'model_providers.gabro.base_url="https://ai-gateway.example/v1"' in joined
    assert 'model_providers.gabro.env_key="OPENAI_API_KEY"' in joined
    assert 'model_providers.gabro.wire_api="responses"' in joined
    assert f'model_catalog_json="{tmp_path / "gabro" / "codex-model-catalog.json"}"' in joined
    assert not codex_launch.augment_codex_command(
        ["claude"],
        base_url="https://ai-gateway.example/v1",
        config_dir=tmp_path / "gabro",
    )[1:]


def test_exec_codex_injects_gateway_provider_overrides(monkeypatch, tmp_path) -> None:
    token = "ephemeral-access-token"
    captured: dict[str, object] = {}
    config_path = tmp_path / "agents.json"

    monkeypatch.setattr(cli, "_acquire_access_token", lambda: token)
    monkeypatch.setattr(cli, "_agents_file", lambda: config_path)
    monkeypatch.setattr(codex_launch, "codex_home", lambda: tmp_path / "codex-home")
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda command, check, env: captured.update({"command": command, "env": env})
        or Mock(returncode=0),
    )

    result = CliRunner().invoke(cli.main, ["exec", "--", "codex", "exec", "ping"])

    assert result.exit_code == 0
    command = captured["command"]
    assert isinstance(command, list)
    assert command[0] == "codex"
    assert command[-2:] == ["exec", "ping"]
    joined = " ".join(command)
    assert 'model_provider="gabro"' in joined
    assert f'model="{profile.default_model()}"' in joined
    assert f'model_providers.gabro.base_url="{profile.BASE_URL}"' in joined
    catalog = Path(tmp_path / "codex-model-catalog.json")
    assert catalog.is_file()
    assert captured["env"]["OPENAI_API_KEY"] == token
    assert token not in result.output


def test_exec_non_codex_command_is_unchanged(monkeypatch, tmp_path) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(cli, "_acquire_access_token", lambda: "token")
    monkeypatch.setattr(cli, "_agents_file", lambda: tmp_path / "agents.json")
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda command, check, env: captured.update({"command": command}) or Mock(returncode=0),
    )

    result = CliRunner().invoke(cli.main, ["exec", "--", "claude", "--print"])

    assert result.exit_code == 0
    assert captured["command"] == ["claude", "--print"]
