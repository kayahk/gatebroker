# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock

import click
import pytest
from click.testing import CliRunner

import gatebroker.cli as cli
from gatebroker import profile


@pytest.fixture(autouse=True)
def approved_credential_store(monkeypatch, request) -> None:
    """Keep command behavior tests independent of the CI runner's keyring backend."""
    stored: dict[tuple[str, str], str] = {}
    monkeypatch.setattr(
        cli.keyring,
        "get_password",
        lambda service, account: stored.get((service, account)),
    )
    monkeypatch.setattr(
        cli.keyring,
        "set_password",
        lambda service, account, value: stored.__setitem__((service, account), value),
    )
    if request.node.name != "test_rejects_an_unapproved_credential_store_backend":
        monkeypatch.setattr(cli, "_require_secure_keyring", lambda: None)


def test_login_uses_device_flow_and_never_prints_access_token(monkeypatch) -> None:
    token = "access-token-must-not-appear-in-output"
    cache = Mock()
    cache.serialize.return_value = json.dumps(
        {
            "AccessToken": {"access": "access-token-must-not-appear-in-output"},
            "IdToken": {"identity": "id-token-must-not-be-stored"},
            "RefreshToken": {"refresh": "refresh-state"},
        }
    )
    application = Mock()
    application.initiate_device_flow.return_value = {
        "message": "Open the verification page and enter the displayed code.",
        "user_code": "device-code",
        "verification_uri": "https://login.microsoft.com/device",
    }
    application.acquire_token_by_device_flow.return_value = {"access_token": token}
    stored: dict[str, str] = {}
    opened_urls: list[str] = []
    copied_codes: list[str] = []

    monkeypatch.setattr(cli, "_load_cache", lambda: cache)
    monkeypatch.setattr(cli, "_application", lambda _cache: application)
    monkeypatch.setattr(cli.keyring, "set_password", lambda service, account, value: stored.update({account: value}))
    monkeypatch.setattr(cli.click, "launch", lambda url: opened_urls.append(url) or True)
    monkeypatch.setattr(cli, "_copy_device_code", lambda code: copied_codes.append(code) or True, raising=False)

    result = CliRunner().invoke(cli.main, ["login"])

    assert result.exit_code == 0
    assert "\x1b]8;;https://login.microsoft.com/device\x1b\\" in result.output
    assert "https://login.microsoft.com/device\x1b]8;;\x1b\\" in result.output
    assert "enter the code device-code" in result.output
    assert "The device code has been copied to your clipboard. Paste it into the Entra page." in result.output
    assert copied_codes == ["device-code"]
    assert "Opened the Entra sign-in page in your browser." in result.output
    assert opened_urls == ["https://login.microsoft.com/device"]
    assert "Authentication completed." in result.output
    assert profile.BASE_URL in result.output
    assert token not in result.output
    assert stored == {cli.CACHE_ACCOUNT: '{"RefreshToken":{"refresh":"refresh-state"}}'}
    application.acquire_token_by_device_flow.assert_called_once()


def test_login_keeps_manual_device_code_instructions_when_clipboard_copy_fails(monkeypatch) -> None:
    cache = Mock()
    cache.serialize.return_value = "{}"
    application = Mock()
    application.initiate_device_flow.return_value = {
        "message": "Open the verification page and enter the displayed code.",
        "user_code": "device-code",
        "verification_uri": "https://login.microsoft.com/device",
    }
    application.acquire_token_by_device_flow.return_value = {"access_token": "token"}

    monkeypatch.setattr(cli, "_load_cache", lambda: cache)
    monkeypatch.setattr(cli, "_application", lambda _cache: application)
    monkeypatch.setattr(cli.keyring, "set_password", lambda *args: None)
    monkeypatch.setattr(cli, "_copy_device_code", lambda code: False, raising=False)
    monkeypatch.setattr(cli.click, "launch", lambda url: False)

    result = CliRunner().invoke(cli.main, ["login"])

    assert result.exit_code == 0
    assert "enter the code device-code" in result.output
    assert "The device code has been copied to your clipboard." not in result.output


def test_login_with_agent_configures_matching_launcher_profile(monkeypatch, tmp_path) -> None:
    cache = Mock()
    cache.has_state_changed = True
    cache.serialize.return_value = '{"RefreshToken":{"refresh":"refresh-state"}}'
    application = Mock()
    application.initiate_device_flow.return_value = {
        "message": "Open the verification page and enter the displayed code.",
        "user_code": "device-code",
        "verification_uri": "https://login.microsoft.com/device",
    }
    application.acquire_token_by_device_flow.return_value = {"access_token": "token"}
    config_path = tmp_path / "agents.json"

    launched: list[list[str]] = []

    def fake_run(command: list[str]) -> None:
        launched.append(list(command))
        raise SystemExit(17)

    monkeypatch.setattr(cli, "_load_cache", lambda: cache)
    monkeypatch.setattr(cli, "_application", lambda _cache: application)
    monkeypatch.setattr(cli, "_copy_device_code", lambda code: False, raising=False)
    monkeypatch.setattr(cli.click, "launch", lambda url: False)
    monkeypatch.setattr(cli, "_agents_file", lambda: config_path)
    monkeypatch.setattr(cli, "_run_with_broker_environment", fake_run)

    result = CliRunner().invoke(cli.main, ["login", "opencode"])

    assert result.exit_code == 17
    assert "Authentication completed." in result.output
    assert "Configured local agent 'opencode'." in result.output
    assert "gabro run opencode" in result.output
    assert cli._load_agents() == {"opencode": ["opencode"]}
    assert launched == [["opencode"]]


def test_login_rejects_agent_names_that_look_like_flags(monkeypatch) -> None:
    monkeypatch.setattr(cli, "_device_code_login", Mock())

    result = CliRunner().invoke(cli.main, ["login", "--", "-opencode"])

    assert result.exit_code != 0
    assert "Agent names must not start with '-'." in result.output
    cli._device_code_login.assert_not_called()


def test_login_rejects_an_empty_agent_name_before_device_login(monkeypatch) -> None:
    monkeypatch.setattr(cli, "_device_code_login", Mock())

    result = CliRunner().invoke(cli.main, ["login", ""])

    assert result.exit_code != 0
    assert "Agent names must not be empty." in result.output
    cli._device_code_login.assert_not_called()


def test_login_with_agent_validates_existing_profile_before_device_login(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "agents.json"
    config_path.write_text('{"agents":{"claude":["claude"]}}', encoding="utf-8")
    monkeypatch.setattr(cli, "_agents_file", lambda: config_path)
    monkeypatch.setattr(cli, "_device_code_login", Mock())

    result = CliRunner().invoke(cli.main, ["login", "opencode"])

    assert result.exit_code != 0
    assert "local agent configuration is invalid" in result.output
    cli._device_code_login.assert_not_called()


def test_exec_injects_ephemeral_openai_environment_without_printing_token(monkeypatch) -> None:
    token = "ephemeral-access-token-must-not-appear-in-output"
    captured: dict[str, object] = {}

    monkeypatch.setattr(cli, "_acquire_access_token", lambda: token)
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda command, check, env: captured.update({"command": command, "env": env}) or Mock(returncode=17),
    )

    result = CliRunner().invoke(cli.main, ["exec", "--", "python", "-c", "pass"])

    assert result.exit_code == 17
    assert result.output == ""
    assert captured["command"] == ["python", "-c", "pass"]
    assert captured["env"]["OPENAI_API_KEY"] == token
    assert captured["env"]["OPENAI_BASE_URL"] == profile.BASE_URL
    assert captured["env"]["ANTHROPIC_AUTH_TOKEN"] == token
    assert captured["env"]["ANTHROPIC_BASE_URL"] == profile.BASE_URL.removesuffix("/v1")
    assert token not in result.output


def test_exec_derives_anthropic_base_url_from_the_reviewed_gateway_profile(monkeypatch) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(cli, "_settings", lambda: ("tenant", "client", "scope", "https://gateway.example/v1"))
    monkeypatch.setattr(cli, "_acquire_access_token", lambda: "ephemeral-token")
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda command, check, env: captured.update({"env": env}) or Mock(returncode=0),
    )

    result = CliRunner().invoke(cli.main, ["exec", "--", "agent"])

    assert result.exit_code == 0
    assert captured["env"]["OPENAI_BASE_URL"] == "https://gateway.example/v1"
    assert captured["env"]["ANTHROPIC_BASE_URL"] == "https://gateway.example"


def test_agents_file_falls_back_when_xdg_config_home_is_empty(monkeypatch) -> None:
    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setenv("XDG_CONFIG_HOME", "")

    assert cli._agents_file() == Path.home() / ".config" / "gabro" / "agents.json"


def test_configure_and_run_named_agent_without_persisting_a_token(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "agents.json"
    captured: dict[str, object] = {}
    token = "ephemeral-access-token-must-not-appear-in-config"

    monkeypatch.setattr(cli, "_agents_file", lambda: config_path)
    monkeypatch.setattr(cli, "_acquire_access_token", lambda: token)
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda command, check, env: captured.update({"command": command, "env": env}) or Mock(returncode=0),
    )

    runner = CliRunner()
    configured = runner.invoke(cli.main, ["configure", "claude", "--", "claude", "--full-auto"])
    result = runner.invoke(cli.main, ["run", "claude", "--", "--model", "gpt-5"])

    assert configured.exit_code == 0
    assert "Configured local agent 'claude'." in configured.output
    assert result.exit_code == 0
    assert result.output == ""
    assert captured["command"] == ["claude", "--full-auto", "--model", "gpt-5"]
    assert captured["env"]["OPENAI_API_KEY"] == token
    assert captured["env"]["OPENAI_BASE_URL"] == profile.BASE_URL
    assert token not in config_path.read_text(encoding="utf-8")
    saved = json.loads(config_path.read_text(encoding="utf-8"))
    assert saved["agents"] == {"claude": ["claude", "--full-auto"]}
    assert isinstance(saved["mac"], str)
    assert len(saved["mac"]) == 64


def test_run_requires_a_configured_agent(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(cli, "_agents_file", lambda: tmp_path / "agents.json")

    result = CliRunner().invoke(cli.main, ["run", "claude"])

    assert result.exit_code != 0
    assert "Local agent 'claude' is not configured." in result.output
    assert "gabro configure claude -- claude" in result.output


def test_run_rejects_a_group_or_world_writable_agent_profile_on_unix(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "agents.json"
    config_path.write_text('{"agents":{"claude":["claude"]}}', encoding="utf-8")
    config_path.chmod(0o666)
    monkeypatch.setattr(cli, "_agents_file", lambda: config_path)
    monkeypatch.setattr(cli.sys, "platform", "linux")

    result = CliRunner().invoke(cli.main, ["run", "claude"])

    assert result.exit_code != 0
    assert "local agent configuration is invalid" in result.output


def test_run_rejects_an_unsigned_profile_on_windows(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "agents.json"
    config_path.write_text('{"agents":{"claude":["claude"]}}', encoding="utf-8")
    config_path.chmod(0o666)
    monkeypatch.setattr(cli, "_agents_file", lambda: config_path)
    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli, "_acquire_access_token", lambda: "ephemeral-token")
    monkeypatch.setattr(cli.subprocess, "run", lambda command, check, env: Mock(returncode=0))

    result = CliRunner().invoke(cli.main, ["run", "claude"])

    assert result.exit_code != 0
    assert "local agent configuration is invalid" in result.output


def test_configure_reset_replaces_an_unsigned_legacy_profile(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "agents.json"
    config_path.write_text('{"agents":{"legacy":["legacy"]}}', encoding="utf-8")
    monkeypatch.setattr(cli, "_agents_file", lambda: config_path)

    result = CliRunner().invoke(
        cli.main,
        ["configure", "--reset", "replacement", "--", "trusted-command"],
    )

    assert result.exit_code == 0
    assert cli._load_agents() == {"replacement": ["trusted-command"]}


def test_run_rejects_a_tampered_signed_profile(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "agents.json"
    monkeypatch.setattr(cli, "_agents_file", lambda: config_path)

    runner = CliRunner()
    assert runner.invoke(cli.main, ["configure", "agent", "--", "trusted"]).exit_code == 0
    profile = json.loads(config_path.read_text(encoding="utf-8"))
    profile["agents"]["agent"] = ["attacker-controlled"]
    config_path.write_text(json.dumps(profile), encoding="utf-8")

    result = runner.invoke(cli.main, ["run", "agent"])

    assert result.exit_code != 0
    assert "local agent configuration is invalid" in result.output


def test_silent_token_acquisition_rejects_multiple_cached_accounts(monkeypatch) -> None:
    application = Mock()
    application.get_accounts.return_value = [{"id": "one"}, {"id": "two"}]
    monkeypatch.setattr(cli, "_load_cache", Mock())
    monkeypatch.setattr(cli, "_application", lambda _cache: application)

    with pytest.raises(click.ClickException, match="Multiple cached Entra accounts"):
        cli._acquire_access_token()

    application.acquire_token_silent.assert_not_called()


def test_exec_reports_a_missing_child_command_without_a_traceback(monkeypatch) -> None:
    token = "ephemeral-access-token-must-not-appear-in-output"
    monkeypatch.setattr(cli, "_acquire_access_token", lambda: token)
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        Mock(side_effect=FileNotFoundError()),
    )

    result = CliRunner().invoke(cli.main, ["exec", "--", "claude-code"])

    assert result.exit_code != 0
    assert "Command not found: claude-code." in result.output
    assert "Install it or pass its full path." in result.output
    assert "Traceback" not in result.output
    assert token not in result.output


def test_exec_reports_other_os_errors_without_a_traceback(monkeypatch) -> None:
    monkeypatch.setattr(cli, "_acquire_access_token", lambda: "token")
    monkeypatch.setattr(cli.subprocess, "run", Mock(side_effect=PermissionError("not executable")))

    result = CliRunner().invoke(cli.main, ["exec", "--", "not-executable"])

    assert result.exit_code != 0
    assert "Could not run command: not-executable." in result.output
    assert "Traceback" not in result.output



def test_logout_removes_only_the_secure_token_cache(monkeypatch) -> None:
    deleted: list[tuple[str, str]] = []
    monkeypatch.setattr(cli.keyring, "get_password", lambda service, account: "serialized-cache")
    monkeypatch.setattr(cli.keyring, "delete_password", lambda service, account: deleted.append((service, account)))

    result = CliRunner().invoke(cli.main, ["logout"])

    assert result.exit_code == 0
    assert result.output == "Signed out. Local GateBroker sign-in state has been removed.\n"
    assert deleted == [(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)]


def test_logout_reports_when_no_local_sign_in_state_exists(monkeypatch) -> None:
    monkeypatch.setattr(cli.keyring, "get_password", lambda service, account: None)

    result = CliRunner().invoke(cli.main, ["logout"])

    assert result.exit_code == 0
    assert result.output == "No local GateBroker sign-in state was found.\n"


def test_settings_ignore_untrusted_environment_overrides(monkeypatch) -> None:
    monkeypatch.setenv("GABRO_BASE_URL", "https://attacker.example/v1")
    monkeypatch.setenv("GABRO_SCOPE", "api://attacker/access_as_user")

    assert cli._settings() == (
        profile.TENANT_ID,
        profile.CLIENT_ID,
        profile.SCOPE,
        profile.BASE_URL,
    )


def test_failed_silent_refresh_persists_changed_cache_before_requiring_login(monkeypatch) -> None:
    cache = Mock()
    cache.has_state_changed = True
    cache.serialize.return_value = '{"RefreshToken":{"refresh":"cleaned-refresh-state"}}'
    application = Mock()
    application.get_accounts.return_value = [object()]
    application.acquire_token_silent.return_value = {}
    saved: dict[str, str] = {}

    monkeypatch.setattr(cli, "_load_cache", lambda: cache)
    monkeypatch.setattr(cli, "_application", lambda _cache: application)
    monkeypatch.setattr(cli.keyring, "set_password", lambda service, account, value: saved.update({account: value}))

    with pytest.raises(click.ClickException, match="run gabro login"):
        cli._acquire_access_token()

    assert saved == {cli.CACHE_ACCOUNT: '{"RefreshToken":{"refresh":"cleaned-refresh-state"}}'}


def test_logout_surfaces_a_failed_delete_for_an_existing_cache(monkeypatch) -> None:
    monkeypatch.setattr(cli.keyring, "get_password", lambda service, account: "serialized-cache")
    monkeypatch.setattr(cli.keyring, "delete_password", Mock(side_effect=cli.PasswordDeleteError("denied")))

    result = CliRunner().invoke(cli.main, ["logout"])

    assert result.exit_code != 0
    assert "credential store is unavailable" in result.output
    assert "denied" not in result.output


def test_load_cache_rewrites_legacy_access_and_id_tokens_before_use(monkeypatch) -> None:
    legacy_cache = json.dumps(
        {
            "AccessToken": {"old-access": "legacy-access-token"},
            "IdToken": {"old-id": "legacy-id-token"},
            "RefreshToken": {"refresh": "refresh-state"},
        }
    )
    stored: dict[str, str] = {}
    monkeypatch.setattr(cli.keyring, "get_password", lambda service, account: legacy_cache)
    monkeypatch.setattr(cli.keyring, "set_password", lambda service, account, value: stored.update({account: value}))

    cli._load_cache()

    assert stored == {cli.CACHE_ACCOUNT: '{"RefreshToken":{"refresh":"refresh-state"}}'}
    assert "legacy-access-token" not in stored[cli.CACHE_ACCOUNT]
    assert "legacy-id-token" not in stored[cli.CACHE_ACCOUNT]


def test_rejects_an_unapproved_credential_store_backend(monkeypatch) -> None:
    insecure_backend = type("InsecureBackend", (), {"__module__": "keyring.backends.file"})()
    monkeypatch.setattr(cli.keyring, "get_keyring", lambda: insecure_backend)

    with pytest.raises(click.ClickException, match="No supported operating-system credential store"):
        cli._require_secure_keyring()


def test_load_cache_scrubs_legacy_tokens_even_when_deserialization_fails(monkeypatch) -> None:
    legacy_cache = json.dumps(
        {
            "AccessToken": {"old-access": "legacy-access-token"},
            "IdToken": {"old-id": "legacy-id-token"},
            "RefreshToken": {"refresh": "refresh-state"},
        }
    )
    stored: dict[str, str] = {}

    class InvalidCache:
        def deserialize(self, _serialized: str) -> None:
            raise ValueError("malformed")

    monkeypatch.setattr(cli.msal, "SerializableTokenCache", InvalidCache)
    monkeypatch.setattr(cli.keyring, "get_password", lambda service, account: legacy_cache)
    monkeypatch.setattr(cli.keyring, "set_password", lambda service, account, value: stored.update({account: value}))

    with pytest.raises(click.ClickException, match="stored sign-in state is invalid"):
        cli._load_cache()

    assert stored == {cli.CACHE_ACCOUNT: '{"RefreshToken":{"refresh":"refresh-state"}}'}


def test_unconfigured_distribution_refuses_to_acquire_a_token(monkeypatch) -> None:
    """A build that still carries the placeholder profile must not mint a token."""
    monkeypatch.setattr(profile, "CONFIGURED", False)

    result = CliRunner().invoke(cli.main, ["exec", "--", "claude"])

    assert result.exit_code != 0
    assert "no distribution profile" in result.output
    assert profile.BASE_URL not in result.output
