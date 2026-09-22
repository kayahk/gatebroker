# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from contextlib import contextmanager
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
    assert "The device code has been copied to your clipboard. Paste it into the sign-in page." in result.output
    assert copied_codes == ["device-code"]
    assert "Opened the sign-in page in your browser." in result.output
    assert opened_urls == ["https://login.microsoft.com/device"]
    assert "Authentication completed." in result.output
    assert profile.BASE_URL in result.output
    assert token not in result.output
    assert stored == {
        cli.CACHE_ACCOUNT: (
            '{"AccessToken":{"access":"access-token-must-not-appear-in-output"},'
            '"RefreshToken":{"refresh":"refresh-state"}}'
        )
    }
    assert "id-token-must-not-be-stored" not in stored[cli.CACHE_ACCOUNT]
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

    with pytest.raises(click.ClickException, match="Multiple cached accounts"):
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



def _memory_keyring(monkeypatch) -> dict[tuple[str, str], str]:
    stored: dict[tuple[str, str], str] = {}
    monkeypatch.setattr(cli.keyring, "get_password", lambda service, account: stored.get((service, account)))
    monkeypatch.setattr(
        cli.keyring,
        "set_password",
        lambda service, account, value: stored.__setitem__((service, account), value),
    )
    monkeypatch.setattr(
        cli.keyring,
        "delete_password",
        lambda service, account: stored.pop((service, account), None),
    )
    return stored


@contextmanager
def _no_windows_cache_lock():
    yield


def test_windows_small_cache_stays_in_the_primary_keyring_entry(monkeypatch) -> None:
    stored = _memory_keyring(monkeypatch)
    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli, "_windows_cache_lock", _no_windows_cache_lock, raising=False)

    cli._store_cache('{"RefreshToken":{"refresh":"state"}}')

    assert stored == {(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT): '{"RefreshToken":{"refresh":"state"}}'}


def test_windows_payload_above_chunk_slack_is_split(monkeypatch) -> None:
    stored = _memory_keyring(monkeypatch)
    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli, "_windows_cache_lock", _no_windows_cache_lock, raising=False)
    payload = "x" * (cli._WINDOWS_CACHE_CHUNK_BYTES // 2 + 1)

    cli._store_cache(payload)

    manifest = json.loads(stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)])[cli._WINDOWS_CACHE_MANIFEST_KEY]
    assert manifest["count"] >= 2
    assert cli._load_windows_chunked_cache(stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)]) == payload


def test_windows_small_write_keeps_old_manifest_when_cleanup_fails(monkeypatch) -> None:
    stored = _memory_keyring(monkeypatch)
    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli, "_windows_cache_lock", _no_windows_cache_lock, raising=False)
    cli._store_cache("x" * (cli._WINDOWS_CREDENTIAL_MAX_BYTES // 2 + 1))
    old_manifest = stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)]
    old = json.loads(old_manifest)[cli._WINDOWS_CACHE_MANIFEST_KEY]
    real_delete = cli.keyring.delete_password

    def delete_password(service, account):
        if account == cli._cache_chunk_account(old["generation"], 0):
            raise OSError("sensitive backend failure")
        real_delete(service, account)

    monkeypatch.setattr(cli.keyring, "delete_password", delete_password)
    cli._store_cache('{"RefreshToken":{"refresh":"state"}}')

    assert stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)] == '{"RefreshToken":{"refresh":"state"}}'
    pending = json.loads(stored[(cli.CACHE_SERVICE, cli._WINDOWS_CACHE_CLEANUP_ACCOUNT)])
    assert pending["cleanup"] == [{"generation": old["generation"], "count": old["count"]}]


def test_windows_cache_splits_utf16_and_reassembles(monkeypatch) -> None:
    stored = _memory_keyring(monkeypatch)
    payload = "😀" * (cli._WINDOWS_CREDENTIAL_MAX_BYTES // 4 + 1)
    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli, "_windows_cache_lock", _no_windows_cache_lock, raising=False)

    cli._store_cache(payload)

    manifest = json.loads(stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)])[cli._WINDOWS_CACHE_MANIFEST_KEY]
    assert manifest["count"] == 2
    assert all(len(value.encode("utf-16-le")) <= cli._WINDOWS_CACHE_CHUNK_BYTES for (service, account), value in stored.items() if account != cli.CACHE_ACCOUNT)
    assert cli._load_windows_chunked_cache(stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)]) == payload


@pytest.mark.parametrize("count", [True, 0, 1_025])
def test_windows_invalid_manifest_counts_fail_closed(monkeypatch, count) -> None:
    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli, "_windows_cache_lock", _no_windows_cache_lock, raising=False)
    monkeypatch.setattr(cli, "_invocation", lambda: "gabro")
    document = json.dumps({cli._WINDOWS_CACHE_MANIFEST_KEY: {"generation": "a" * 32, "count": count}})

    with pytest.raises(click.ClickException, match="stored sign-in state is invalid"):
        cli._load_windows_chunked_cache(document)


def test_windows_escaped_manifest_key_fails_closed(monkeypatch) -> None:
    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli, "_windows_cache_lock", _no_windows_cache_lock, raising=False)
    monkeypatch.setattr(cli, "_invocation", lambda: "gabro")
    document = '{"windows-cache-ch\\u0075nks":{"generation":"bad","count":1}}'

    with pytest.raises(click.ClickException, match="stored sign-in state is invalid"):
        cli._load_windows_chunked_cache(document)


def test_windows_large_to_small_primary_write_failure_preserves_old_chunks(monkeypatch) -> None:
    stored = _memory_keyring(monkeypatch)
    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli, "_windows_cache_lock", _no_windows_cache_lock, raising=False)
    cli._store_cache("x" * (cli._WINDOWS_CREDENTIAL_MAX_BYTES // 2 + 1))
    old_primary = stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)]
    old_accounts = set(stored)
    real_set = cli.keyring.set_password

    def fail_small_primary(service, account, value):
        if account == cli.CACHE_ACCOUNT and value == "small":
            raise OSError("primary write failed")
        real_set(service, account, value)

    monkeypatch.setattr(cli.keyring, "set_password", fail_small_primary)
    with pytest.raises(click.ClickException, match="credential store is unavailable"):
        cli._store_cache("small")

    assert stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)] == old_primary
    assert set(stored) == old_accounts


def test_windows_partial_write_rollback_cleanup_failure_is_recorded_for_retry(monkeypatch) -> None:
    stored = _memory_keyring(monkeypatch)
    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli, "_windows_cache_lock", _no_windows_cache_lock, raising=False)
    cli._store_cache("x" * (cli._WINDOWS_CREDENTIAL_MAX_BYTES // 2 + 1))
    old_manifest = json.loads(stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)])[cli._WINDOWS_CACHE_MANIFEST_KEY]
    new_generation = "b" * 32
    new_account = cli._cache_chunk_account(new_generation, 0)
    real_set = cli.keyring.set_password
    real_delete = cli.keyring.delete_password

    monkeypatch.setattr(cli.secrets, "token_hex", lambda _count: new_generation)

    def fail_second_chunk(service, account, value):
        if account == cli._cache_chunk_account(new_generation, 1):
            raise OSError("chunk write failed")
        real_set(service, account, value)

    def fail_rollback_cleanup(service, account):
        if account == new_account:
            raise OSError("cleanup failed")
        real_delete(service, account)

    monkeypatch.setattr(cli.keyring, "set_password", fail_second_chunk)
    monkeypatch.setattr(cli.keyring, "delete_password", fail_rollback_cleanup)
    with pytest.raises(click.ClickException, match="credential store is unavailable"):
        cli._store_cache("y" * (cli._WINDOWS_CREDENTIAL_MAX_BYTES // 2 + 1))

    pending = json.loads(stored[(cli.CACHE_SERVICE, cli._WINDOWS_CACHE_CLEANUP_ACCOUNT)])
    assert {item["generation"] for item in pending["cleanup"]} == {old_manifest["generation"], new_generation}
    assert next(item["count"] for item in pending["cleanup"] if item["generation"] == new_generation) == 2
    assert (cli.CACHE_SERVICE, new_account) in stored


def test_windows_load_reads_primary_and_chunks_under_one_lock(monkeypatch) -> None:
    events: list[str] = []
    lock_held = False

    @contextmanager
    def tracking_lock():
        nonlocal lock_held
        events.append("lock")
        lock_held = True
        try:
            yield
        finally:
            lock_held = False
            events.append("unlock")

    manifest = cli._windows_cache_manifest_document("a" * 32, 1, [])
    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli, "_windows_cache_lock", tracking_lock)
    monkeypatch.setattr(cli.keyring, "get_password", lambda service, account: events.append(f"get:{account}:{lock_held}") or (manifest if account == cli.CACHE_ACCOUNT else '{"RefreshToken":{}}'))

    cli._load_cache()

    assert f"get:{cli.CACHE_ACCOUNT}:True" in events
    assert events == ["lock", f"get:{cli.CACHE_ACCOUNT}:True", f"get:{cli._cache_chunk_account('a' * 32, 0)}:True", "unlock"]


def test_windows_partial_write_preserves_old_cache_and_cleans_new_chunks(monkeypatch) -> None:
    stored = _memory_keyring(monkeypatch)
    old = "old cache"
    payload = "x" * (cli._WINDOWS_CREDENTIAL_MAX_BYTES // 2 + 1)
    calls = 0
    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli, "_windows_cache_lock", _no_windows_cache_lock, raising=False)
    stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)] = old

    def set_password(service, account, value):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("sensitive backend failure")
        stored[(service, account)] = value

    monkeypatch.setattr(cli.keyring, "set_password", set_password)

    with pytest.raises(click.ClickException, match="credential store is unavailable") as raised:
        cli._store_cache(payload)

    assert old == stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)]
    assert all("sensitive backend failure" not in str(error) for error in [raised.value])
    assert stored[(cli.CACHE_SERVICE, cli._WINDOWS_CACHE_CLEANUP_ACCOUNT)]


def test_windows_manifest_switches_only_after_all_chunks_are_written(monkeypatch) -> None:
    stored = _memory_keyring(monkeypatch)
    events: list[str] = []
    payload = "x" * (cli._WINDOWS_CREDENTIAL_MAX_BYTES // 2 + 1)
    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli, "_windows_cache_lock", _no_windows_cache_lock, raising=False)

    def set_password(service, account, value):
        events.append(account)
        stored[(service, account)] = value

    monkeypatch.setattr(cli.keyring, "set_password", set_password)
    cli._store_cache(payload)

    manifest_indices = [index for index, account in enumerate(events) if account == cli.CACHE_ACCOUNT]
    assert manifest_indices[0] == len([account for account in events if "-chunk-" in account])
    assert all("-chunk-" in account for account in events[:manifest_indices[0]])


def test_windows_cleanup_failure_is_recorded_and_retried(monkeypatch) -> None:
    stored = _memory_keyring(monkeypatch)
    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli, "_windows_cache_lock", _no_windows_cache_lock, raising=False)
    cli._store_cache("a" * (cli._WINDOWS_CREDENTIAL_MAX_BYTES // 2 + 1))
    old_manifest = json.loads(stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)])[cli._WINDOWS_CACHE_MANIFEST_KEY]
    old_chunks = [cli._cache_chunk_account(old_manifest["generation"], index) for index in range(old_manifest["count"])]
    real_delete = cli.keyring.delete_password
    failed_once = True

    def delete_password(service, account):
        nonlocal failed_once
        if account == old_chunks[0] and failed_once:
            failed_once = False
            raise OSError("sensitive backend failure")
        real_delete(service, account)

    monkeypatch.setattr(cli.keyring, "delete_password", delete_password)
    cli._store_cache("b" * (cli._WINDOWS_CREDENTIAL_MAX_BYTES // 2 + 1))
    current = json.loads(stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)])[cli._WINDOWS_CACHE_MANIFEST_KEY]
    assert current["generation"] != old_manifest["generation"]
    cli._store_cache("c" * (cli._WINDOWS_CREDENTIAL_MAX_BYTES // 2 + 1))
    cli._store_cache("d" * (cli._WINDOWS_CREDENTIAL_MAX_BYTES // 2 + 1))
    assert all((cli.CACHE_SERVICE, account) not in stored for account in old_chunks)


def test_windows_logout_removes_manifest_chunks(monkeypatch) -> None:
    stored = _memory_keyring(monkeypatch)
    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli, "_windows_cache_lock", _no_windows_cache_lock, raising=False)
    cli._store_cache("x" * (cli._WINDOWS_CREDENTIAL_MAX_BYTES // 2 + 1))

    result = CliRunner().invoke(cli.main, ["logout"])

    assert result.exit_code == 0
    assert stored == {}


def test_windows_keyring_and_os_errors_are_sanitized(monkeypatch) -> None:
    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli, "_windows_cache_lock", _no_windows_cache_lock, raising=False)
    monkeypatch.setattr(cli.keyring, "get_password", Mock(side_effect=OSError("secret backend detail")))

    with pytest.raises(click.ClickException, match="credential store is unavailable") as raised:
        cli._load_cache()

    assert "secret backend detail" not in str(raised.value)


def test_logout_removes_only_the_secure_token_cache(monkeypatch) -> None:
    deleted: list[tuple[str, str]] = []
    monkeypatch.setattr(
        cli.keyring,
        "get_password",
        lambda service, account: "serialized-cache" if account == cli.CACHE_ACCOUNT else None,
    )
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
    application.acquire_token_silent_with_error.return_value = {}
    saved: dict[str, str] = {}

    monkeypatch.setattr(cli, "_load_cache", lambda: cache)
    monkeypatch.setattr(cli, "_application", lambda _cache: application)
    monkeypatch.setattr(cli.keyring, "set_password", lambda service, account, value: saved.update({account: value}))

    with pytest.raises(click.ClickException, match="run gabro login"):
        cli._acquire_access_token()

    assert saved == {cli.CACHE_ACCOUNT: '{"RefreshToken":{"refresh":"cleaned-refresh-state"}}'}


def test_token_json_emits_a_compact_silent_result_without_device_login(monkeypatch) -> None:
    token = "silent-access-token"
    device_login = Mock()
    monkeypatch.setattr(
        cli,
        "_acquire_access_token_result",
        lambda: {"access_token": token, "expires_in": 300},
        raising=False,
    )
    monkeypatch.setattr(cli, "_device_code_login", device_login)

    result = CliRunner().invoke(cli.main, ["token"])

    assert result.exit_code == 0
    assert result.output == '{"access_token":"silent-access-token","expires_in":300}\n'
    device_login.assert_not_called()


def test_token_json_format_flag_matches_the_default(monkeypatch) -> None:
    monkeypatch.setattr(
        cli,
        "_acquire_access_token_result",
        lambda: {"access_token": "silent-access-token", "expires_in": 300},
        raising=False,
    )

    result = CliRunner().invoke(cli.main, ["token", "--format", "json"])

    assert result.exit_code == 0
    assert result.output == '{"access_token":"silent-access-token","expires_in":300}\n'


@pytest.mark.parametrize("expires_in", [True, 0, -1, 1.5, "300", None])
def test_token_json_rejects_invalid_expiry_without_leaking_token(monkeypatch, expires_in) -> None:
    secret = "secret-access-token"
    monkeypatch.setattr(
        cli,
        "_acquire_access_token_result",
        lambda: {"access_token": secret, "expires_in": expires_in},
        raising=False,
    )

    result = CliRunner().invoke(cli.main, ["token", "--format", "json"])

    assert result.exit_code != 0
    assert secret not in result.output


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_token_json_does_not_swallow_process_interruptions(monkeypatch, interruption) -> None:
    monkeypatch.setattr(
        cli,
        "_acquire_access_token_result",
        Mock(side_effect=interruption()),
        raising=False,
    )

    assert cli.token.callback is not None
    with pytest.raises(interruption):
        cli.token.callback("json")

def test_token_json_failure_never_leaks_a_token_or_starts_device_login(monkeypatch) -> None:
    secret = "secret-access-token"
    device_login = Mock()
    monkeypatch.setattr(
        cli,
        "_acquire_access_token_result",
        Mock(side_effect=click.ClickException(f"renewal failed: {secret}")),
        raising=False,
    )
    monkeypatch.setattr(cli, "_device_code_login", device_login)

    result = CliRunner().invoke(cli.main, ["token", "--format", "json"])

    assert result.exit_code != 0
    assert secret not in result.output
    device_login.assert_not_called()


def test_logout_surfaces_a_failed_delete_for_an_existing_cache(monkeypatch) -> None:
    monkeypatch.setattr(
        cli.keyring,
        "get_password",
        lambda service, account: "serialized-cache" if account == cli.CACHE_ACCOUNT else None,
    )
    monkeypatch.setattr(cli.keyring, "delete_password", Mock(side_effect=cli.PasswordDeleteError("denied")))

    result = CliRunner().invoke(cli.main, ["logout"])

    assert result.exit_code != 0
    assert "credential store is unavailable" in result.output
    assert "denied" not in result.output


def test_load_cache_rewrites_legacy_id_tokens_but_retains_access_tokens(monkeypatch) -> None:
    legacy_cache = json.dumps(
        {
            "AccessToken": {"old-access": "legacy-access-token"},
            "IdToken": {"old-id": "legacy-id-token"},
            "RefreshToken": {"refresh": "refresh-state"},
        }
    )
    stored: dict[str, str] = {}
    monkeypatch.setattr(
        cli.keyring,
        "get_password",
        lambda service, account: legacy_cache if account == cli.CACHE_ACCOUNT else None,
    )
    monkeypatch.setattr(cli.keyring, "set_password", lambda service, account, value: stored.update({account: value}))

    cli._load_cache()

    assert stored == {
        cli.CACHE_ACCOUNT: (
            '{"AccessToken":{"old-access":"legacy-access-token"},'
            '"RefreshToken":{"refresh":"refresh-state"}}'
        )
    }
    assert "legacy-id-token" not in stored[cli.CACHE_ACCOUNT]


def test_rejects_an_unapproved_credential_store_backend(monkeypatch) -> None:
    insecure_backend = type("InsecureBackend", (), {"__module__": "keyring.backends.file"})()
    monkeypatch.setattr(cli.keyring, "get_keyring", lambda: insecure_backend)

    with pytest.raises(click.ClickException, match="No supported operating-system credential store"):
        cli._require_secure_keyring()


def test_load_cache_scrubs_id_tokens_even_when_deserialization_fails(monkeypatch) -> None:
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
    monkeypatch.setattr(
        cli.keyring,
        "get_password",
        lambda service, account: legacy_cache if account == cli.CACHE_ACCOUNT else None,
    )
    monkeypatch.setattr(cli.keyring, "set_password", lambda service, account, value: stored.update({account: value}))

    with pytest.raises(click.ClickException, match="stored sign-in state is invalid"):
        cli._load_cache()

    assert stored == {
        cli.CACHE_ACCOUNT: (
            '{"AccessToken":{"old-access":"legacy-access-token"},'
            '"RefreshToken":{"refresh":"refresh-state"}}'
        )
    }
    assert "legacy-id-token" not in stored[cli.CACHE_ACCOUNT]


def test_unconfigured_distribution_refuses_to_acquire_a_token(monkeypatch) -> None:
    """A build that still carries the placeholder profile must not mint a token."""
    monkeypatch.setattr(profile, "CONFIGURED", False)

    result = CliRunner().invoke(cli.main, ["exec", "--", "claude"])

    assert result.exit_code != 0
    assert "no distribution profile" in result.output
    assert profile.BASE_URL not in result.output


def test_entra_profile_builds_a_microsoft_authority(monkeypatch) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(profile, "TENANT_ID", "tenant-abc")
    monkeypatch.setattr(profile, "OIDC_AUTHORITY", "")
    monkeypatch.setattr(
        cli.msal, "PublicClientApplication", lambda **kwargs: captured.update(kwargs)
    )

    cli._application(cli.msal.SerializableTokenCache())

    assert captured["authority"] == "https://login.microsoftonline.com/tenant-abc"
    assert "oidc_authority" not in captured


def test_generic_profile_builds_an_oidc_discovery_authority(monkeypatch) -> None:
    """Any OIDC provider that advertises a device endpoint must be usable."""
    captured: dict[str, object] = {}
    monkeypatch.setattr(profile, "TENANT_ID", "")
    monkeypatch.setattr(profile, "OIDC_AUTHORITY", "https://idp.example.test/realms/demo")
    monkeypatch.setattr(
        cli.msal, "PublicClientApplication", lambda **kwargs: captured.update(kwargs)
    )

    cli._application(cli.msal.SerializableTokenCache())

    assert captured["oidc_authority"] == "https://idp.example.test/realms/demo"
    assert "authority" not in captured


@pytest.mark.parametrize(
    ("tenant", "authority"),
    [("tenant-abc", "https://idp.example.test/realms/demo"), ("", "")],
)
def test_profile_must_name_exactly_one_identity_provider(
    monkeypatch, tenant: str, authority: str
) -> None:
    """Two authorities, or none, is a configuration mistake rather than a default."""
    monkeypatch.setattr(profile, "TENANT_ID", tenant)
    monkeypatch.setattr(profile, "OIDC_AUTHORITY", authority)

    with pytest.raises(click.ClickException, match="exactly one"):
        cli._settings()


def _write_dev_profile(tmp_path, **overrides) -> str:
    document = {
        "oidc_authority": "https://idp.example.test/realms/demo",
        "client_id": "dev-client",
        "scope": "openid broker",
        "base_url": "http://localhost:8080/v1",
        "models": [["demo-small", "Demo small"]],
    }
    document.update(overrides)
    path = tmp_path / "dev-profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return str(path)


def _reload_profile(monkeypatch, location: str | None):
    import importlib

    if location is None:
        monkeypatch.delenv("GABRO_DEV_PROFILE", raising=False)
    else:
        monkeypatch.setenv("GABRO_DEV_PROFILE", location)
    return importlib.reload(profile)


def test_a_development_profile_configures_an_unconfigured_build(monkeypatch, tmp_path) -> None:
    """Trying the demo must not require editing tracked source."""
    reloaded = _reload_profile(monkeypatch, _write_dev_profile(tmp_path))
    try:
        assert reloaded.CONFIGURED is True
        assert reloaded.DEVELOPMENT is True
        assert reloaded.OIDC_AUTHORITY == "https://idp.example.test/realms/demo"
        assert reloaded.default_model() == "demo-small"
    finally:
        _reload_profile(monkeypatch, None)


def test_a_configured_distribution_ignores_the_development_profile(monkeypatch, tmp_path) -> None:
    """The whole point of compiling coordinates in is that they cannot be redirected."""
    location = _write_dev_profile(
        tmp_path, base_url="https://attacker.example/v1", oidc_authority="https://attacker.example"
    )
    monkeypatch.setattr(profile, "CONFIGURED", True)
    monkeypatch.setenv("GABRO_DEV_PROFILE", location)

    profile._apply_development_profile()

    assert profile.BASE_URL != "https://attacker.example/v1"
    assert profile.DEVELOPMENT is False


def test_an_unconfigured_build_without_a_development_profile_still_refuses(monkeypatch) -> None:
    reloaded = _reload_profile(monkeypatch, None)
    try:
        assert reloaded.CONFIGURED is False
        assert reloaded.DEVELOPMENT is False
    finally:
        _reload_profile(monkeypatch, None)


@pytest.mark.parametrize(
    "overrides",
    [
        {"models": []},
        {"models": "demo-small"},
        {"tenant_id": "t"},
        {"oidc_authority": ""},
    ],
)
def test_rejects_an_invalid_development_profile(monkeypatch, tmp_path, overrides) -> None:
    location = _write_dev_profile(tmp_path, **overrides)
    monkeypatch.setenv("GABRO_DEV_PROFILE", location)
    monkeypatch.setattr(profile, "CONFIGURED", False)

    with pytest.raises(RuntimeError, match="GABRO_DEV_PROFILE"):
        profile._apply_development_profile()


def test_rejects_an_unreadable_development_profile(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GABRO_DEV_PROFILE", str(tmp_path / "absent.json"))
    monkeypatch.setattr(profile, "CONFIGURED", False)

    with pytest.raises(RuntimeError, match="GABRO_DEV_PROFILE"):
        profile._apply_development_profile()


def test_the_shipped_demo_profile_names_the_demo_realm(tmp_path, monkeypatch) -> None:
    """The file the demo README tells people to use must actually load.

    Its `ca_bundle` points at TLS material the demo generates on first run and does not
    commit, so the file is copied with that field redirected at a stand-in. Everything
    else is exactly as shipped.
    """
    shipped = json.loads(
        (Path(__file__).parents[1] / "demo" / "gabro-dev-profile.json").read_text(
            encoding="utf-8"
        )
    )
    assert shipped["ca_bundle"] == "tls/ca.pem", "the demo generates its CA here"

    stand_in = tmp_path / "ca.pem"
    stand_in.write_text("not a real certificate", encoding="utf-8")
    shipped["ca_bundle"] = str(stand_in)
    location = tmp_path / "profile.json"
    location.write_text(json.dumps(shipped), encoding="utf-8")

    reloaded = _reload_profile(monkeypatch, str(location))
    try:
        assert reloaded.DEVELOPMENT is True
        assert reloaded.OIDC_AUTHORITY == (
            "https://localhost:8443/realms/gatebroker-demo"
        )
        assert reloaded.BASE_URL == "http://localhost:8080/v1"
        assert reloaded.CLIENT_ID == "gabro-cli"
        assert reloaded.default_model() == "demo-small"
    finally:
        _reload_profile(monkeypatch, None)


def test_a_profile_that_fails_validation_leaves_the_module_untouched(
    tmp_path, monkeypatch
) -> None:
    """Partial application would leave some values from the file and some defaults."""
    location = _write_dev_profile(tmp_path, ca_bundle=str(tmp_path / "absent.pem"))
    monkeypatch.setenv("GABRO_DEV_PROFILE", location)
    monkeypatch.setattr(profile, "CONFIGURED", False)
    def state():
        return (profile.MODELS, profile.CLIENT_ID, profile.BASE_URL, profile.CA_BUNDLE)

    before = state()

    with pytest.raises(RuntimeError, match="ca_bundle"):
        profile._apply_development_profile()

    assert state() == before
    assert profile.DEVELOPMENT is False


def test_version_reports_an_unconfigured_build(monkeypatch) -> None:
    """`gabro --version` answers "am I running the code I think I am"."""
    monkeypatch.setattr(profile, "CONFIGURED", False)
    monkeypatch.setattr(profile, "DEVELOPMENT", False)

    result = CliRunner().invoke(cli.main, ["--version"])

    assert result.exit_code == 0
    assert cli.__name__.split(".")[0] in result.output or "gabro" in result.output
    assert "none set" in result.output
    assert "GABRO_DEV_PROFILE" in result.output


def test_version_names_the_development_profile_in_use(monkeypatch, tmp_path) -> None:
    location = _write_dev_profile(tmp_path)
    monkeypatch.setenv("GABRO_DEV_PROFILE", location)
    monkeypatch.setattr(profile, "DEVELOPMENT", True)

    result = CliRunner().invoke(cli.main, ["--version"])

    assert result.exit_code == 0
    assert location in result.output
    assert profile.BASE_URL in result.output


def test_version_does_not_require_a_configured_profile(monkeypatch) -> None:
    """It has to work precisely when the CLI otherwise refuses to run."""
    monkeypatch.setattr(profile, "CONFIGURED", False)

    result = CliRunner().invoke(cli.main, ["--version"])

    assert result.exit_code == 0
    assert "no distribution profile" not in result.output


def _silent_application(result: object) -> Mock:
    application = Mock()
    application.get_accounts.return_value = [object()]
    application.acquire_token_silent_with_error.return_value = result
    return application


def test_a_failed_renewal_reports_cleanly_rather_than_crashing(monkeypatch) -> None:
    """MSAL returns None when it cannot redeem the refresh token, which used to reach
    `.get` on None and print a traceback at the user.
    """
    cache = Mock()
    cache.has_state_changed = False
    monkeypatch.setattr(cli, "_load_cache", lambda: cache)
    monkeypatch.setattr(cli, "_application", lambda _cache: _silent_application(None))

    with pytest.raises(click.ClickException, match="run gabro login"):
        cli._acquire_access_token()


def test_a_failed_renewal_says_why_when_the_provider_explains(monkeypatch) -> None:
    """A bare "sign in again" right after signing in successfully is unactionable."""
    cache = Mock()
    cache.has_state_changed = False
    rejection = {
        "error": "invalid_scope",
        "error_description": "Invalid scopes: offline_access openid broker profile",
    }
    monkeypatch.setattr(cli, "_load_cache", lambda: cache)
    monkeypatch.setattr(cli, "_application", lambda _cache: _silent_application(rejection))

    with pytest.raises(click.ClickException) as raised:
        cli._acquire_access_token()

    message = str(raised.value)
    assert "invalid_scope" in message
    assert "Invalid scopes" in message


def test_a_renewal_failure_reason_reports_only_the_error_not_the_whole_result(
    monkeypatch,
) -> None:
    """Only the error code and description are repeated, never other fields."""
    cache = Mock()
    cache.has_state_changed = False
    rejection = {
        "error": "invalid_grant",
        "error_description": "Token is not active",
        "refresh_token": "secret-refresh-material",
        "id_token": "secret-id-material",
    }
    monkeypatch.setattr(cli, "_load_cache", lambda: cache)
    monkeypatch.setattr(cli, "_application", lambda _cache: _silent_application(rejection))

    with pytest.raises(click.ClickException) as raised:
        cli._acquire_access_token()

    message = str(raised.value)
    assert "invalid_grant" in message
    assert "secret-refresh-material" not in message
    assert "secret-id-material" not in message


def test_a_renewal_that_succeeds_returns_the_token(monkeypatch) -> None:
    cache = Mock()
    cache.has_state_changed = False
    monkeypatch.setattr(cli, "_load_cache", lambda: cache)
    monkeypatch.setattr(
        cli, "_application", lambda _cache: _silent_application({"access_token": "renewed"})
    )

    assert cli._acquire_access_token() == "renewed"


def test_login_leaves_exactly_one_cached_account(monkeypatch) -> None:
    """A stale account otherwise makes every later command fail until logout is found.

    An identity provider that gets rebuilt issues new subject identifiers for the same
    username, so signing in again is enough to accumulate one.
    """
    stale = {"home_account_id": "old-id", "username": "alice"}
    fresh = {"home_account_id": "new-id", "username": "alice"}
    removed: list[dict] = []
    application = Mock()
    application.get_accounts.return_value = [stale, fresh]
    application.remove_account.side_effect = removed.append
    application.initiate_device_flow.return_value = {
        "user_code": "CODE", "verification_uri": "https://idp.example.test/device"
    }
    application.acquire_token_by_device_flow.return_value = {
        "access_token": "token", "id_token_claims": {"home_account_id": "new-id"}
    }

    monkeypatch.setattr(cli, "_load_cache", lambda: Mock(has_state_changed=False))
    monkeypatch.setattr(cli, "_application", lambda _cache: application)
    monkeypatch.setattr(cli, "_copy_device_code", lambda _code: False)
    monkeypatch.setattr(cli.click, "launch", lambda _url: False)

    result = CliRunner().invoke(cli.main, ["login"])

    assert result.exit_code == 0
    assert removed == [stale]


def test_login_keeps_the_newest_account_when_claims_omit_the_identifier(monkeypatch) -> None:
    stale = {"home_account_id": "old-id"}
    fresh = {"home_account_id": "new-id"}
    removed: list[dict] = []
    application = Mock()
    application.get_accounts.return_value = [stale, fresh]
    application.remove_account.side_effect = removed.append
    application.initiate_device_flow.return_value = {
        "user_code": "CODE", "verification_uri": "https://idp.example.test/device"
    }
    application.acquire_token_by_device_flow.return_value = {"access_token": "token"}

    monkeypatch.setattr(cli, "_load_cache", lambda: Mock(has_state_changed=False))
    monkeypatch.setattr(cli, "_application", lambda _cache: application)
    monkeypatch.setattr(cli, "_copy_device_code", lambda _code: False)
    monkeypatch.setattr(cli.click, "launch", lambda _url: False)

    assert CliRunner().invoke(cli.main, ["login"]).exit_code == 0
    assert removed == [stale]


def test_pruning_never_fails_a_successful_sign_in(monkeypatch) -> None:
    """Housekeeping must not turn a completed sign-in into an error."""
    application = Mock()
    application.get_accounts.side_effect = RuntimeError("cache unavailable")
    application.initiate_device_flow.return_value = {
        "user_code": "CODE", "verification_uri": "https://idp.example.test/device"
    }
    application.acquire_token_by_device_flow.return_value = {"access_token": "token"}

    monkeypatch.setattr(cli, "_load_cache", lambda: Mock(has_state_changed=False))
    monkeypatch.setattr(cli, "_application", lambda _cache: application)
    monkeypatch.setattr(cli, "_copy_device_code", lambda _code: False)
    monkeypatch.setattr(cli.click, "launch", lambda _url: False)

    assert CliRunner().invoke(cli.main, ["login"]).exit_code == 0


def test_advice_names_a_command_that_exists_on_this_machine(monkeypatch) -> None:
    """`gabro logout` is useless advice when gabro is not on PATH."""
    monkeypatch.setattr(cli.shutil, "which", lambda _name: None)
    assert cli._invocation() == "uv run gabro"

    monkeypatch.setattr(cli.shutil, "which", lambda _name: "/usr/local/bin/gabro")
    assert cli._invocation() == "gabro"


def test_multiple_account_error_tells_the_user_a_runnable_command(monkeypatch) -> None:
    cache = Mock()
    cache.has_state_changed = False
    application = Mock()
    application.get_accounts.return_value = [object(), object()]
    monkeypatch.setattr(cli, "_load_cache", lambda: cache)
    monkeypatch.setattr(cli, "_application", lambda _cache: application)
    monkeypatch.setattr(cli.shutil, "which", lambda _name: None)

    with pytest.raises(click.ClickException, match="uv run gabro logout"):
        cli._acquire_access_token()
