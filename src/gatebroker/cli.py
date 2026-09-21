# SPDX-License-Identifier: Apache-2.0
"""Secure device-code credential helper for the GateBroker."""

from __future__ import annotations

import base64
import hmac
import json
import os
import secrets
import shutil
import stat
import subprocess  # nosec B404
import sys
import tempfile
from collections.abc import Mapping, Sequence
from contextlib import contextmanager, suppress
from pathlib import Path

import click
import keyring
import msal
from keyring.errors import KeyringError, PasswordDeleteError

from gatebroker import __version__, profile
from gatebroker.claude_launch import augment_claude_environment, is_claude_command
from gatebroker.codex_launch import augment_codex_command, is_codex_command
from gatebroker.copilot_launch import augment_copilot_environment, is_copilot_command
from gatebroker.model_discovery import allowed_models

_DEV_PROFILE_VARIABLE = "GABRO_DEV_PROFILE"
CACHE_SERVICE = "gabro"
CACHE_ACCOUNT = "broker-device-code-cache"
PROFILE_INTEGRITY_ACCOUNT = "agent-profile-integrity-key"
_SECURE_KEYRING_BACKENDS = {
    "darwin": ("keyring.backends.macOS",),
    "linux": ("keyring.backends.SecretService", "keyring.backends.kwallet"),
    "win32": ("keyring.backends.Windows",),
}


def _settings() -> tuple[str, str, str, str]:
    """Return the distribution's identity-provider resource and gateway endpoint.

    This helper must not accept environment overrides: a token for the broker
    resource must never be injected into an arbitrary endpoint by a shell
    profile, wrapper, or CI environment. See ``gatebroker.profile``.
    """
    if not profile.CONFIGURED:
        raise click.ClickException(
            "This build has no distribution profile. Either set the values in "
            "gatebroker/profile.py and mark it CONFIGURED, or point "
            "GABRO_DEV_PROFILE at a profile file for development. The demo ships "
            "one at demo/gabro-dev-profile.json."
        )
    if bool(profile.TENANT_ID) == bool(profile.OIDC_AUTHORITY):
        raise click.ClickException(
            "Set exactly one of TENANT_ID (Microsoft Entra) or OIDC_AUTHORITY "
            "(any other OIDC provider) in gatebroker/profile.py."
        )
    return profile.TENANT_ID, profile.CLIENT_ID, profile.SCOPE, profile.BASE_URL


def _invocation() -> str:
    """Return how to invoke this CLI from where it is running.

    Telling someone to run `gabro logout` is useless when `gabro` is not on their PATH,
    which is the normal case for a source checkout driven through `uv run`.
    """
    return "gabro" if shutil.which("gabro") else "uv run gabro"


def _agents_file() -> Path:
    """Return the platform-appropriate, non-secret local agent profile file."""
    if sys.platform == "darwin":
        config_root = Path.home() / "Library" / "Application Support"
    elif sys.platform == "win32":
        config_root = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    else:
        config_root = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return config_root / "gabro" / "agents.json"


def _load_agents() -> dict[str, list[str]]:
    """Load validated launcher profiles; these profiles must never hold secrets."""
    path = _agents_file()
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            return {}
        with os.fdopen(descriptor, encoding="utf-8") as profile_file:
            info = os.fstat(profile_file.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("unsafe profile type")
            if sys.platform != "win32" and (
                info.st_mode & 0o022
                or (hasattr(os, "getuid") and info.st_uid != os.getuid())
            ):
                raise ValueError("unsafe profile permissions")
            data = json.load(profile_file)
        agents = data["agents"]
        if not isinstance(agents, dict) or any(
            not isinstance(name, str)
            or not name
            or not isinstance(command, list)
            or not command
            or any(not isinstance(argument, str) or not argument for argument in command)
            for name, command in agents.items()
        ):
            raise ValueError("invalid profile")
        expected_mac = data.get("mac")
        if not isinstance(expected_mac, str) or not hmac.compare_digest(
            expected_mac, _agents_mac(agents, _profile_integrity_key(create=False))
        ):
            raise ValueError("invalid profile integrity")
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise click.ClickException(
            "The local agent configuration is invalid; use configure --reset to replace it."
        ) from error
    return agents


def _save_agents(agents: dict[str, list[str]]) -> None:
    path = _agents_file()
    temporary_path: str | None = None
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent_info = path.parent.stat(follow_symlinks=False)
        if not stat.S_ISDIR(parent_info.st_mode) or path.parent.is_symlink():
            raise OSError("unsafe profile directory")
        if sys.platform != "win32" and (
            parent_info.st_mode & 0o022
            or (hasattr(os, "getuid") and parent_info.st_uid != os.getuid())
        ):
            raise OSError("unsafe profile directory permissions")
        document = {
            "agents": agents,
            "mac": _agents_mac(agents, _profile_integrity_key(create=True)),
        }
        descriptor, temporary_path = tempfile.mkstemp(
            dir=path.parent,
            prefix=".agents-",
            suffix=".tmp",
        )
        os.chmod(temporary_path, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as profile_file:
            json.dump(document, profile_file, indent=2, sort_keys=True)
            profile_file.write("\n")
            profile_file.flush()
            os.fsync(profile_file.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
    except (OSError, KeyringError, ValueError) as error:
        raise click.ClickException("Unable to save the local agent configuration.") from error
    finally:
        if temporary_path is not None:
            with suppress(FileNotFoundError):
                os.unlink(temporary_path)


def _profile_integrity_key(*, create: bool) -> bytes:
    _require_secure_keyring()
    try:
        encoded = keyring.get_password(CACHE_SERVICE, PROFILE_INTEGRITY_ACCOUNT)
        if encoded is None:
            if not create:
                raise ValueError("missing profile integrity key")
            encoded = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
            keyring.set_password(CACHE_SERVICE, PROFILE_INTEGRITY_ACCOUNT, encoded)
        key = base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (KeyringError, ValueError) as error:
        raise ValueError("invalid profile integrity key") from error
    if len(key) != 32:
        raise ValueError("invalid profile integrity key")
    return key


def _agents_mac(agents: dict[str, list[str]], key: bytes) -> str:
    canonical = json.dumps(agents, separators=(",", ":"), sort_keys=True).encode()
    return hmac.digest(key, canonical, "sha256").hex()


def _require_secure_keyring() -> None:
    allowed_backends = _SECURE_KEYRING_BACKENDS.get(sys.platform, ())
    backend_module = type(keyring.get_keyring()).__module__
    if backend_module not in allowed_backends:
        raise click.ClickException("No supported operating-system credential store is available.")


def _sanitize_cache(serialized: str) -> tuple[str, bool]:
    cache_data = json.loads(serialized)
    removed = cache_data.pop("IdToken", None) is not None
    return json.dumps(cache_data, separators=(",", ":")), removed


_WINDOWS_CREDENTIAL_MAX_BYTES = 2_560
_WINDOWS_CACHE_CHUNK_BYTES = 2_400
_WINDOWS_CACHE_MANIFEST_KEY = "windows-cache-chunks"
_WINDOWS_CACHE_CLEANUP_ACCOUNT = f"{CACHE_ACCOUNT}-chunk-cleanup"
_WINDOWS_CACHE_MAX_CHUNKS = 1_024
_WINDOWS_CACHE_MAX_CLEANUP_ENTRIES = 16


def _cache_chunk_account(generation: str, index: int) -> str:
    return f"{CACHE_ACCOUNT}-chunk-{generation}-{index}"


def _split_windows_cache(serialized: str) -> list[str]:
    chunks: list[str] = []
    current: list[str] = []
    current_bytes = 0
    for character in serialized:
        character_bytes = len(character.encode("utf-16-le"))
        if current and current_bytes + character_bytes > _WINDOWS_CACHE_CHUNK_BYTES:
            chunks.append("".join(current))
            current = []
            current_bytes = 0
        current.append(character)
        current_bytes += character_bytes
    if current:
        chunks.append("".join(current))
    return chunks


def _valid_windows_cache_generation(value: object) -> bool:
    return isinstance(value, str) and len(value) == 32 and all(character in "0123456789abcdef" for character in value)


def _valid_windows_cache_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= _WINDOWS_CACHE_MAX_CHUNKS


def _windows_cache_manifest(serialized: str | None) -> tuple[str, int, list[tuple[str, int]]] | None:
    if not serialized:
        return None
    try:
        value = json.loads(serialized).get(_WINDOWS_CACHE_MANIFEST_KEY)
    except (AttributeError, TypeError, ValueError):
        return None
    if not isinstance(value, dict):
        return None
    generation = value.get("generation")
    count = value.get("count")
    cleanup = value.get("cleanup", [])
    if not _valid_windows_cache_generation(generation) or not _valid_windows_cache_count(count):
        return None
    if (
        not isinstance(cleanup, list)
        or len(cleanup) > _WINDOWS_CACHE_MAX_CLEANUP_ENTRIES
        or any(
            not isinstance(item, dict)
            or not _valid_windows_cache_generation(item.get("generation"))
            or not _valid_windows_cache_count(item.get("count"))
            for item in cleanup
        )
    ):
        return None
    entries = [(item["generation"], item["count"]) for item in cleanup]
    if not _windows_cache_entries_have_consistent_counts([(generation, count), *entries]):
        return None
    return generation, count, entries


def _windows_cache_manifest_document(generation: str, count: int, cleanup: list[tuple[str, int]]) -> str:
    manifest: dict[str, object] = {"generation": generation, "count": count}
    if cleanup:
        manifest["cleanup"] = [{"generation": old, "count": old_count} for old, old_count in cleanup]
    return json.dumps({_WINDOWS_CACHE_MANIFEST_KEY: manifest}, separators=(",", ":"))


def _windows_cache_entries_have_consistent_counts(entries: list[tuple[str, int]]) -> bool:
    counts: dict[str, int] = {}
    for generation, count in entries:
        existing = counts.setdefault(generation, count)
        if existing != count:
            return False
    return True


def _windows_cache_entries(value: object) -> list[tuple[str, int]] | None:
    """Parse an exact cleanup journal; unknown data must never be discarded."""
    if not isinstance(value, dict) or set(value) != {"cleanup"} or not isinstance(value["cleanup"], list):
        return None
    entries: list[tuple[str, int]] = []
    for item in value["cleanup"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"generation", "count"}
            or not _valid_windows_cache_generation(item["generation"])
            or not _valid_windows_cache_count(item["count"])
        ):
            return None
        entry = (item["generation"], item["count"])
        if entry not in entries:
            entries.append(entry)
    if not _windows_cache_entries_have_consistent_counts(entries):
        return None
    return entries if len(entries) <= _WINDOWS_CACHE_MAX_CLEANUP_ENTRIES else None


def _pending_windows_cache_cleanup() -> list[tuple[str, int]]:
    serialized = keyring.get_password(CACHE_SERVICE, _WINDOWS_CACHE_CLEANUP_ACCOUNT)
    if serialized is None:
        return []
    try:
        entries = _windows_cache_entries(json.loads(serialized))
    except (TypeError, ValueError):
        entries = None
    if entries is None:
        raise click.ClickException(f"The stored sign-in state is invalid; run {_invocation()} logout, then login.")
    return entries


def _merge_windows_cache_entries(*groups: list[tuple[str, int]]) -> list[tuple[str, int]]:
    merged: list[tuple[str, int]] = []
    for group in groups:
        for entry in group:
            if entry not in merged:
                merged.append(entry)
    if not _windows_cache_entries_have_consistent_counts(merged):
        raise click.ClickException(f"The stored sign-in state is invalid; run {_invocation()} logout, then login.")
    if len(merged) > _WINDOWS_CACHE_MAX_CLEANUP_ENTRIES:
        raise click.ClickException("The operating-system credential store cannot save the sign-in state.")
    return merged


def _write_windows_cache_cleanup(entries: list[tuple[str, int]]) -> None:
    keyring.set_password(CACHE_SERVICE, _WINDOWS_CACHE_CLEANUP_ACCOUNT, json.dumps({"cleanup": [{"generation": generation, "count": count} for generation, count in entries]}, separators=(",", ":")))


def _record_windows_cache_cleanup(entries: list[tuple[str, int]]) -> None:
    # Journal entries are merged, never replaced: a failed rollback must not erase an
    # earlier orphan that only this journal can name.
    _write_windows_cache_cleanup(_merge_windows_cache_entries(_pending_windows_cache_cleanup(), entries))


def _retry_windows_cache_cleanup(active: tuple[str, int] | None) -> None:
    entries = _pending_windows_cache_cleanup()
    if active and any(generation == active[0] and count != active[1] for generation, count in entries):
        raise click.ClickException(f"The stored sign-in state is invalid; run {_invocation()} logout, then login.")
    stale = [entry for entry in entries if active is None or entry[0] != active[0]]
    failed = _delete_windows_cache_manifest_entries(stale)
    remaining = _merge_windows_cache_entries([active] if active else [], failed)
    if remaining:
        _write_windows_cache_cleanup(remaining)
    elif entries:
        keyring.delete_password(CACHE_SERVICE, _WINDOWS_CACHE_CLEANUP_ACCOUNT)


def _delete_windows_cache_generation(generation: str, count: int) -> bool:
    for index in range(count):
        account = _cache_chunk_account(generation, index)
        try:
            if keyring.get_password(CACHE_SERVICE, account) is None:
                continue
            keyring.delete_password(CACHE_SERVICE, account)
        except PasswordDeleteError:
            return False
        except (KeyringError, OSError):
            return False
    return True


def _delete_windows_cache_manifest_entries(entries: list[tuple[str, int]]) -> list[tuple[str, int]]:
    return [(generation, count) for generation, count in entries if not _delete_windows_cache_generation(generation, count)]


@contextmanager
def _windows_cache_lock():
    if sys.platform != "win32":
        yield
        return
    import msvcrt

    lock_path = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "gabro" / "cache.lock"
    lock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with lock_path.open("a+b") as lock_file:
        if lock_file.seek(0, os.SEEK_END) == 0:
            lock_file.write(b"0")
            lock_file.flush()
        lock_file.seek(0)
        msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
        try:
            yield
        finally:
            lock_file.seek(0)
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)


def _load_windows_chunked_cache(serialized: str) -> str:
    with _windows_cache_lock():
        return _load_windows_chunked_cache_unlocked(serialized)


def _load_windows_chunked_cache_unlocked(serialized: str) -> str:
    manifest = _windows_cache_manifest(serialized)
    if manifest is None:
        try:
            decoded = json.loads(serialized)
        except (TypeError, ValueError):
            decoded = None
        if isinstance(decoded, dict) and _WINDOWS_CACHE_MANIFEST_KEY in decoded:
            raise click.ClickException(f"The stored sign-in state is invalid; run {_invocation()} logout, then login.")
        return serialized
    generation, count, _cleanup = manifest
    try:
        chunks = [keyring.get_password(CACHE_SERVICE, _cache_chunk_account(generation, index)) for index in range(count)]
    except (KeyringError, OSError) as error:
        raise click.ClickException("The operating-system credential store is unavailable.") from error
    if any(not isinstance(chunk, str) for chunk in chunks):
        raise click.ClickException(f"The stored sign-in state is invalid; run {_invocation()} logout, then login.")
    return "".join(chunks)


def _delete_windows_cache_chunks(serialized: str | None) -> None:
    manifest = _windows_cache_manifest(serialized)
    if manifest is None:
        return
    generation, count, cleanup = manifest
    if _delete_windows_cache_manifest_entries([(generation, count), *cleanup]):
        raise click.ClickException("The operating-system credential store is unavailable.")


def _store_cache(serialized: str) -> None:
    try:
        with _windows_cache_lock():
            _store_cache_unlocked(serialized)
    except click.ClickException:
        raise
    except (KeyringError, OSError) as error:
        raise click.ClickException("The operating-system credential store is unavailable.") from error


def _invalid_windows_manifest(serialized: str | None) -> bool:
    if not serialized:
        return False
    try:
        decoded = json.loads(serialized)
    except (TypeError, ValueError):
        return False
    return isinstance(decoded, dict) and _WINDOWS_CACHE_MANIFEST_KEY in decoded and _windows_cache_manifest(serialized) is None


def _store_cache_unlocked(serialized: str) -> None:
    _require_secure_keyring()
    if sys.platform != "win32":
        keyring.set_password(CACHE_SERVICE, CACHE_ACCOUNT, serialized)
        return

    previous = keyring.get_password(CACHE_SERVICE, CACHE_ACCOUNT)
    if _invalid_windows_manifest(previous):
        raise click.ClickException(f"The stored sign-in state is invalid; run {_invocation()} logout, then login.")
    previous_manifest = _windows_cache_manifest(previous)
    active = None if previous_manifest is None else (previous_manifest[0], previous_manifest[1])
    embedded_cleanup = [] if previous_manifest is None else previous_manifest[2]

    # Migrate cleanup carried by older manifest formats before replacing the primary
    # pointer. A failed journal write leaves the old manifest and all its ownership intact.
    if embedded_cleanup:
        _record_windows_cache_cleanup(embedded_cleanup)

    # Only generations other than the primary's active generation may be reaped.
    # The journal is conservative: entries remain valid even when some chunks have
    # already disappeared, so interruption at any point is retryable.
    _retry_windows_cache_cleanup(active)

    if len(serialized.encode("utf-16-le")) <= _WINDOWS_CREDENTIAL_MAX_BYTES:
        if active:
            _record_windows_cache_cleanup([active])
        keyring.set_password(CACHE_SERVICE, CACHE_ACCOUNT, serialized)
        return

    chunks = _split_windows_cache(serialized)
    if len(chunks) > _WINDOWS_CACHE_MAX_CHUNKS:
        raise click.ClickException("The operating-system credential store cannot save the sign-in state.")
    generation = secrets.token_hex(16)
    new_entry = (generation, len(chunks))

    # Durable intent precedes credential data. The active old generation is also
    # journaled before publication, so no delete is needed in the commit path.
    _record_windows_cache_cleanup(([active] if active else []) + [new_entry])
    for index, chunk in enumerate(chunks):
        keyring.set_password(CACHE_SERVICE, _cache_chunk_account(generation, index), chunk)
    # This is the sole commit point. After it succeeds the new cache is valid and
    # cleanup remains deferred/retryable; no fallible post-commit operation runs.
    keyring.set_password(CACHE_SERVICE, CACHE_ACCOUNT, _windows_cache_manifest_document(generation, len(chunks), []))


def _load_cache() -> msal.SerializableTokenCache:
    cache = msal.SerializableTokenCache()
    _require_secure_keyring()
    try:
        if sys.platform == "win32":
            with _windows_cache_lock():
                serialized = keyring.get_password(CACHE_SERVICE, CACHE_ACCOUNT)
                if serialized:
                    serialized = _load_windows_chunked_cache_unlocked(serialized)
                    sanitized, removed_tokens = _sanitize_cache(serialized)
                    if removed_tokens:
                        _store_cache_unlocked(sanitized)
                    cache.deserialize(sanitized)
        else:
            serialized = keyring.get_password(CACHE_SERVICE, CACHE_ACCOUNT)
            if serialized:
                sanitized, removed_tokens = _sanitize_cache(serialized)
                if removed_tokens:
                    _store_cache_unlocked(sanitized)
                cache.deserialize(sanitized)
    except (KeyringError, OSError) as error:
        raise click.ClickException("The operating-system credential store is unavailable.") from error
    except click.ClickException:
        raise
    except Exception as error:  # Cache contents must never be shown to the user.
        raise click.ClickException(
            f"The stored sign-in state is invalid; run {_invocation()} logout, then login."
        ) from error
    return cache


def _save_cache(cache: msal.SerializableTokenCache) -> None:
    if not cache.has_state_changed:
        return
    serialized, _removed_tokens = _sanitize_cache(cache.serialize())
    # MSAL serializes access and ID tokens alongside refresh state. Retain only
    # the entries necessary for a later silent refresh in the OS credential
    # store; short-lived broker access tokens must stay process-ephemeral.
    _store_cache(serialized)


def _application(cache: msal.SerializableTokenCache) -> msal.PublicClientApplication:
    tenant_id, client_id, _scope, _base_url = _settings()
    # MSAL goes through `requests`, which honours neither SSL_CERT_FILE nor the system
    # trust store, so a private CA has to be handed to it explicitly.
    verification = {"verify": profile.CA_BUNDLE} if profile.CA_BUNDLE else {}
    if tenant_id:
        return msal.PublicClientApplication(
            client_id=client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            token_cache=cache,
            **verification,
        )
    # A non-Microsoft provider is reached through OIDC discovery rather than the
    # Entra authority, so its device authorization endpoint is taken from the
    # issuer's own metadata.
    return msal.PublicClientApplication(
        client_id=client_id,
        oidc_authority=profile.OIDC_AUTHORITY,
        token_cache=cache,
        **verification,
    )


def _terminal_hyperlink(url: str) -> str:
    """Return an OSC 8 hyperlink while retaining the URL as visible text."""
    return f"\033]8;;{url}\033\\{url}\033]8;;\033\\"


def _copy_device_code(code: str) -> bool:
    """Copy a short-lived device code without exposing auth tokens to a clipboard."""
    if sys.platform == "darwin":
        commands = (("pbcopy",),)
    elif sys.platform == "win32":
        commands = (("clip",),)
    else:
        commands = (("wl-copy",), ("xclip", "-selection", "clipboard"))

    for command in commands:
        if shutil.which(command[0]) is None:
            continue
        try:
            # The clipboard command is a fixed argv tuple and never uses a shell.
            completed = subprocess.run(  # nosec B603
                command,
                input=code,
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=3,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if completed.returncode == 0:
            return True
    return False


def _device_login_url(flow: dict[str, object]) -> str | None:
    verification_uri_complete = flow.get("verification_uri_complete")
    if isinstance(verification_uri_complete, str) and verification_uri_complete:
        return verification_uri_complete

    verification_uri = flow.get("verification_uri")
    if isinstance(verification_uri, str) and verification_uri:
        return verification_uri
    return None


def _device_code_instructions(flow: dict[str, object]) -> str:
    """Format an explicit terminal hyperlink for the device-code flow."""
    verification_uri = _device_login_url(flow)
    user_code = flow.get("user_code")
    if isinstance(verification_uri, str) and isinstance(user_code, str) and user_code:
        return f"To sign in, open {_terminal_hyperlink(verification_uri)} in your browser and enter the code {user_code}."

    raise click.ClickException("Unable to start device-code sign-in.")


def _device_code_login() -> None:
    _tenant_id, _client_id, scope, base_url = _settings()
    cache = _load_cache()
    application = _application(cache)
    flow = application.initiate_device_flow(scopes=[scope])

    click.echo(_device_code_instructions(flow))
    user_code = flow.get("user_code")
    if isinstance(user_code, str) and _copy_device_code(user_code):
        click.echo("The device code has been copied to your clipboard. Paste it into the sign-in page.")
    verification_uri = _device_login_url(flow)
    if verification_uri is not None:
        try:
            opened = click.launch(verification_uri)
        except Exception:
            opened = False
        if opened:
            click.echo("Opened the sign-in page in your browser.")
    result = application.acquire_token_by_device_flow(flow)
    if "access_token" not in result:
        raise click.ClickException("Device-code sign-in did not complete successfully.")
    _retain_only_signed_in_account(application, result)
    _save_cache(cache)
    click.echo(f"Authentication completed. You can direct your agent at {base_url}")


def _retain_only_signed_in_account(
    application: msal.PublicClientApplication, result: Mapping[str, object]
) -> None:
    """Drop every cached account except the one that just signed in.

    Only one account is ever usable: token acquisition refuses to guess between
    several. Without this, a second sign-in leaves the first account behind and every
    later command fails until the user finds `logout` -- and a stale account accumulates
    easily, since an identity provider that is rebuilt issues new subject identifiers
    for the same username.
    """
    try:
        accounts = [account for account in application.get_accounts() if isinstance(account, Mapping)]
    except Exception:
        # Pruning is housekeeping. It must never turn a successful sign-in into a
        # failure, whatever shape the identity library returns.
        return
    if len(accounts) < 2:
        return

    claims = result.get("id_token_claims")
    signed_in = claims.get("home_account_id") if isinstance(claims, Mapping) else None
    if not isinstance(signed_in, str) or not signed_in:
        # Without an identifier to keep, keep the newest account, which is the one this
        # flow just created.
        signed_in = accounts[-1].get("home_account_id")
    for account in accounts:
        if account.get("home_account_id") != signed_in:
            with suppress(Exception):
                application.remove_account(account)


def _acquire_access_token_result() -> Mapping[str, object]:
    """Return a silently acquired MSAL result without starting an interactive flow."""
    _tenant_id, _client_id, scope, _base_url = _settings()
    cache = _load_cache()
    application = _application(cache)
    accounts = application.get_accounts()
    if len(accounts) > 1:
        raise click.ClickException(
            f"Multiple cached accounts were found; run {_invocation()} logout, then login."
        )
    if accounts:
        # Returns None when no cached token matches and the refresh could not be
        # redeemed, so the reason is fetched alongside it: a silent "please sign in
        # again" after a successful sign-in is impossible to act on, and the identity
        # provider usually knows exactly what is wrong.
        result = application.acquire_token_silent_with_error(
            scopes=[scope], account=accounts[0]
        )
        token = (result or {}).get("access_token")
        if isinstance(token, str) and token and isinstance(result, Mapping):
            _save_cache(cache)
            return result
        reason = _renewal_failure_reason(result)
    else:
        reason = ""
    _save_cache(cache)
    raise click.ClickException(
        f"No valid GateBroker sign-in is available; run {_invocation()} login.{reason}"
    )


def _acquire_access_token() -> str:
    result = _acquire_access_token_result()
    token = result.get("access_token")
    # The result-returning helper verifies this before returning; keep this defensive
    # boundary because callers use the string helper as a credential injection point.
    if isinstance(token, str) and token:
        return token
    raise click.ClickException("No valid GateBroker sign-in is available; run login.")


def _renewal_failure_reason(result: object) -> str:
    """Summarize why renewal failed, without repeating anything sensitive.

    Only the provider's error code and description are used. Neither carries token or
    key material, and without them the caller is left guessing.
    """
    if not isinstance(result, Mapping):
        return ""
    error = result.get("error")
    description = result.get("error_description")
    if not isinstance(error, str) or not error:
        return ""
    detail = f" The identity provider rejected the renewal: {error}"
    if isinstance(description, str) and description:
        detail += f" ({description.splitlines()[0][:200]})"
    return detail + "."


def _version_message() -> str:
    """Describe the build and where its coordinates came from.

    Enough to answer "am I running the code I think I am, and which profile is it
    using", which is otherwise guesswork when a checkout is behind.
    """
    if profile.DEVELOPMENT:
        origin = f"development file {os.environ.get(_DEV_PROFILE_VARIABLE)}"
    elif profile.CONFIGURED:
        origin = "compiled into this distribution"
    else:
        origin = f"none set; export {_DEV_PROFILE_VARIABLE} or configure profile.py"
    return "\n".join(
        (
            f"gabro {__version__}",
            f"profile: {origin}",
            f"gateway: {profile.BASE_URL if profile.CONFIGURED else '-'}",
            f"code:    {Path(__file__).resolve().parent}",
        )
    )


@click.group()
@click.option(
    "--version",
    is_flag=True,
    expose_value=False,
    is_eager=True,
    callback=lambda context, _parameter, value: (
        context.exit(click.echo(_version_message()) or 0) if value else None
    ),
    help="Show the version, which profile is in use, and where this build lives.",
)
def main() -> None:
    """Authenticate local OpenAI- and Anthropic-compatible tools to a private AI gateway."""
    if profile.DEVELOPMENT:
        # Say so every time. Someone should never be unsure whether the token they
        # just minted came from a reviewed distribution or from a local file.
        click.echo(
            f"Using the development profile from {os.environ.get(_DEV_PROFILE_VARIABLE)}",
            err=True,
        )


def _configure_local_agent(agent: str, command: Sequence[str], *, reset: bool) -> None:
    """Save a non-secret launcher profile for a local agent command."""
    if not agent:
        raise click.UsageError("Agent names must not be empty.")
    if agent.startswith("-"):
        raise click.UsageError("Agent names must not start with '-'.")
    if not command:
        raise click.UsageError("Provide the local agent command after --.")
    agents = {} if reset else _load_agents()
    agents[agent] = list(command)
    _save_agents(agents)
    click.echo(f"Configured local agent '{agent}'. Run it with: {_invocation()} run {agent}")


@main.command()
@click.argument("agent", required=False)
def login(agent: str | None) -> None:
    """Sign in by device code and save sanitized refresh state in the OS credential store.

    When AGENT is provided, also save a launcher profile equivalent to
    `gabro configure AGENT -- AGENT` and immediately start it with an
    ephemeral broker credential, equivalent to `gabro run AGENT`, after
    sign-in succeeds.
    """
    if agent is not None:
        if not agent:
            raise click.UsageError("Agent names must not be empty.")
        if agent.startswith("-"):
            raise click.UsageError("Agent names must not start with '-'.")
        _load_agents()
    _device_code_login()
    if agent is not None:
        _configure_local_agent(agent, [agent], reset=False)
        _run_with_broker_environment([agent])


@main.command()
@click.option("--format", "output_format", type=click.Choice(("json",)), required=True)
def token(output_format: str) -> None:
    """Print a silently acquired broker token for a non-interactive caller."""
    del output_format  # The explicit choice leaves room for future formats without defaults.
    try:
        result = _acquire_access_token_result()
        access_token = result.get("access_token")
        expires_in = result.get("expires_in")
        if (
            not isinstance(access_token, str)
            or not access_token
            or not isinstance(expires_in, int)
            or isinstance(expires_in, bool)
            or expires_in <= 0
        ):
            raise ValueError("silent result lacks a usable expiration")
    except Exception as error:
        # A token command is machine-facing: emit no partial JSON or provider details,
        # which can include credential material, and never fall back to device login.
        raise click.ClickException("No valid GateBroker sign-in is available; run login.") from error
    click.echo(json.dumps({"access_token": access_token, "expires_in": expires_in}, separators=(",", ":")))


@main.command()
def logout() -> None:
    """Remove the local sanitized MSAL cache from the OS credential store."""
    try:
        _require_secure_keyring()
        if sys.platform == "win32":
            with _windows_cache_lock():
                serialized = keyring.get_password(CACHE_SERVICE, CACHE_ACCOUNT)
                if _invalid_windows_manifest(serialized):
                    raise click.ClickException(f"The stored sign-in state is invalid; run {_invocation()} logout after repairing the credential entry.")
                manifest = _windows_cache_manifest(serialized)
                primary_entries = [] if manifest is None else [(manifest[0], manifest[1]), *manifest[2]]
                entries = _merge_windows_cache_entries(_pending_windows_cache_cleanup(), primary_entries)
                if serialized is None and not entries:
                    click.echo("No local GateBroker sign-in state was found.")
                    return
                if entries:
                    _write_windows_cache_cleanup(entries)
                # Remove the pointer before its chunks. If this delete fails, the old
                # cache is still complete; after it succeeds, the journal owns cleanup.
                if serialized is not None:
                    keyring.delete_password(CACHE_SERVICE, CACHE_ACCOUNT)
                failed = _delete_windows_cache_manifest_entries(entries)
                if failed:
                    _write_windows_cache_cleanup(failed)
                    raise click.ClickException("The operating-system credential store is unavailable.")
                if entries:
                    keyring.delete_password(CACHE_SERVICE, _WINDOWS_CACHE_CLEANUP_ACCOUNT)
        else:
            serialized = keyring.get_password(CACHE_SERVICE, CACHE_ACCOUNT)
            if serialized is None:
                click.echo("No local GateBroker sign-in state was found.")
                return
            keyring.delete_password(CACHE_SERVICE, CACHE_ACCOUNT)
        click.echo("Signed out. Local GateBroker sign-in state has been removed.")
    except click.ClickException:
        raise
    except (KeyringError, PasswordDeleteError, OSError) as error:
        raise click.ClickException("The operating-system credential store is unavailable.") from error


def _selects_a_model(command: Sequence[str]) -> bool:
    """Report whether this agent needs a gateway model id named for it."""
    return (
        is_claude_command(command)
        or is_codex_command(command)
        or is_copilot_command(command)
    )


def _run_with_broker_environment(command: Sequence[str]) -> None:
    """Start one command with the token and gateway endpoint kept process-local."""
    _tenant_id, _client_id, _scope, base_url = _settings()
    environment = os.environ.copy()
    environment["OPENAI_BASE_URL"] = base_url
    environment["OPENAI_API_KEY"] = _acquire_access_token()
    environment["ANTHROPIC_BASE_URL"] = base_url.removesuffix("/v1")
    environment["ANTHROPIC_AUTH_TOKEN"] = environment["OPENAI_API_KEY"]
    # Copilot ignores OPENAI_BASE_URL; it selects a custom endpoint through its own
    # BYOK COPILOT_PROVIDER_* variables, so inject them when launching Copilot.
    environment = augment_copilot_environment(
        command,
        environment,
        base_url=base_url,
        token=environment["OPENAI_API_KEY"],
    )
    # Ask the broker what this user may use. The entitlement policy is the only place a
    # model list is declared, and the broker resolves one policy per caller, so this is
    # the only way to avoid carrying a stale copy here. Only asked for agents whose model
    # has to be named; there is no reason to make the request otherwise.
    available: tuple[str, ...] = ()
    if _selects_a_model(command):
        available = allowed_models(base_url=base_url, token=environment["OPENAI_API_KEY"])
    # Claude Code reaches the gateway from ANTHROPIC_BASE_URL alone, but defaults to
    # Anthropic's own model ids, which a policy is unlikely to list. Name allowed models
    # instead, or every request is refused with a generic 403.
    environment = augment_claude_environment(command, environment, available_models=available)
    # Codex ignores OPENAI_BASE_URL for provider/model selection; inject reviewed
    # non-secret -c overrides so gateway models appear instead of OpenAI defaults.
    launch_command = augment_codex_command(
        command,
        base_url=base_url,
        config_dir=_agents_file().parent,
        available=available,
    )
    try:
        # The configured argv is passed directly and never interpreted by a shell.
        completed = subprocess.run(  # nosec B603
            launch_command, check=False, env=environment
        )
    except FileNotFoundError as error:
        raise click.ClickException(
            f"Command not found: {command[0]}. Install it or pass its full path."
        ) from error
    except OSError as error:
        raise click.ClickException(
            f"Could not run command: {command[0]}. Check that it is executable."
        ) from error
    raise SystemExit(completed.returncode)


@main.command(name="configure", context_settings={"ignore_unknown_options": True})
@click.option("--reset", is_flag=True, help="Discard all existing launcher profiles first.")
@click.argument("agent")
@click.argument("command", nargs=-1, type=click.UNPROCESSED)
def configure_command(reset: bool, agent: str, command: Sequence[str]) -> None:
    """Save a non-secret launch profile: configure NAME -- COMMAND [ARGS...]."""
    _configure_local_agent(agent, command, reset=reset)


@main.command(name="run", context_settings={"ignore_unknown_options": True})
@click.argument("agent")
@click.argument("arguments", nargs=-1, type=click.UNPROCESSED)
def run_command(agent: str, arguments: Sequence[str]) -> None:
    """Run a configured local agent with an ephemeral broker credential."""
    command = _load_agents().get(agent)
    if command is None:
        raise click.ClickException(
            f"Local agent '{agent}' is not configured. "
            f"Configure it with: {_invocation()} configure {agent} -- {agent}"
        )
    _run_with_broker_environment([*command, *arguments])


@main.command(name="exec", context_settings={"ignore_unknown_options": True})
@click.argument("command", nargs=-1, type=click.UNPROCESSED)
def exec_command(command: Sequence[str]) -> None:
    """Run COMMAND with an ephemeral broker token in its process environment."""
    if not command:
        raise click.UsageError("Provide a command after --.")
    _run_with_broker_environment(command)


if __name__ == "__main__":  # pragma: no cover
    main()
