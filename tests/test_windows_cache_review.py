from __future__ import annotations

import json
from contextlib import contextmanager

import click
import pytest

from gatebroker import cli


def memory_keyring(monkeypatch):
    stored = {}
    monkeypatch.setattr(cli.keyring, "get_password", lambda service, account: stored.get((service, account)))
    monkeypatch.setattr(cli.keyring, "set_password", lambda service, account, value: stored.__setitem__((service, account), value))
    monkeypatch.setattr(cli.keyring, "delete_password", lambda service, account: stored.pop((service, account), None))
    return stored


@contextmanager
def no_lock():
    yield


def win(monkeypatch):
    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli, "_windows_cache_lock", no_lock)
    monkeypatch.setattr(cli, "_require_secure_keyring", lambda: None)
    monkeypatch.setattr(cli, "_invocation", lambda: "gabro")


def test_cleanup_record_merges_existing_entries(monkeypatch):
    stored = memory_keyring(monkeypatch)
    win(monkeypatch)
    first = ("a" * 32, 1)
    second = ("b" * 32, 2)
    stored[(cli.CACHE_SERVICE, cli._WINDOWS_CACHE_CLEANUP_ACCOUNT)] = json.dumps({"cleanup": [{"generation": first[0], "count": first[1]}]})
    cli._record_windows_cache_cleanup([second])
    assert json.loads(stored[(cli.CACHE_SERVICE, cli._WINDOWS_CACHE_CLEANUP_ACCOUNT)]) == {
        "cleanup": [{"generation": first[0], "count": 1}, {"generation": second[0], "count": 2}]
    }


@pytest.mark.parametrize("value", ["not-json", json.dumps({"cleanup": [{"generation": "bad", "count": 1}]})])
def test_malformed_standalone_cleanup_fails_closed(monkeypatch, value):
    stored = memory_keyring(monkeypatch)
    win(monkeypatch)
    stored[(cli.CACHE_SERVICE, cli._WINDOWS_CACHE_CLEANUP_ACCOUNT)] = value
    with pytest.raises(click.ClickException, match="stored sign-in state is invalid"):
        cli._store_cache("small")


@pytest.mark.parametrize("source", ["embedded", "standalone"])
def test_conflicting_active_cleanup_count_fails_closed_before_primary_write(monkeypatch, source):
    stored = memory_keyring(monkeypatch)
    win(monkeypatch)
    active = ("a" * 32, 2)
    conflicting = (active[0], 1)
    manifest_cleanup: list[tuple[str, int]] = [conflicting] if source == "embedded" else []
    stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)] = cli._windows_cache_manifest_document(
        active[0], active[1], manifest_cleanup
    )
    for index in range(active[1]):
        stored[(cli.CACHE_SERVICE, cli._cache_chunk_account(active[0], index))] = f"active-{index}"
    if source == "standalone":
        stored[(cli.CACHE_SERVICE, cli._WINDOWS_CACHE_CLEANUP_ACCOUNT)] = json.dumps(
            {"cleanup": [{"generation": conflicting[0], "count": conflicting[1]}]}
        )

    with pytest.raises(click.ClickException, match="stored sign-in state is invalid"):
        cli._store_cache("small")

    assert stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)] == cli._windows_cache_manifest_document(
        active[0], active[1], manifest_cleanup
    )
    assert [stored[(cli.CACHE_SERVICE, cli._cache_chunk_account(active[0], index))] for index in range(active[1])] == [
        "active-0",
        "active-1",
    ]


@pytest.mark.parametrize("source", ["embedded", "standalone"])
def test_duplicate_cleanup_generation_with_conflicting_counts_fails_closed(monkeypatch, source):
    stored = memory_keyring(monkeypatch)
    win(monkeypatch)
    duplicate = "b" * 32
    cleanup = [(duplicate, 1), (duplicate, 2)]
    if source == "embedded":
        stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)] = cli._windows_cache_manifest_document("a" * 32, 1, cleanup)
    else:
        stored[(cli.CACHE_SERVICE, cli._WINDOWS_CACHE_CLEANUP_ACCOUNT)] = json.dumps(
            {"cleanup": [{"generation": generation, "count": count} for generation, count in cleanup]}
        )

    with pytest.raises(click.ClickException, match="stored sign-in state is invalid"):
        cli._store_cache("small")


def test_merging_conflicting_cleanup_generation_counts_fails_closed():
    generation = "a" * 32

    with pytest.raises(click.ClickException, match="stored sign-in state is invalid"):
        cli._merge_windows_cache_entries([(generation, 1)], [(generation, 2)])


def test_load_sanitization_does_not_reenter_windows_lock(monkeypatch):
    memory_keyring(monkeypatch)
    held = False
    events = []

    @contextmanager
    def tracking_lock():
        nonlocal held
        assert not held
        held = True
        events.append("lock")
        try:
            yield
        finally:
            held = False
            events.append("unlock")

    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli, "_require_secure_keyring", lambda: None)
    monkeypatch.setattr(cli, "_windows_cache_lock", tracking_lock)
    monkeypatch.setattr(cli.keyring, "get_password", lambda service, account: '{"IdToken":{"x":1}}' if account == cli.CACHE_ACCOUNT else None)
    monkeypatch.setattr(cli.keyring, "set_password", lambda service, account, value: events.append(("set", held)))
    cli._load_cache()
    assert events == ["lock", ("set", True), "unlock"]


def test_logout_covers_standalone_cleanup_and_malformed_manifest_fails_closed(monkeypatch):
    stored = memory_keyring(monkeypatch)
    win(monkeypatch)
    generation = "a" * 32
    stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)] = cli._windows_cache_manifest_document(generation, 1, [])
    stored[(cli.CACHE_SERVICE, cli._cache_chunk_account(generation, 0))] = "secret"
    extra = "b" * 32
    stored[(cli.CACHE_SERVICE, cli._WINDOWS_CACHE_CLEANUP_ACCOUNT)] = json.dumps({"cleanup": [{"generation": extra, "count": 1}]})
    stored[(cli.CACHE_SERVICE, cli._cache_chunk_account(extra, 0))] = "old-secret"
    result = cli.logout.callback()
    assert result is None
    assert stored == {}

    stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)] = json.dumps({cli._WINDOWS_CACHE_MANIFEST_KEY: {"generation": "bad", "count": 1}})
    with pytest.raises(click.ClickException, match="stored sign-in state is invalid"):
        cli.logout.callback()


@pytest.mark.parametrize("replacement", ["small", "x" * 2000])
def test_manifest_embedded_cleanup_is_migrated_before_replacement(monkeypatch, replacement):
    stored = memory_keyring(monkeypatch)
    win(monkeypatch)
    active = ("a" * 32, 1)
    legacy_cleanup = ("b" * 32, 1)
    stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)] = cli._windows_cache_manifest_document(
        active[0], active[1], [legacy_cleanup]
    )
    stored[(cli.CACHE_SERVICE, cli._cache_chunk_account(active[0], 0))] = "active-secret"
    stored[(cli.CACHE_SERVICE, cli._cache_chunk_account(legacy_cleanup[0], 0))] = "old-secret"

    cli._store_cache(replacement)

    journal = cli._pending_windows_cache_cleanup()
    assert active in journal
    assert legacy_cleanup in journal or (
        cli.CACHE_SERVICE,
        cli._cache_chunk_account(legacy_cleanup[0], 0),
    ) not in stored


@pytest.mark.parametrize(
    "document",
    [
        json.dumps({cli._WINDOWS_CACHE_MANIFEST_KEY: {"generation": "a" * 32, "count": 1}, "unexpected": True}),
        json.dumps({cli._WINDOWS_CACHE_MANIFEST_KEY: {"generation": "a" * 32, "count": 1, "unexpected": True}}),
        json.dumps({cli._WINDOWS_CACHE_MANIFEST_KEY: {"generation": "a" * 32, "count": 1, "cleanup": [{"generation": "b" * 32, "count": 1, "unexpected": True}]}}),
        '{"windows-cache-chunks":{"generation":"' + "a" * 32 + '","generation":"' + "b" * 32 + '","count":1}}',
        '{"windows-cache-ch\\u0075nks":{"generation":"' + "a" * 32 + '","count":1},"windows-cache-chunks":{"generation":"' + "b" * 32 + '","count":1}}',
    ],
)
def test_non_exact_or_duplicate_primary_manifest_fails_closed_everywhere(monkeypatch, document):
    stored = memory_keyring(monkeypatch)
    win(monkeypatch)
    stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)] = document

    with pytest.raises(click.ClickException, match="stored sign-in state is invalid"):
        cli._load_windows_chunked_cache(document)
    with pytest.raises(click.ClickException, match="stored sign-in state is invalid"):
        cli._store_cache("small")
    with pytest.raises(click.ClickException, match="stored sign-in state is invalid"):
        cli.logout.callback()
    assert stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)] == document


@pytest.mark.parametrize(
    "document",
    [
        '{"windows-cache-chunks":{"generation":"' + "a" * 32 + '","count":1',
        '{"windows-cache-ch\\u0075nks":{"generation":"' + "a" * 32 + '","count":1}} trailing',
    ],
)
def test_manifest_looking_malformed_primary_and_chunks_are_preserved(monkeypatch, document):
    stored = memory_keyring(monkeypatch)
    win(monkeypatch)
    chunk_account = cli._cache_chunk_account("a" * 32, 0)
    stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)] = document
    stored[(cli.CACHE_SERVICE, chunk_account)] = "sensitive chunk"
    original = stored.copy()

    with pytest.raises(click.ClickException, match="stored sign-in state is invalid"):
        cli._load_windows_chunked_cache(document)
    with pytest.raises(click.ClickException, match="stored sign-in state is invalid"):
        cli._store_cache("replacement")
    with pytest.raises(click.ClickException, match="stored sign-in state is invalid"):
        cli.logout.callback()

    assert stored == original


@pytest.mark.parametrize(
    "key_spelling",
    [
        cli._WINDOWS_CACHE_MANIFEST_KEY,
        "windows-cache-ch\\u0075nks",
    ],
    ids=["literal", "unicode-escaped-u"],
)
def test_truncated_reserved_manifest_key_fails_closed_and_preserves_chunks(monkeypatch, key_spelling):
    for boundary in range(1, len(key_spelling) + 1):
        stored = memory_keyring(monkeypatch)
        win(monkeypatch)
        document = '{"' + key_spelling[:boundary]
        chunk_account = cli._cache_chunk_account("a" * 32, 0)
        stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)] = document
        stored[(cli.CACHE_SERVICE, chunk_account)] = "sensitive chunk"
        original = stored.copy()

        with pytest.raises(click.ClickException, match="stored sign-in state is invalid"):
            cli._load_windows_chunked_cache(document)
        with pytest.raises(click.ClickException, match="stored sign-in state is invalid"):
            cli._store_cache("replacement")
        with pytest.raises(click.ClickException, match="stored sign-in state is invalid"):
            cli.logout.callback()

        assert stored == original


def test_valid_ordinary_msal_cache_is_not_manifest_like(monkeypatch):
    stored = memory_keyring(monkeypatch)
    win(monkeypatch)
    document = json.dumps({"RefreshToken": {"windows-cache-chunks": "ordinary cache value"}})
    stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)] = document

    assert cli._load_windows_chunked_cache(document) == document
    cli._store_cache("replacement")
    assert stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)] == "replacement"


@pytest.mark.parametrize("chunked", [False, True], ids=["direct", "chunked"])
@pytest.mark.parametrize(
    "payload",
    [
        '{"RefreshToken":{},"RefreshToken":{}}',
        '{"RefreshToken":{"value":NaN}}',
        '{"RefreshToken":{"value":Infinity}}',
        '{"RefreshToken":{"value":-Infinity}}',
    ],
    ids=["duplicate-key", "nan", "infinity", "negative-infinity"],
)
def test_ambiguous_or_nonstandard_cache_payload_is_rejected(monkeypatch, chunked, payload):
    stored = memory_keyring(monkeypatch)
    win(monkeypatch)
    if chunked:
        generation = "a" * 32
        stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)] = cli._windows_cache_manifest_document(generation, 1, [])
        stored[(cli.CACHE_SERVICE, cli._cache_chunk_account(generation, 0))] = payload
    else:
        stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)] = payload
    original = stored.copy()

    with pytest.raises(click.ClickException, match="stored sign-in state is invalid"):
        cli._load_cache()

    assert stored == original


@pytest.mark.parametrize(
    "document",
    [
        json.dumps({"cleanup": [], "unexpected": True}),
        json.dumps({"cleanup": [{"generation": "a" * 32, "count": 1, "unexpected": True}]}),
        '{"cleanup":[],"clean\\u0075p":[]}',
    ],
)
def test_non_exact_or_duplicate_standalone_cleanup_fails_closed(monkeypatch, document):
    stored = memory_keyring(monkeypatch)
    win(monkeypatch)
    stored[(cli.CACHE_SERVICE, cli._WINDOWS_CACHE_CLEANUP_ACCOUNT)] = document

    with pytest.raises(click.ClickException, match="stored sign-in state is invalid"):
        cli._store_cache("small")
    with pytest.raises(click.ClickException, match="stored sign-in state is invalid"):
        cli.logout.callback()
    assert stored[(cli.CACHE_SERVICE, cli._WINDOWS_CACHE_CLEANUP_ACCOUNT)] == document


def test_generation_collision_retries_before_chunk_writes_and_preserves_active_cache(monkeypatch):
    stored = memory_keyring(monkeypatch)
    win(monkeypatch)
    active = "a" * 32
    replacement = "b" * 32
    payload = "x" * 2000
    old_manifest = cli._windows_cache_manifest_document(active, 2, [])
    stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)] = old_manifest
    for index in range(2):
        stored[(cli.CACHE_SERVICE, cli._cache_chunk_account(active, index))] = f"old-{index}"
    generations = iter([active, replacement])
    monkeypatch.setattr(cli.secrets, "token_hex", lambda _: next(generations))
    real_set = cli.keyring.set_password

    def fail_second_replacement_chunk(service, account, value):
        if account == cli._cache_chunk_account(replacement, 1):
            raise OSError("write")
        real_set(service, account, value)

    monkeypatch.setattr(cli.keyring, "set_password", fail_second_replacement_chunk)
    with pytest.raises(click.ClickException, match="credential store is unavailable"):
        cli._store_cache(payload)

    assert stored[(cli.CACHE_SERVICE, cli.CACHE_ACCOUNT)] == old_manifest
    assert [stored[(cli.CACHE_SERVICE, cli._cache_chunk_account(active, index))] for index in range(2)] == ["old-0", "old-1"]


def test_failed_chunk_write_is_pretracked_before_any_chunk_write(monkeypatch):
    stored = memory_keyring(monkeypatch)
    win(monkeypatch)
    calls = []
    real_set = cli.keyring.set_password
    generation = "c" * 32
    monkeypatch.setattr(cli.secrets, "token_hex", lambda _: generation)

    def fail_chunk(service, account, value):
        calls.append(account)
        if account == cli._cache_chunk_account(generation, 0):
            raise OSError("write")
        real_set(service, account, value)

    monkeypatch.setattr(cli.keyring, "set_password", fail_chunk)
    with pytest.raises(click.ClickException):
        cli._store_cache("x" * 2000)
    assert calls[0] == cli._WINDOWS_CACHE_CLEANUP_ACCOUNT
    assert (cli.CACHE_SERVICE, cli.CACHE_ACCOUNT) not in stored
    expected_count = len(cli._split_windows_cache("x" * 2000))
    assert json.loads(stored[(cli.CACHE_SERVICE, cli._WINDOWS_CACHE_CLEANUP_ACCOUNT)])["cleanup"] == [{"generation": generation, "count": expected_count}]
