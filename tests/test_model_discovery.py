# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import io
import json
import urllib.error
from unittest.mock import Mock

import pytest
from click.testing import CliRunner

import gatebroker.cli as cli
from gatebroker import model_discovery, profile
from gatebroker.model_discovery import allowed_models, select


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def _serves(payload: object, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    seen: list[str] = []

    def urlopen(request, timeout=None):  # noqa: ARG001
        seen.append(request.full_url)
        seen.append(request.get_header("Authorization"))
        return _Response(json.dumps(payload).encode())

    monkeypatch.setattr(model_discovery.urllib.request, "urlopen", urlopen)
    return seen


def test_reads_the_models_the_broker_reports(monkeypatch) -> None:
    seen = _serves({"object": "list", "data": [{"id": "a"}, {"id": "b"}]}, monkeypatch)

    assert allowed_models(base_url="https://gw.test/v1", token="t") == ("a", "b")
    assert seen[0] == "https://gw.test/v1/models"
    assert seen[1] == "Bearer t"


@pytest.mark.parametrize(
    "payload",
    [{"data": "not-a-list"}, {"data": [{"no_id": 1}, {"id": ""}, {"id": 5}]}, {}, [], "nonsense"],
)
def test_a_malformed_answer_reads_as_nothing_discovered(monkeypatch, payload) -> None:
    _serves(payload, monkeypatch)

    assert allowed_models(base_url="https://gw.test/v1", token="t") == ()


@pytest.mark.parametrize(
    "failure",
    [
        urllib.error.URLError("unreachable"),
        urllib.error.HTTPError("https://gw.test/v1/models", 403, "denied", {}, None),
        TimeoutError("slow"),
        OSError("socket"),
    ],
)
def test_discovery_failure_is_not_fatal(monkeypatch, failure) -> None:
    """An agent must still start when a metadata request fails."""

    def urlopen(_request, timeout=None):  # noqa: ARG001
        raise failure

    monkeypatch.setattr(model_discovery.urllib.request, "urlopen", urlopen)

    assert allowed_models(base_url="https://gw.test/v1", token="t") == ()


def test_selection_never_names_a_model_the_policy_withheld() -> None:
    """The broker refuses an unlisted model with an uninformative 403."""
    available = ("only-this-one",)

    assert select(profile.model_preference(), available, profile.primary_model()) == "only-this-one"


def test_selection_prefers_the_ranked_model_among_those_allowed() -> None:
    preference = profile.model_preference()

    assert select(preference, tuple(reversed(preference)), "fallback") == preference[0]


def test_selection_falls_back_only_when_nothing_was_discovered() -> None:
    assert select(profile.model_preference(), (), "compiled-default") == "compiled-default"


def test_selection_accepts_a_model_this_build_has_never_heard_of() -> None:
    assert select(profile.model_preference(), ("brand-new",), "x") == "brand-new"


def test_launching_claude_uses_the_discovered_models(monkeypatch) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(cli, "_acquire_access_token", lambda: "ephemeral-token")
    monkeypatch.setattr(cli, "allowed_models", lambda **_kwargs: ("policy-only-model",))
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda command, check, env: captured.update({"env": env}) or Mock(returncode=0),
    )

    result = CliRunner().invoke(cli.main, ["exec", "--", "claude"])

    assert result.exit_code == 0
    assert captured["env"]["ANTHROPIC_MODEL"] == "policy-only-model"
    assert captured["env"]["ANTHROPIC_SMALL_FAST_MODEL"] == "policy-only-model"


def test_discovery_is_skipped_for_agents_that_do_not_need_a_model(monkeypatch) -> None:
    asked = False

    def discover(**_kwargs):
        nonlocal asked
        asked = True
        return ()

    monkeypatch.setattr(cli, "_acquire_access_token", lambda: "ephemeral-token")
    monkeypatch.setattr(cli, "allowed_models", discover)
    monkeypatch.setattr(cli.subprocess, "run", lambda command, check, env: Mock(returncode=0))

    CliRunner().invoke(cli.main, ["exec", "--", "some-other-agent"])
    assert asked is False

    CliRunner().invoke(cli.main, ["exec", "--", "claude"])
    assert asked is True
