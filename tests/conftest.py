# SPDX-License-Identifier: Apache-2.0
"""Shared test setup.

The shipped ``gatebroker.profile`` is an unconfigured placeholder, and the CLI
refuses to acquire a token while ``CONFIGURED`` is False. Most tests exercise the
behaviour of a *configured* distribution, so they run with the placeholder values
marked configured. ``test_cli.py`` covers the unconfigured refusal explicitly.
"""

from __future__ import annotations

import pytest

from gatebroker import profile


@pytest.fixture(autouse=True)
def configured_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(profile, "CONFIGURED", True)
