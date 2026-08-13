# SPDX-License-Identifier: Apache-2.0
"""Shared test setup.

The shipped ``gatebroker.profile`` is an unconfigured placeholder, and the CLI refuses
to acquire a token while ``CONFIGURED`` is False. Most tests exercise the behaviour of a
*configured* distribution, so they run with the placeholder values marked configured.
``test_cli.py`` covers the unconfigured refusal explicitly.
"""

from __future__ import annotations

import importlib
import os

import pytest

from gatebroker import profile

# A developer who has exported GABRO_DEV_PROFILE to try the demo would otherwise change
# what the suite is testing: the profile module applies that file at import time, so
# MODELS and the rest would carry demo values. Drop it and reload before any test module
# imports something that captures those values at import time.
if os.environ.pop("GABRO_DEV_PROFILE", None) is not None:
    profile = importlib.reload(profile)


@pytest.fixture(autouse=True)
def configured_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(profile, "CONFIGURED", True)
