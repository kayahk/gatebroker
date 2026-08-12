# SPDX-License-Identifier: Apache-2.0
"""Copilot CLI provider helpers for gabro launches.

The GitHub Copilot CLI does not treat OPENAI_BASE_URL as a provider switch. It
selects a custom OpenAI-compatible endpoint through its own "bring your own key"
(BYOK) environment variables. When the CLI starts the Copilot agent, it therefore
injects reviewed COPILOT_PROVIDER_* variables so the session runs on an approved
gateway model instead of the built-in GitHub-hosted models:

- COPILOT_PROVIDER_BASE_URL -> the private gateway's OpenAI-compatible base URL;
- COPILOT_PROVIDER_TYPE     -> ``openai`` (the gateway is OpenAI-compatible);
- COPILOT_PROVIDER_API_KEY  -> the short-lived broker token (a secret);
- COPILOT_MODEL             -> an approved gateway model id (overridable via --model).

The base URL, provider type, and model id are non-secret. COPILOT_PROVIDER_API_KEY
carries the broker access token and must be treated as a secret even though it is
short-lived: it is injected only into the spawned Copilot child process, is never
written to disk, and must never be persisted in a Copilot configuration file.

Copilot BYOK selects a single model per launch; it does not enumerate the gateway
catalog into the interactive ``/model`` picker. Users pick another approved model by
relaunching with ``--model`` (or exporting ``COPILOT_MODEL``).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import PurePosixPath, PureWindowsPath

from gatebroker import profile

DEFAULT_COPILOT_MODEL = profile.default_model()
COPILOT_PROVIDER_TYPE = "openai"


def is_copilot_command(command: Sequence[str]) -> bool:
    """Return True when argv launches the standalone GitHub Copilot CLI."""
    if not command:
        return False
    raw = command[0]
    # Resolve basename for both POSIX and Windows paths even when this helper
    # runs on macOS/Linux during tests or cross-platform packaging.
    executable = PureWindowsPath(raw).name.lower() if "\\" in raw else PurePosixPath(raw).name.lower()
    return executable in {"copilot", "copilot.exe"}


def copilot_provider_environment(
    *, base_url: str, token: str, model: str = DEFAULT_COPILOT_MODEL
) -> dict[str, str]:
    """Return the Copilot BYOK provider variables for a launch.

    The base URL, provider type, and model id are non-secret; the returned
    ``COPILOT_PROVIDER_API_KEY`` holds the broker access token and must be treated
    as a secret (injected into the child process only, never persisted).
    """
    return {
        "COPILOT_PROVIDER_BASE_URL": base_url,
        "COPILOT_PROVIDER_TYPE": COPILOT_PROVIDER_TYPE,
        "COPILOT_PROVIDER_API_KEY": token,
        "COPILOT_MODEL": model,
    }


def augment_copilot_environment(
    command: Sequence[str],
    environment: Mapping[str, str],
    *,
    base_url: str,
    token: str,
) -> dict[str, str]:
    """Return environment with Copilot BYOK provider overrides when launching Copilot.

    Non-Copilot commands are returned unchanged. An existing COPILOT_MODEL in the
    caller's environment is preserved so users can pin a different approved model.
    """
    merged = dict(environment)
    if not is_copilot_command(command):
        return merged
    model = merged.get("COPILOT_MODEL") or DEFAULT_COPILOT_MODEL
    merged.update(copilot_provider_environment(base_url=base_url, token=token, model=model))
    return merged
