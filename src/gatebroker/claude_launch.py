# SPDX-License-Identifier: Apache-2.0
"""Claude Code model selection for gabro launches.

Claude Code honours ``ANTHROPIC_BASE_URL`` and ``ANTHROPIC_AUTH_TOKEN``, so it reaches the
gateway as soon as the CLI supplies those. Its *model* names are the problem: it defaults
to Anthropic's own ids, which an entitlement policy is unlikely to list, so every request
is refused with a generic 403 that says nothing about the cause. Without this, using Claude
means knowing to write

    gabro exec -- sh -c 'export ANTHROPIC_MODEL=... ANTHROPIC_SMALL_FAST_MODEL=...; claude'

which is not something a user could reasonably infer.

Claude Code asks for two models: the main one, and a cheaper one for background work such
as summarising and titling. Both have to name models the policy allows, or the background
requests fail on their own while the session appears healthy.

No credential material is set here. The token is supplied separately and stays in the
spawned process.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import PurePosixPath, PureWindowsPath

from gatebroker import profile
from gatebroker.model_discovery import select

MODEL_VARIABLE = "ANTHROPIC_MODEL"
SMALL_FAST_MODEL_VARIABLE = "ANTHROPIC_SMALL_FAST_MODEL"


def is_claude_command(command: Sequence[str]) -> bool:
    """Return True when argv launches the Claude Code CLI."""
    if not command:
        return False
    raw = command[0]
    # Resolve basename for both POSIX and Windows paths even when this helper runs on
    # macOS/Linux during tests or cross-platform packaging.
    executable = (
        PureWindowsPath(raw).name.lower() if "\\" in raw else PurePosixPath(raw).name.lower()
    )
    return executable in {"claude", "claude.exe"}


def claude_model_environment(*, model: str, small_fast_model: str) -> dict[str, str]:
    """Return the non-secret model variables Claude Code reads."""
    return {
        MODEL_VARIABLE: model,
        SMALL_FAST_MODEL_VARIABLE: small_fast_model,
    }


def augment_claude_environment(
    command: Sequence[str],
    environment: Mapping[str, str],
    *,
    available_models: tuple[str, ...] = (),
) -> dict[str, str]:
    """Return environment with allowed gateway models set when launching Claude Code.

    ``available_models`` is what the broker reported for this caller. Only those are
    considered, so Claude is never pointed at a model the policy withholds. With nothing
    discovered the profile's models are used, which keeps the agent startable.

    Non-Claude commands are returned unchanged. A value the caller already set is
    preserved, so pinning a different allowed model still works.
    """
    merged = dict(environment)
    if not is_claude_command(command):
        return merged
    preference = profile.model_preference()
    merged.update(
        claude_model_environment(
            model=merged.get(MODEL_VARIABLE)
            or select(preference, available_models, profile.primary_model()),
            small_fast_model=merged.get(SMALL_FAST_MODEL_VARIABLE)
            or select(
                (profile.small_fast_model(), *reversed(preference)),
                available_models,
                profile.small_fast_model(),
            ),
        )
    )
    return merged
