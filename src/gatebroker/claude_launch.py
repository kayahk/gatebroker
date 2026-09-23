# SPDX-License-Identifier: Apache-2.0
"""Claude Code model selection for gabro launches.

Claude Code honours ``ANTHROPIC_BASE_URL`` and ``ANTHROPIC_AUTH_TOKEN``, so it reaches the
gateway as soon as the CLI supplies those. Its *model* names are the problem: it defaults
to Anthropic's own ids, which an entitlement policy is unlikely to list, so every request
is refused with a generic 403 that says nothing about the cause. Without this, using Claude
means knowing to write

    gabro exec -- sh -c 'export ANTHROPIC_MODEL=... ANTHROPIC_SMALL_FAST_MODEL=...; claude'

which is not something a user could reasonably infer.

Claude Code has several slots (session, opus/sonnet/haiku/fable aliases, Plan Mode
Explore subagents). They all have to name the same allowed gateway model. Mapping those
aliases onto a cheap/expensive pair teaches a hierarchy the entitlement catalog does not
have, and leaving any slot on an Anthropic id makes Plan Mode fail with a generic 403.
One allowed id -- a router when the policy lists one, otherwise the preferred primary --
is enough.

No credential material is set here. The token is supplied separately and stays in the
spawned process.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import PurePosixPath, PureWindowsPath

from gatebroker import profile
from gatebroker.model_discovery import select_claude_model

MODEL_VARIABLE = "ANTHROPIC_MODEL"
SMALL_FAST_MODEL_VARIABLE = "ANTHROPIC_SMALL_FAST_MODEL"
# Family aliases Plan Mode and ``/model`` resolve independently of ANTHROPIC_MODEL.
OPUS_MODEL_VARIABLE = "ANTHROPIC_DEFAULT_OPUS_MODEL"
SONNET_MODEL_VARIABLE = "ANTHROPIC_DEFAULT_SONNET_MODEL"
HAIKU_MODEL_VARIABLE = "ANTHROPIC_DEFAULT_HAIKU_MODEL"
FABLE_MODEL_VARIABLE = "ANTHROPIC_DEFAULT_FABLE_MODEL"
# Explore/Plan subagents can send a full Anthropic id; this overrides that choice.
SUBAGENT_MODEL_VARIABLE = "CLAUDE_CODE_SUBAGENT_MODEL"
_MODEL_VARIABLES = (
    MODEL_VARIABLE,
    SMALL_FAST_MODEL_VARIABLE,
    OPUS_MODEL_VARIABLE,
    SONNET_MODEL_VARIABLE,
    HAIKU_MODEL_VARIABLE,
    FABLE_MODEL_VARIABLE,
    SUBAGENT_MODEL_VARIABLE,
)


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


def claude_model_environment(*, model: str) -> dict[str, str]:
    """Return the non-secret model variables Claude Code reads."""
    return {variable: model for variable in _MODEL_VARIABLES}


def _first_approved_pin(
    pins: tuple[str | None, ...], available_models: tuple[str, ...], default: str
) -> str:
    """Keep the first non-empty pin that discovery cannot reject or approves."""
    for pin in pins:
        if pin and (not available_models or pin in available_models):
            return pin
    return default


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
    default = select_claude_model(available_models, profile.primary_model())
    defaults = claude_model_environment(model=default)
    selected_small = _first_approved_pin(
        (environment.get(SMALL_FAST_MODEL_VARIABLE), environment.get(HAIKU_MODEL_VARIABLE)),
        available_models,
        default,
    )
    for key, value in defaults.items():
        if key not in {SMALL_FAST_MODEL_VARIABLE, HAIKU_MODEL_VARIABLE}:
            merged[key] = _first_approved_pin((merged.get(key),), available_models, value)
    merged[SMALL_FAST_MODEL_VARIABLE] = selected_small
    merged[HAIKU_MODEL_VARIABLE] = selected_small
    return merged
