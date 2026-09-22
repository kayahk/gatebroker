# SPDX-License-Identifier: Apache-2.0
"""Ask the broker which models the signed-in user may actually use.

An entitlement policy is the only place a model list is declared, and the broker resolves
exactly one policy per caller, so the broker is the one component that knows the answer
for *this* user. Anything a client hardcodes is a copy: it drifts as soon as the policy
changes, and it pins people to a subset of what they are entitled to. A policy written to
track a whole gateway catalog is exactly the case a fixed list gets wrong.

Discovery is best-effort on purpose. Launching an agent must not fail because a metadata
request did, so a failure falls back to the distribution profile and lets the agent start.
If the caller genuinely has no entitlement, their first real request fails anyway -- with
the broker's answer rather than a guess made here.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from gatebroker import profile

_ROUTER_MARKERS = ("auto-router", "auto_router", "autorouter", "smart-router")
_TIMEOUT_SECONDS = 10


def allowed_models(*, base_url: str, token: str) -> tuple[str, ...]:
    """Return the caller's allowed models, or an empty tuple if they cannot be read."""
    endpoint = f"{base_url.rstrip('/')}/models"
    request = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:  # nosec B310
            document = json.load(response)
    except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError):
        return ()
    entries = document.get("data") if isinstance(document, dict) else None
    if not isinstance(entries, list):
        return ()
    return tuple(
        entry["id"]
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("id"), str) and entry["id"]
    )


def select(preferences: tuple[str, ...], available: tuple[str, ...], fallback: str) -> str:
    """Choose the most preferred model the caller is allowed to use.

    With nothing discovered, the profile's fallback is used so the agent still starts.
    With models discovered, only those are considered: never name one the caller's policy
    withholds, because the broker refuses it with a deliberately uninformative 403.
    """
    if not available:
        return fallback
    for preferred in preferences:
        if preferred in available:
            return preferred
    # The policy may allow something this build has never heard of, which is the point.
    return available[0]


def looks_like_router(model_id: str) -> bool:
    """Return whether an entitled id denotes a generic auto-router.

    Only the final path segment is classified, and markers must match that
    segment exactly so leaf ids that merely contain those words are left alone.
    """
    basename = model_id.casefold().rsplit("/", 1)[-1]
    return basename == "auto" or basename.endswith("-auto") or basename in _ROUTER_MARKERS


def select_router(available: tuple[str, ...]) -> str | None:
    """Return the first entitled auto-router, if the policy lists one."""
    return next((model for model in available if looks_like_router(model)), None)


def select_claude_model(available: tuple[str, ...], fallback: str) -> str:
    """Select one entitled model for every Claude Code family slot.

    A router is preferred because Claude's family aliases are not entitlement model IDs.
    The fallback is used only when discovery failed; otherwise selection stays within the
    models the broker reported for this caller.
    """
    return select_router(available) or select(profile.model_preference(), available, fallback)
