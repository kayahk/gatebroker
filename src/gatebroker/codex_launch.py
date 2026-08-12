# SPDX-License-Identifier: Apache-2.0
"""Non-secret Codex provider/catalog helpers for gabro launches.

Codex does not treat OPENAI_BASE_URL as a model-provider switch. When the CLI
starts Codex, it therefore injects reviewed -c overrides that:

- point a custom provider at the private gateway Responses endpoint;
- select an approved gateway model id;
- install a local model catalog so the /model picker lists gateway models
  instead of only the built-in OpenAI presets.

No broker token or other credential material is written to disk.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from gatebroker import profile

APPROVED_CODEX_MODELS: tuple[tuple[str, str], ...] = profile.MODELS
DEFAULT_CODEX_MODEL = profile.default_model()
CODEX_PROVIDER_ID = "gabro"
CODEX_PROVIDER_NAME = profile.GATEWAY_NAME
CODEX_CATALOG_FILENAME = "codex-model-catalog.json"
_FALLBACK_BASE_INSTRUCTIONS = (
    f"You are Codex, a coding agent working through the {profile.GATEWAY_NAME} gateway. "
    "Collaborate with the user until their goal is handled."
)


def is_codex_command(command: Sequence[str]) -> bool:
    """Return True when argv launches the Codex CLI executable."""
    if not command:
        return False
    raw = command[0]
    # Resolve basename for both POSIX and Windows paths even when this helper
    # runs on macOS/Linux during tests or cross-platform packaging.
    executable = PureWindowsPath(raw).name.lower() if "\\" in raw else PurePosixPath(raw).name.lower()
    return executable in {"codex", "codex.exe"}


def codex_home() -> Path:
    """Return Codex's config home, honoring CODEX_HOME when set."""
    configured = os.environ.get("CODEX_HOME")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".codex"


def catalog_file(config_dir: Path) -> Path:
    """Return the path of the non-secret catalog written under the gabro config dir."""
    return config_dir / CODEX_CATALOG_FILENAME


def ensure_codex_model_catalog(config_dir: Path) -> Path:
    """Write/update the local Codex model catalog and return its path."""
    path = catalog_file(config_dir)
    document = {"models": _catalog_models(codex_home() / "models_cache.json")}
    _atomic_write_json(path, document)
    return path


def augment_codex_command(command: Sequence[str], *, base_url: str, config_dir: Path) -> list[str]:
    """Return command with Codex gateway provider/catalog overrides injected."""
    if not is_codex_command(command):
        return list(command)
    catalog_path = ensure_codex_model_catalog(config_dir)
    overrides = _cli_overrides(base_url=base_url, catalog_path=catalog_path)
    return [command[0], *overrides, *command[1:]]


def _cli_overrides(*, base_url: str, catalog_path: Path) -> list[str]:
    provider_prefix = f"model_providers.{CODEX_PROVIDER_ID}"
    return [
        "-c",
        f'model_provider="{CODEX_PROVIDER_ID}"',
        "-c",
        f'model="{DEFAULT_CODEX_MODEL}"',
        "-c",
        f'model_catalog_json="{catalog_path}"',
        "-c",
        f'{provider_prefix}.name="{CODEX_PROVIDER_NAME}"',
        "-c",
        f'{provider_prefix}.base_url="{base_url}"',
        "-c",
        f'{provider_prefix}.env_key="OPENAI_API_KEY"',
        "-c",
        f'{provider_prefix}.wire_api="responses"',
    ]


def _catalog_models(models_cache_path: Path) -> list[dict[str, Any]]:
    template = _template_model(models_cache_path)
    models: list[dict[str, Any]] = []
    for index, (slug, display_name) in enumerate(APPROVED_CODEX_MODELS, start=1):
        if template is None:
            models.append(_fallback_model(slug, display_name, priority=index))
            continue
        entry = dict(template)
        entry["slug"] = slug
        entry["display_name"] = display_name
        entry["description"] = f"Approved gateway model ({slug})."
        entry["priority"] = index
        entry["visibility"] = "list"
        entry["supported_in_api"] = True
        for key in ("comp_hash", "upgrade", "availability_nux"):
            entry.pop(key, None)
        models.append(entry)
    return models


def _template_model(models_cache_path: Path) -> dict[str, Any] | None:
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(models_cache_path, flags)
        with os.fdopen(descriptor, encoding="utf-8") as cache_file:
            info = os.fstat(cache_file.fileno())
            if not stat.S_ISREG(info.st_mode):
                return None
            payload = json.load(cache_file)
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(payload, Mapping):
        return None
    models = payload.get("models")
    if not isinstance(models, list):
        return None
    for candidate in models:
        if (
            isinstance(candidate, dict)
            and isinstance(candidate.get("slug"), str)
            and (
                isinstance(candidate.get("base_instructions"), str)
                or isinstance((candidate.get("model_messages") or {}).get("instructions_template"), str)
            )
        ):
            return candidate
    return None


def _fallback_model(slug: str, display_name: str, *, priority: int) -> dict[str, Any]:
    return {
        "slug": slug,
        "display_name": display_name,
        "description": f"Approved gateway model ({slug}).",
        "default_reasoning_level": "high",
        "supported_reasoning_levels": [
            {"effort": "low", "description": "Fast responses with lighter reasoning"},
            {"effort": "medium", "description": "Balances speed and reasoning depth"},
            {"effort": "high", "description": "Greater reasoning depth for complex problems"},
            {"effort": "xhigh", "description": "Extra high reasoning depth for complex problems"},
        ],
        "shell_type": "shell_command",
        "visibility": "list",
        "supported_in_api": True,
        "priority": priority,
        "context_window": 272000,
        "max_context_window": 272000,
        "effective_context_window_percent": 95,
        "truncation_policy": {"mode": "tokens", "limit": 272000},
        "support_verbosity": True,
        "default_verbosity": "medium",
        "supports_parallel_tool_calls": True,
        "experimental_supported_tools": [],
        "apply_patch_tool_type": "freeform",
        "input_modalities": ["text"],
        "tool_mode": "default",
        "base_instructions": _FALLBACK_BASE_INSTRUCTIONS,
    }


def _atomic_write_json(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_info = path.parent.stat(follow_symlinks=False)
    if not stat.S_ISDIR(parent_info.st_mode) or path.parent.is_symlink():
        raise OSError("unsafe catalog directory")
    if sys.platform != "win32" and (
        parent_info.st_mode & 0o022
        or (hasattr(os, "getuid") and parent_info.st_uid != os.getuid())
    ):
        raise OSError("unsafe catalog directory permissions")
    descriptor, temporary_path = tempfile.mkstemp(
        dir=path.parent,
        prefix=".codex-catalog-",
        suffix=".tmp",
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if sys.platform != "win32":
            os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
    except Exception:
        with suppress(OSError):
            os.unlink(temporary_path)
        raise
