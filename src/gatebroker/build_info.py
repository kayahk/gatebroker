# SPDX-License-Identifier: Apache-2.0
"""Runtime version and release-build provenance for ``gabro``."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

_DISTRIBUTION_NAME = "gatebroker"
_MANIFEST_NAME = "gabro_build_info.json"
_UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class BuildInfo:
    """Non-secret identity data for one CLI build."""

    version: str
    build: str
    revision: str


def _source_build_info() -> BuildInfo:
    """Return metadata for an installed Python distribution without Git probing."""
    try:
        package_version = version(_DISTRIBUTION_NAME)
    except PackageNotFoundError:
        package_version = _UNAVAILABLE
    return BuildInfo(version=package_version, build="source", revision=_UNAVAILABLE)


def _release_build_info(path: Path) -> BuildInfo | None:
    """Return validated embedded build metadata, or ``None`` when unavailable."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    build = payload.get("build")
    package_version = payload.get("version")
    revision = payload.get("revision")
    if build != "release" or not all(
        isinstance(value, str) and value for value in (package_version, revision)
    ):
        return None
    return BuildInfo(version=package_version, build=build, revision=revision)


def build_info() -> BuildInfo:
    """Return installed-package or embedded-release identity data."""
    bundle_root = getattr(sys, "_MEIPASS", None) if getattr(sys, "frozen", False) else None
    if isinstance(bundle_root, str):
        release = _release_build_info(Path(bundle_root) / _MANIFEST_NAME)
        if release is not None:
            return release
        return BuildInfo(version=_UNAVAILABLE, build=_UNAVAILABLE, revision=_UNAVAILABLE)
    return _source_build_info()
