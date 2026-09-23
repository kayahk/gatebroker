# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json

import gatebroker.build_info as build_info


def test_source_build_uses_installed_distribution_metadata(monkeypatch) -> None:
    monkeypatch.setattr(build_info, "version", lambda name: "1.2.3")
    monkeypatch.setattr(build_info.sys, "frozen", False, raising=False)

    assert build_info.build_info() == build_info.BuildInfo(
        version="1.2.3", build="source", revision="unavailable"
    )


def test_frozen_build_reads_embedded_release_manifest(tmp_path, monkeypatch) -> None:
    (tmp_path / "gabro_build_info.json").write_text(
        json.dumps({"build": "release", "revision": "a" * 40, "version": "1.2.3"}),
        encoding="utf-8",
    )
    monkeypatch.setattr(build_info.sys, "frozen", True, raising=False)
    monkeypatch.setattr(build_info.sys, "_MEIPASS", str(tmp_path), raising=False)

    assert build_info.build_info() == build_info.BuildInfo(
        version="1.2.3", build="release", revision="a" * 40
    )


def test_frozen_build_with_invalid_manifest_returns_safe_fallback(tmp_path, monkeypatch) -> None:
    (tmp_path / "gabro_build_info.json").write_text("not json", encoding="utf-8")
    monkeypatch.setattr(build_info.sys, "frozen", True, raising=False)
    monkeypatch.setattr(build_info.sys, "_MEIPASS", str(tmp_path), raising=False)

    assert build_info.build_info() == build_info.BuildInfo(
        version="unavailable", build="unavailable", revision="unavailable"
    )
