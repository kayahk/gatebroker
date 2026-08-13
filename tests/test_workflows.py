# SPDX-License-Identifier: Apache-2.0
"""Supply-chain properties of the release pipeline that must not regress."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
IMAGE_WORKFLOW = WORKFLOWS / "build-push-image.yaml"
RELEASE_WORKFLOW = WORKFLOWS / "release-cli.yaml"
DOCKERFILE = ROOT / "Dockerfile"


def test_every_third_party_action_is_pinned_to_a_commit() -> None:
    for workflow in WORKFLOWS.glob("*.yaml"):
        for action in re.findall(r"uses:\s+[^@\s]+@([^\s#]+)", workflow.read_text()):
            assert re.fullmatch(r"[0-9a-f]{40}", action), (workflow.name, action)


def test_container_image_is_non_root_and_built_from_the_lockfile() -> None:
    contents = DOCKERFILE.read_text(encoding="utf-8")

    assert "FROM python:3.11-slim@sha256:" in contents
    assert "COPY --from=ghcr.io/astral-sh/uv@sha256:" in contents
    assert "uv sync --locked --no-dev --no-editable" in contents
    assert "chown broker:broker /app" in contents
    assert "USER broker" in contents
    assert 'CMD ["python", "-m", "gatebroker.runtime"]' in contents


def test_published_images_are_addressable_by_immutable_digest_not_latest() -> None:
    workflow = IMAGE_WORKFLOW.read_text(encoding="utf-8")

    assert "${GITHUB_SHA}" in workflow
    assert ":latest" not in workflow
    assert "attest-build-provenance" in workflow
    assert "org.opencontainers.image.licenses=Apache-2.0" in workflow


def test_release_refuses_to_ship_an_unconfigured_distribution_profile() -> None:
    """A signed artifact must never point users at the placeholder endpoint."""
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")

    assert "Refuse to ship an unconfigured distribution profile" in workflow
    assert "if not profile.CONFIGURED:" in workflow
    # A development profile must not be able to satisfy the gate either.
    assert "if profile.DEVELOPMENT:" in workflow


def test_release_builds_every_supported_platform_with_checksums() -> None:
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")

    assert "macos-14" in workflow
    assert "ubuntu-24.04" in workflow
    assert "windows-2025" in workflow
    assert "PyInstaller" in workflow
    assert "hashlib.sha256()" in workflow
    # Read in chunks: a release asset must not be loaded into memory whole.
    assert "source.read(1024 * 1024)" in workflow
    assert "read_bytes()" not in workflow
    assert 'python-version: "3.11"' in workflow


def test_release_signs_macos_when_configured_and_labels_it_when_not() -> None:
    """A fork without an Apple account still gets a release, clearly unsigned."""
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")

    assert "codesign --force --options runtime --timestamp" in workflow
    assert "xcrun notarytool submit" in workflow
    assert "xcrun stapler staple" in workflow
    assert "spctl --assess --type install" in workflow
    assert "gabro-macos-arm64-unsigned.tar.gz" in workflow
    assert "steps.macos_signing.outputs.configured == 'true'" in workflow


def test_release_is_triggered_only_by_a_version_tag() -> None:
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")

    assert '- "v*"' in workflow
    assert "workflow_dispatch" not in workflow
    assert 'release_version="${GITHUB_REF_NAME#v}"' in workflow
