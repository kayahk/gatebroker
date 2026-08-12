# SPDX-License-Identifier: Apache-2.0
"""The published example must stay consistent with what the runtime enforces.

These tests exist so a change to the runtime contract cannot silently leave the
reference deployment describing something that no longer works.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from gatebroker.policy import load_policies
from gatebroker.runtime import load_runtime_settings

DEPLOY = Path(__file__).parents[1] / "deploy" / "kubernetes"
MANIFEST = DEPLOY / "gatebroker.yaml"
ENTITLEMENTS = DEPLOY / "entitlements-example.yaml"


def _documents(path: Path) -> list[dict]:
    return [
        document
        for document in yaml.safe_load_all(path.read_text(encoding="utf-8"))
        if document
    ]


def _container() -> dict:
    deployment = next(
        document for document in _documents(MANIFEST) if document["kind"] == "Deployment"
    )
    return deployment["spec"]["template"]["spec"]["containers"][0]


def _environment() -> dict[str, str]:
    return {entry["name"]: entry["value"] for entry in _container()["env"]}


def test_example_environment_matches_the_names_the_runtime_reads() -> None:
    """Every variable in the example must be one the runtime actually consumes."""
    environment = _environment()
    settings_source = Path(load_runtime_settings.__code__.co_filename).read_text(
        encoding="utf-8"
    )

    for name in environment:
        assert name.startswith("GABRO_"), name
        assert f'"{name}"' in settings_source, (
            f"{name} is set in the example but never read by load_runtime_settings"
        )


def test_example_configures_the_runtime_without_error(tmp_path: Path) -> None:
    """The example values must satisfy every check load_runtime_settings makes."""
    environment = dict(_environment())
    tenant = "00000000-0000-0000-0000-000000000000"

    # The example carries REPLACE placeholders and points at a projected directory
    # that only exists in-cluster. Substitute a well-formed tenant, a routable
    # upstream, and a real path; everything else is asserted as published.
    environment["GABRO_ENTRA_ISSUER"] = f"https://login.microsoftonline.com/{tenant}/v2.0"
    environment["GABRO_ENTRA_JWKS_URL"] = (
        f"https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"
    )
    environment["GABRO_UPSTREAM_BASE_URL"] = "https://gateway.example.test"
    environment["GABRO_UPSTREAM_TRUSTED_HOSTS"] = "gateway.example.test"
    policy_file = tmp_path / Path(environment["GABRO_POLICY_PATH"]).name
    policy_file.write_text(_entitlements()["policies.json"], encoding="utf-8")
    environment["GABRO_POLICY_PATH"] = str(policy_file)
    environment["GABRO_KEY_DIR"] = str(tmp_path)

    settings = load_runtime_settings(environment)

    assert settings.trusted_upstream_hosts == frozenset({"gateway.example.test"})
    assert settings.entra.required_delegated_scope == environment["GABRO_ENTRA_REQUIRED_SCOPE"]
    assert settings.allow_cluster_local_plaintext_upstream is False


def _entitlements() -> dict[str, str]:
    secret = next(
        document for document in _documents(ENTITLEMENTS) if document["kind"] == "Secret"
    )
    return secret["stringData"]


def test_example_policy_document_is_valid_and_secret_free() -> None:
    data = _entitlements()
    policies = load_policies(data["policies.json"])

    assert policies, "the example must show at least one policy"
    for policy in policies:
        assert policy.entra_group_ids or policy.entra_app_roles
        # A policy names a key; it must never carry the value.
        assert policy.key_ref in data, (
            f"{policy.key_ref} has no matching file in the projected directory"
        )
        assert data[policy.key_ref] == "REPLACE", (
            "the example must not ship anything resembling a real key"
        )
    assert json.loads(data["policies.json"])


def test_example_projects_policies_and_keys_from_one_read_only_directory() -> None:
    environment = _environment()
    mounts = {mount["name"]: mount for mount in _container()["volumeMounts"]}
    key_directory = environment["GABRO_KEY_DIR"]

    assert environment["GABRO_POLICY_PATH"] == f"{key_directory}/policies.json"
    assert mounts["entitlements"]["mountPath"] == key_directory
    assert mounts["entitlements"]["readOnly"] is True


def test_example_runs_one_replica_because_the_limiter_is_process_local() -> None:
    deployment = next(
        document for document in _documents(MANIFEST) if document["kind"] == "Deployment"
    )

    assert deployment["spec"]["replicas"] == 1


def test_example_container_runs_unprivileged_with_a_read_only_root() -> None:
    container = _container()
    security = container["securityContext"]

    assert security["allowPrivilegeEscalation"] is False
    assert security["readOnlyRootFilesystem"] is True
    assert security["capabilities"]["drop"] == ["ALL"]


def test_example_probes_the_non_disclosing_health_endpoints() -> None:
    container = _container()

    assert container["livenessProbe"]["httpGet"]["path"] == "/healthz"
    assert container["readinessProbe"]["httpGet"]["path"] == "/readyz"
