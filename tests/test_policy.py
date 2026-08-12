# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import pytest

from gatebroker.policy import (
    EntitlementResolutionError,
    Policy,
    PolicyConfigurationError,
    load_policies,
    resolve_entitlement,
)


def test_resolves_the_single_highest_priority_matching_policy() -> None:
    lower_priority = Policy(
        id="standard",
        entra_group_ids=frozenset({"group-standard"}),
        allowed_models=frozenset({"gpt-4o-mini"}),
        key_ref="STANDARD_KEY",
        priority=10,
    )
    higher_priority = Policy(
        id="premium",
        entra_group_ids=frozenset({"group-premium"}),
        allowed_models=frozenset({"gpt-4o", "gpt-4o-mini"}),
        key_ref="PREMIUM_KEY",
        priority=20,
    )

    result = resolve_entitlement(
        policies=(lower_priority, higher_priority),
        token_group_ids={"group-standard", "group-premium"},
    )

    assert result == higher_priority


def test_loads_non_secret_policies_from_json() -> None:
    policies = load_policies(
        '''
        {"policies": [{
          "id": "researchers",
          "entra_group_ids": ["group-research"],
          "allowed_models": ["gpt-4o-mini"],
          "key_ref": "RESEARCHERS_KEY",
          "priority": 5
        }]}
        '''
    )

    assert policies == (
        Policy(
            id="researchers",
            entra_group_ids=frozenset({"group-research"}),
            allowed_models=frozenset({"gpt-4o-mini"}),
            key_ref="RESEARCHERS_KEY",
            priority=5,
        ),
    )


def test_normalizes_policy_identifiers_and_entitlements() -> None:
    policies = load_policies(
        '''
        {"policies": [{
          "id": " researchers ",
          "entra_group_ids": [" group-research "],
          "allowed_models": [" gpt-4o-mini "],
          "key_ref": "RESEARCHERS_KEY",
          "priority": 5
        }]}
        '''
    )

    assert policies == (
        Policy(
            id="researchers",
            entra_group_ids=frozenset({"group-research"}),
            allowed_models=frozenset({"gpt-4o-mini"}),
            key_ref="RESEARCHERS_KEY",
            priority=5,
        ),
    )


@pytest.mark.parametrize(
    "document",
    [
        "not-json",
        "[]",
        '{"policies": {}}',
        '{"policies": [{"id": "p", "entra_group_ids": ["g"], "allowed_models": ["m"], "key_ref": "lowercase_key", "priority": 1}]}',
        '{"policies": [{"id": "p", "entra_group_ids": ["g"], "allowed_models": ["m"], "key_ref": "UPSTREAM_KEY=reference", "priority": 1}]}',
    ],
)
def test_rejects_malformed_root_and_non_reference_key_values(document: str) -> None:
    with pytest.raises(PolicyConfigurationError):
        load_policies(document)


@pytest.mark.parametrize(
    "record",
    [
        {"entra_group_ids": ["g"], "allowed_models": ["m"], "key_ref": "KEY", "priority": 1},
        {"id": "p", "allowed_models": ["m"], "key_ref": "KEY", "priority": 1},
        {"id": "p", "entra_group_ids": ["g"], "key_ref": "KEY", "priority": 1},
        {"id": "p", "entra_group_ids": ["g"], "allowed_models": ["m"], "priority": 1},
        {"id": "p", "entra_group_ids": ["g"], "allowed_models": ["m"], "key_ref": "KEY"},
        {"id": 1, "entra_group_ids": ["g"], "allowed_models": ["m"], "key_ref": "KEY", "priority": 1},
        {"id": "p", "entra_group_ids": "g", "allowed_models": ["m"], "key_ref": "KEY", "priority": 1},
        {"id": "p", "entra_group_ids": ["g"], "allowed_models": "m", "key_ref": "KEY", "priority": 1},
        {"id": "p", "entra_group_ids": ["g"], "allowed_models": ["m"], "key_ref": 1, "priority": 1},
        {"id": "p", "entra_group_ids": ["g"], "allowed_models": ["m"], "key_ref": "KEY", "priority": True},
    ],
)
def test_rejects_missing_or_wrong_typed_policy_fields(record: dict[str, object]) -> None:
    import json

    with pytest.raises(PolicyConfigurationError):
        load_policies(json.dumps({"policies": [record]}))


@pytest.mark.parametrize(
    ("document", "reason"),
    [
        ('{"policies": [{"id": "", "entra_group_ids": ["g"], "allowed_models": ["m"], "key_ref": "KEY", "priority": 1}]}', "id"),
        ('{"policies": [{"id": "p", "entra_group_ids": [], "allowed_models": ["m"], "key_ref": "KEY", "priority": 1}]}', "entitlement"),
        ('{"policies": [{"id": "p", "entra_group_ids": ["g"], "allowed_models": [], "key_ref": "KEY", "priority": 1}]}', "model"),
        ('{"policies": [{"id": "p", "entra_group_ids": ["g"], "allowed_models": ["m"], "key_ref": "", "priority": 1}]}', "key"),
        ('{"policies": [{"id": "p", "entra_group_ids": ["g"], "allowed_models": ["m"], "key_ref": "KEY", "priority": "1"}]}', "priority"),
        ('{"policies": [{"id": "p", "entra_group_ids": ["g"], "allowed_models": ["m"], "key_ref": "KEY", "priority": 1}, {"id": "p", "entra_group_ids": ["g2"], "allowed_models": ["m2"], "key_ref": "KEY2", "priority": 2}]}', "duplicate"),
    ],
)
def test_rejects_invalid_policy_documents(document: str, reason: str) -> None:
    with pytest.raises(PolicyConfigurationError, match=reason):
        load_policies(document)


def test_denies_when_no_policy_matches_token_groups() -> None:
    policy = Policy("p", frozenset({"group-a"}), frozenset({"m"}), "KEY", 1)

    with pytest.raises(EntitlementResolutionError, match="No entitlement"):
        resolve_entitlement(policies=(policy,), token_group_ids={"group-b"})


def test_denies_when_multiple_matching_policies_share_highest_priority() -> None:
    first = Policy("first", frozenset({"group-a"}), frozenset({"m1"}), "KEY1", 1)
    second = Policy("second", frozenset({"group-b"}), frozenset({"m2"}), "KEY2", 1)

    with pytest.raises(EntitlementResolutionError, match="Multiple entitlement"):
        resolve_entitlement(policies=(first, second), token_group_ids={"group-a", "group-b"})


def test_loads_and_resolves_an_app_role_only_policy() -> None:
    policies = load_policies(
        '''
        {"policies": [{
          "id": "automation",
          "entra_app_roles": ["Broker.Automation"],
          "allowed_models": ["gpt-4o-mini"],
          "key_ref": "AUTOMATION_KEY",
          "priority": 20
        }]}
        '''
    )

    result = resolve_entitlement(
        policies=policies,
        token_group_ids=set(),
        token_app_roles={"Broker.Automation"},
    )

    assert result.id == "automation"


def test_loads_a_source_neutral_key_reference() -> None:
    policies = load_policies(
        '{"policies": [{"id": "p", "entra_group_ids": ["g"], "allowed_models": ["m"],'
        ' "key_ref": "UPSTREAM_API_KEY_P", "priority": 1}]}'
    )

    assert policies[0].key_ref == "UPSTREAM_API_KEY_P"


def test_key_reference_names_a_value_the_deployment_resolves() -> None:
    """A policy carries the name of a key, never the key itself."""
    policies = load_policies(
        '{"policies": [{"id": "p", "entra_group_ids": ["g"], "allowed_models": ["m"],'
        ' "key_ref": "UPSTREAM_API_KEY", "priority": 1}]}'
    )

    assert policies[0].key_ref == "UPSTREAM_API_KEY"


def test_rejects_a_policy_without_a_key_reference() -> None:
    with pytest.raises(PolicyConfigurationError, match="Invalid policy record"):
        load_policies(
            '{"policies": [{"id": "p", "entra_group_ids": ["g"], "allowed_models": ["m"],'
            ' "priority": 1}]}'
        )
