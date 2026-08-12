# SPDX-License-Identifier: Apache-2.0
"""Fail-closed entitlement policy resolution."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any


class PolicyConfigurationError(ValueError):
    """Raised when a policy document violates the broker contract."""


class EntitlementResolutionError(PermissionError):
    """Raised when token entitlements cannot resolve to exactly one policy."""


@dataclass(frozen=True)
class Policy:
    """A non-secret, server-side entitlement policy."""

    id: str
    entra_group_ids: frozenset[str]
    allowed_models: frozenset[str]
    key_ref: str
    priority: int
    entra_app_roles: frozenset[str] = frozenset()


def load_policies(document: str) -> tuple[Policy, ...]:
    """Load policy records from a non-secret JSON document."""
    try:
        data = json.loads(document)
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise PolicyConfigurationError("Invalid policy document") from error

    if not isinstance(data, dict) or not isinstance(data.get("policies"), list):
        raise PolicyConfigurationError("Invalid policy document")
    records = data["policies"]

    policies = tuple(_policy_from_record(record) for record in records)
    if len({policy.id for policy in policies}) != len(policies):
        raise PolicyConfigurationError("duplicate policy id")
    return policies


def _policy_from_record(record: Any) -> Policy:
    if not isinstance(record, dict):
        raise PolicyConfigurationError("Invalid policy record")
    try:
        policy_id = record["id"]
        groups = record.get("entra_group_ids", [])
        app_roles = record.get("entra_app_roles", [])
        models = record["allowed_models"]
        key_ref = record["key_ref"]
        priority = record["priority"]
    except KeyError as error:
        raise PolicyConfigurationError("Invalid policy record") from error

    if not isinstance(policy_id, str) or not policy_id.strip():
        raise PolicyConfigurationError("invalid policy id")
    if not _strings(groups) or not _strings(app_roles) or not (groups or app_roles):
        raise PolicyConfigurationError("invalid policy Entra entitlements")
    if not _nonempty_strings(models):
        raise PolicyConfigurationError("invalid policy models")
    if not isinstance(key_ref, str) or not re.fullmatch(r"[A-Z_][A-Z0-9_]*", key_ref):
        raise PolicyConfigurationError("invalid policy key reference")
    if type(priority) is not int:
        raise PolicyConfigurationError("invalid policy priority")
    return Policy(
        id=policy_id.strip(),
        entra_group_ids=frozenset(group.strip() for group in groups),
        allowed_models=frozenset(model.strip() for model in models),
        key_ref=key_ref,
        priority=priority,
        entra_app_roles=frozenset(role.strip() for role in app_roles),
    )


def _nonempty_strings(value: Any) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, str) and item.strip() for item in value)
    )


def _strings(value: Any) -> bool:
    return isinstance(value, list) and all(
        isinstance(item, str) and item.strip() for item in value
    )


def resolve_entitlement(
    *,
    policies: tuple[Policy, ...],
    token_group_ids: set[str],
    token_app_roles: set[str] | None = None,
) -> Policy:
    """Return the only matching group/role policy at the highest priority, or deny."""
    app_roles = token_app_roles or set()
    matches = [
        policy
        for policy in policies
        if policy.entra_group_ids.intersection(token_group_ids)
        or policy.entra_app_roles.intersection(app_roles)
    ]
    if not matches:
        raise EntitlementResolutionError("No entitlement policy matches token claims")

    highest_priority = max(policy.priority for policy in matches)
    winners = [policy for policy in matches if policy.priority == highest_priority]
    if len(winners) != 1:
        raise EntitlementResolutionError(
            "Multiple entitlement policies share the highest priority"
        )
    return winners[0]
