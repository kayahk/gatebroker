# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

import pytest

from gatebroker.oidc import (
    TokenValidationConfig,
    TokenValidationError,
    validate_access_token,
)


@dataclass
class FakeVerifier:
    payload: Mapping[str, object]

    def __call__(self, token: str) -> Mapping[str, object]:
        assert token == "opaque-test-token"
        return self.payload


def config() -> TokenValidationConfig:
    return TokenValidationConfig(
        issuer="https://login.microsoftonline.com/tenant/v2.0",
        audience="api://gatebroker",
        required_delegated_scope="broker.access",
        allowed_app_roles=frozenset({"Broker.Access"}),
    )


def valid_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "iss": "https://login.microsoftonline.com/tenant/v2.0",
        "aud": "api://gatebroker",
        "exp": 2_000,
        "nbf": 1_000,
        "scp": "broker.access profile",
        "oid": "user-object-id",
        "groups": ["group-a"],
    }
    payload.update(overrides)
    return payload


def test_validates_fake_verified_payload_with_required_delegated_scope() -> None:
    identity = validate_access_token(
        "opaque-test-token", config(), FakeVerifier(valid_payload()), now=1_500
    )

    assert identity.subject == "user-object-id"
    assert identity.group_ids == frozenset({"group-a"})
    assert identity.app_roles == frozenset()


def test_accepts_configured_audience_from_audience_list() -> None:
    identity = validate_access_token(
        "opaque-test-token",
        config(),
        FakeVerifier(valid_payload(aud=["api://other", "api://gatebroker"])),
        now=1_500,
    )

    assert identity.subject == "user-object-id"
    assert identity.app_roles == frozenset()


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"iss": "https://wrong.example/"}, "issuer"),
        ({"aud": "api://other"}, "audience"),
        ({"exp": 1_500}, "expired"),
        ({"nbf": 1_501}, "not yet valid"),
        ({"scp": "profile", "roles": []}, "authorization"),
        ({"oid": ""}, "missing subject claim"),
        ({"_claim_names": {"groups": "src1"}}, "overage"),
        ({"hasgroups": True}, "overage"),
    ],
)
def test_rejects_invalid_verified_claims(
    overrides: dict[str, object], reason: str
) -> None:
    with pytest.raises(TokenValidationError, match=reason):
        validate_access_token(
            "opaque-test-token", config(), FakeVerifier(valid_payload(**overrides)), now=1_500
        )


@pytest.mark.parametrize(
    ("claim", "reason"),
    [("exp", "expired"), ("nbf", "not yet valid")],
)
def test_rejects_verified_tokens_missing_required_temporal_claim(
    claim: str, reason: str
) -> None:
    payload = valid_payload()
    del payload[claim]

    with pytest.raises(TokenValidationError, match=reason):
        validate_access_token(
            "opaque-test-token", config(), FakeVerifier(payload), now=1_500
        )


@pytest.mark.parametrize(
    ("overrides", "now"),
    [
        ({"exp": float("nan")}, 1_500),
        ({"exp": float("inf")}, 1_500),
        ({"nbf": float("nan")}, 1_500),
        ({}, float("nan")),
    ],
)
def test_rejects_non_finite_temporal_values(
    overrides: dict[str, object], now: float
) -> None:
    with pytest.raises(TokenValidationError):
        validate_access_token(
            "opaque-test-token", config(), FakeVerifier(valid_payload(**overrides)), now=now
        )


@pytest.mark.parametrize("payload", [None, [], "not-a-claims-mapping"])
def test_normalizes_non_mapping_verifier_outputs(payload: object) -> None:
    with pytest.raises(TokenValidationError, match="verification"):
        validate_access_token(
            "opaque-test-token", config(), lambda _token: payload, now=1_500
        )


def test_normalizes_verifier_errors() -> None:
    def broken_verifier(_token: str) -> Mapping[str, object]:
        raise RuntimeError("verifier backend failed")

    with pytest.raises(TokenValidationError, match="verification"):
        validate_access_token("opaque-test-token", config(), broken_verifier, now=1_500)


def test_accepts_allowed_app_role_when_delegated_scope_is_absent() -> None:
    identity = validate_access_token(
        "opaque-test-token",
        config(),
        FakeVerifier(valid_payload(scp=None, roles=["Broker.Access"])),
        now=1_500,
    )

    assert identity.subject == "user-object-id"
    assert identity.app_roles == frozenset({"Broker.Access"})
