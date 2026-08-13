# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace

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
    [("exp", "expired")],
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


def test_accepts_a_delegated_scope_from_a_configured_scope_claim() -> None:
    """Most providers spell granted scopes `scope` rather than Entra's `scp`."""
    payload = valid_payload(scp=None)
    payload["scope"] = "openid broker.access"

    identity = validate_access_token(
        "opaque-test-token",
        replace(config(), scope_claim="scope"),
        FakeVerifier(payload),
        now=1_500,
    )

    assert identity.subject == "user-object-id"


def test_a_scope_in_the_wrong_claim_does_not_authorize() -> None:
    payload = valid_payload(scp=None)
    payload["scope"] = "openid broker.access"

    with pytest.raises(TokenValidationError, match="missing required authorization"):
        validate_access_token(
            "opaque-test-token", config(), FakeVerifier(payload), now=1_500
        )


def test_accepts_a_token_without_nbf() -> None:
    """`nbf` is optional in RFC 7519 and providers such as Keycloak omit it."""
    payload = valid_payload()
    del payload["nbf"]

    identity = validate_access_token(
        "opaque-test-token", config(), FakeVerifier(payload), now=1_500
    )

    assert identity.subject == "user-object-id"


def test_still_enforces_nbf_when_the_provider_sends_it() -> None:
    with pytest.raises(TokenValidationError, match="token not yet valid"):
        validate_access_token(
            "opaque-test-token",
            config(),
            FakeVerifier(valid_payload(nbf=1_600)),
            now=1_500,
        )


@pytest.mark.parametrize("nbf", ["1000", None, True, float("nan"), float("inf")])
def test_rejects_an_unusable_nbf_rather_than_ignoring_it(nbf: object) -> None:
    """A present but malformed claim must fail closed, not be treated as absent."""
    with pytest.raises(TokenValidationError, match="token not yet valid"):
        validate_access_token(
            "opaque-test-token",
            config(),
            FakeVerifier(valid_payload(nbf=nbf)),
            now=1_500,
        )


def test_still_requires_exp() -> None:
    payload = valid_payload()
    del payload["exp"]

    with pytest.raises(TokenValidationError, match="token expired"):
        validate_access_token(
            "opaque-test-token", config(), FakeVerifier(payload), now=1_500
        )
