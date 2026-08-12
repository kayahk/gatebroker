# SPDX-License-Identifier: Apache-2.0
"""Entra access-token claim validation behind a signature-verification boundary."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, TypeGuard


class TokenValidationError(PermissionError):
    """Raised when a verified token does not satisfy the broker contract."""


class TokenVerifier(Protocol):
    """Signature verifier boundary; JWKS retrieval is intentionally outside this slice."""

    def __call__(self, token: str) -> Mapping[str, object]: ...


@dataclass(frozen=True)
class EntraTokenValidationConfig:
    issuer: str
    audience: str
    required_delegated_scope: str
    allowed_app_roles: frozenset[str]


@dataclass(frozen=True)
class ValidatedIdentity:
    oid: str
    group_ids: frozenset[str]
    app_roles: frozenset[str]


def validate_access_token(
    token: str,
    config: EntraTokenValidationConfig,
    verifier: TokenVerifier,
    *,
    now: int | float,
) -> ValidatedIdentity:
    """Verify through the injected boundary then fail closed on broker claims."""
    try:
        claims = verifier(token)
    except Exception as error:
        raise TokenValidationError("token verification failed") from error
    if not isinstance(claims, Mapping):
        raise TokenValidationError("token verification failed")
    if not _number(now):
        raise TokenValidationError("invalid current time")
    if claims.get("iss") != config.issuer:
        raise TokenValidationError("invalid issuer")
    if not _has_configured_audience(claims.get("aud"), config.audience):
        raise TokenValidationError("invalid audience")
    _validate_temporal_claims(claims, now)
    _reject_group_overage(claims)
    if not _is_authorized(claims, config):
        raise TokenValidationError("missing required authorization")
    oid = claims.get("oid")
    if not isinstance(oid, str) or not oid.strip():
        raise TokenValidationError("missing oid")
    return ValidatedIdentity(
        oid=oid,
        group_ids=_string_set(claims.get("groups")),
        app_roles=_string_set(claims.get("roles")),
    )


def _validate_temporal_claims(claims: Mapping[str, object], now: int | float) -> None:
    exp = claims.get("exp")
    nbf = claims.get("nbf")
    if not _number(exp):
        raise TokenValidationError("token expired")
    if now >= exp:
        raise TokenValidationError("token expired")
    if not _number(nbf):
        raise TokenValidationError("token not yet valid")
    if now < nbf:
        raise TokenValidationError("token not yet valid")


def _has_configured_audience(audience: object, configured_audience: str) -> bool:
    return audience == configured_audience or (
        isinstance(audience, list) and configured_audience in audience
    )


def _reject_group_overage(claims: Mapping[str, object]) -> None:
    claim_names = claims.get("_claim_names")
    if (isinstance(claim_names, Mapping) and "groups" in claim_names) or (
        claims.get("hasgroups") is True
    ):
        raise TokenValidationError("group overage is not supported")


def _is_authorized(
    claims: Mapping[str, object], config: EntraTokenValidationConfig
) -> bool:
    scopes = claims.get("scp")
    if isinstance(scopes, str) and config.required_delegated_scope in scopes.split():
        return True
    return bool(_string_set(claims.get("roles")) & config.allowed_app_roles)


def _string_set(value: object) -> frozenset[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return frozenset()
    return frozenset(value)


def _number(value: object) -> TypeGuard[int | float]:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and (not isinstance(value, float) or math.isfinite(value))
    )
