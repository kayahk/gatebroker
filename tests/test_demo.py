# SPDX-License-Identifier: Apache-2.0
"""Guards on the demo fixtures.

Each assertion here corresponds to a way the demo has actually broken. They are cheap
to run and they fail in seconds, whereas the real thing fails several minutes into a
container start with a message that points somewhere else entirely.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from gatebroker.policy import load_policies

DEMO = Path(__file__).parents[1] / "demo"
REALM = json.loads((DEMO / "keycloak" / "realm-gatebroker-demo.json").read_text(encoding="utf-8"))
COMPOSE = yaml.safe_load((DEMO / "docker-compose.yml").read_text(encoding="utf-8"))


def _client(client_id: str) -> dict:
    return next(client for client in REALM["clients"] if client["clientId"] == client_id)


def _broker_environment() -> dict[str, str]:
    return {
        key: str(value)
        for key, value in COMPOSE["services"]["gatebroker"]["environment"].items()
    }


def test_the_cli_client_can_run_a_device_code_flow() -> None:
    client = _client("gabro-cli")

    assert client["publicClient"] is True
    assert client["attributes"]["oauth2.device.authorization.grant.enabled"] == "true"


def test_the_cli_client_does_not_require_pkce() -> None:
    """PKCE belongs to the authorization-code flow, not to RFC 8628 device
    authorization. Requiring it makes Keycloak reject the request the CLI sends with
    "Missing parameter: code_challenge_method", which looks like a client bug.
    """
    assert "pkce.code.challenge.method" not in _client("gabro-cli").get("attributes", {})


def test_the_realm_emits_every_claim_the_broker_requires() -> None:
    """Declaring client scopes replaces Keycloak's defaults, so `basic` -- which is
    where `sub` lives -- has to be listed explicitly or every request is a 401.
    """
    scopes = {scope["name"]: scope for scope in REALM["clientScopes"]}
    assert set(_client("gabro-cli")["defaultClientScopes"]) == {"basic", "broker"}

    mappers = {m["name"]: m for m in scopes["basic"]["protocolMappers"]}
    assert mappers["sub"]["protocolMapper"] == "oidc-sub-mapper"

    broker_mappers = {m["protocolMapper"]: m for m in scopes["broker"]["protocolMappers"]}
    audience = broker_mappers["oidc-audience-mapper"]["config"]
    assert audience["included.client.audience"] == _broker_environment()["GABRO_OIDC_AUDIENCE"]
    groups = broker_mappers["oidc-group-membership-mapper"]["config"]
    assert groups["claim.name"] == "groups"
    # Full paths would make claim values like "/engineering", which no policy matches.
    assert groups["full.path"] == "false"


def test_the_broker_is_told_which_claim_names_this_provider_uses() -> None:
    """Keycloak spells these differently from Entra, whose spellings are the defaults."""
    environment = _broker_environment()

    assert environment["GABRO_OIDC_SUBJECT_CLAIM"] == "sub"
    assert environment["GABRO_OIDC_SCOPE_CLAIM"] == "scope"


def test_the_issuer_is_one_name_everyone_can_reach() -> None:
    """The browser and the containers must agree, which is why the demo shares a
    network namespace and addresses everything as localhost.
    """
    environment = _broker_environment()
    keycloak = COMPOSE["services"]["keycloak"]["environment"]

    assert keycloak["KC_HOSTNAME"] == "https://localhost:8443"
    assert environment["GABRO_OIDC_ISSUER"].startswith("https://localhost:8443/")
    assert environment["GABRO_OIDC_JWKS_URL"].startswith(environment["GABRO_OIDC_ISSUER"])
    for service in ("mock-model", "litellm", "gatebroker", "smoke"):
        assert COMPOSE["services"][service]["network_mode"] == "service:keycloak"


def test_every_policy_key_the_demo_references_is_projected() -> None:
    entitlements = DEMO / "entitlements"
    policies = load_policies((entitlements / "policies.json").read_text(encoding="utf-8"))

    assert policies
    for policy in policies:
        assert (entitlements / policy.key_ref).is_file(), policy.key_ref


def test_the_demo_grants_reach_a_model_the_gateway_actually_serves() -> None:
    """A policy may only allow models the gateway is configured with, or the demo
    denies requests for a reason that has nothing to do with entitlement.
    """
    gateway = yaml.safe_load((DEMO / "litellm" / "config.yaml").read_text(encoding="utf-8"))
    served = {model["model_name"] for model in gateway["model_list"]}
    policies = load_policies((DEMO / "entitlements" / "policies.json").read_text(encoding="utf-8"))

    for policy in policies:
        assert policy.allowed_models <= served, (policy.id, policy.allowed_models - served)


def test_the_gateway_key_the_broker_presents_is_the_one_the_gateway_expects() -> None:
    gateway = yaml.safe_load((DEMO / "litellm" / "config.yaml").read_text(encoding="utf-8"))
    expected = gateway["general_settings"]["master_key"]
    entitlements = DEMO / "entitlements"
    policies = load_policies((entitlements / "policies.json").read_text(encoding="utf-8"))

    for policy in policies:
        assert (entitlements / policy.key_ref).read_text(encoding="utf-8").strip() == expected


def test_the_realm_accepts_the_scopes_the_identity_library_always_adds() -> None:
    """MSAL appends offline_access, openid and profile to every request it makes.

    Declaring client scopes replaces Keycloak's defaults, so these have to be present
    or the first silent renewal after a successful sign-in is rejected with
    invalid_scope -- a failure that only appears once the access token expires.
    """
    declared = {scope["name"] for scope in REALM["clientScopes"]}
    client = _client("gabro-cli")
    assigned = set(client["defaultClientScopes"]) | set(client.get("optionalClientScopes", []))

    for required in ("profile", "offline_access"):
        assert required in declared, required
        assert required in assigned, required


def test_offline_access_is_optional_rather_than_default() -> None:
    """As a default scope every request implicitly asks for an offline token, which
    Keycloak refuses with "Offline tokens not allowed" unless the user holds the role.
    """
    client = _client("gabro-cli")

    assert "offline_access" not in client["defaultClientScopes"]
    assert "offline_access" in client["optionalClientScopes"]


def test_the_demo_users_may_hold_the_refresh_token_the_cli_needs() -> None:
    for user in REALM["users"]:
        assert "offline_access" in user["realmRoles"], user["username"]
    assert any(role["name"] == "offline_access" for role in REALM["roles"]["realm"])


def test_the_development_profile_does_not_duplicate_a_reserved_scope() -> None:
    """MSAL adds `openid` itself, so naming it again asks for it twice and Keycloak
    reports the duplicate as an invalid scope.
    """
    document = json.loads((DEMO / "gabro-dev-profile.json").read_text(encoding="utf-8"))
    requested = document["scope"].split()

    assert "openid" not in requested
    assert requested == ["broker"]


def test_the_development_profile_requests_a_scope_the_realm_grants() -> None:
    document = json.loads((DEMO / "gabro-dev-profile.json").read_text(encoding="utf-8"))
    client = _client("gabro-cli")
    assigned = set(client["defaultClientScopes"]) | set(client.get("optionalClientScopes", []))

    for scope in document["scope"].split():
        assert scope in assigned, scope
    assert document["scope"] == _broker_environment()["GABRO_OIDC_REQUIRED_SCOPE"]


def test_the_mock_provider_accepts_what_the_broker_forwards() -> None:
    """A provider limit below the broker's turns a valid request into an upstream 413.

    That reads like a broker fault, and it is how raising the broker's default was found
    to be insufficient on its own: the demo's own provider still capped at a megabyte.
    """
    from gatebroker.forwarding import DEFAULT_MAX_REQUEST_BYTES

    source = (DEMO / "mock-model" / "server.py").read_text(encoding="utf-8")
    declared = re.search(r"^_MAX_BODY_BYTES = ([0-9_]+)$", source, re.M)

    assert declared, "the mock provider must declare its body limit"
    assert int(declared.group(1).replace("_", "")) >= DEFAULT_MAX_REQUEST_BYTES
