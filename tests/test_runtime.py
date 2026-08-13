# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import asyncio
import datetime
import json
import secrets
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import gatebroker.runtime as runtime
from gatebroker.runtime import (
    FixedWindowRateLimiter,
    JwksVerifier,
    create_runtime_app,
    load_runtime_settings,
)

POLICIES = {
    "policies": [
        {
            "id": "researchers",
            "group_ids": ["group-research"],
            "allowed_models": ["gpt-4o-mini"],
            "key_ref": "RESEARCHERS_KEY",
            "priority": 10,
        }
    ]
}


def runtime_environment(policy_path: Path) -> dict[str, str]:
    return {
        "GABRO_OIDC_ISSUER": "https://login.microsoftonline.com/tenant-id/v2.0",
        "GABRO_OIDC_AUDIENCE": "api://broker-app-id",
        "GABRO_OIDC_REQUIRED_SCOPE": "Broker.Access",
        "GABRO_OIDC_JWKS_URL": "https://login.microsoftonline.com/tenant-id/discovery/v2.0/keys",
        "GABRO_UPSTREAM_BASE_URL": "https://gateway.internal.svc.cluster.local",
        "GABRO_UPSTREAM_TRUSTED_HOSTS": "gateway.internal.svc.cluster.local",
        "GABRO_POLICY_PATH": str(policy_path),
        "RESEARCHERS_KEY": "server-side-key",
    }


def signed_token(
    settings: runtime.RuntimeSettings,
    private_key: rsa.RSAPrivateKey,
    kid: str,
) -> str:
    return jwt.encode(
        {
            "iss": settings.oidc.issuer,
            "aud": settings.oidc.audience,
            "exp": 4_000_000_000,
            "nbf": 0,
            "oid": "subject-123",
        },
        private_key,
        algorithm="RS256",
        headers={"kid": kid},
    )


def test_rejects_missing_required_runtime_configuration(tmp_path: Path) -> None:
    environment = runtime_environment(tmp_path / "policies.json")
    del environment["GABRO_OIDC_AUDIENCE"]

    with pytest.raises(RuntimeError, match="GABRO_OIDC_AUDIENCE"):
        load_runtime_settings(environment)


def test_plaintext_upstream_opt_in_defaults_to_disabled(tmp_path: Path) -> None:
    policy_path = tmp_path / "policies.json"
    policy_path.write_text(json.dumps(POLICIES), encoding="utf-8")

    settings = load_runtime_settings(runtime_environment(policy_path))

    assert settings.allow_cluster_local_plaintext_upstream is False


def test_plaintext_upstream_opt_in_builds_direct_cluster_local_app(tmp_path: Path) -> None:
    policy_path = tmp_path / "policies.json"
    policy_path.write_text(json.dumps(POLICIES), encoding="utf-8")
    environment = runtime_environment(policy_path)
    environment["GABRO_UPSTREAM_BASE_URL"] = (
        "http://gateway.internal.svc.cluster.local:4000"
    )
    environment["GABRO_UPSTREAM_ALLOW_CLUSTER_LOCAL_PLAINTEXT"] = "true"

    settings = load_runtime_settings(environment)

    assert settings.allow_cluster_local_plaintext_upstream is True
    app = runtime.create_runtime_app(
        settings,
        token_verifier=lambda _token: {},
        transport=httpx.MockTransport(lambda _request: httpx.Response(200)),
    )
    assert app is not None


@pytest.mark.parametrize("value", ["yes", "True", "1", "", " true ", "true\n"])
def test_rejects_non_boolean_plaintext_upstream_opt_in(tmp_path: Path, value: str) -> None:
    policy_path = tmp_path / "policies.json"
    policy_path.write_text(json.dumps(POLICIES), encoding="utf-8")
    environment = runtime_environment(policy_path)
    environment["GABRO_UPSTREAM_ALLOW_CLUSTER_LOCAL_PLAINTEXT"] = value

    with pytest.raises(
        RuntimeError, match="GABRO_UPSTREAM_ALLOW_CLUSTER_LOCAL_PLAINTEXT"
    ):
        load_runtime_settings(environment)


def test_rejects_jwks_url_that_is_not_the_issuer_tenants_entra_discovery_endpoint(
    tmp_path: Path,
) -> None:
    policy_path = tmp_path / "policies.json"
    policy_path.write_text(json.dumps(POLICIES), encoding="utf-8")
    environment = runtime_environment(policy_path)
    environment["GABRO_OIDC_JWKS_URL"] = (
        "https://login.microsoftonline.com/another-tenant/discovery/v2.0/keys"
    )

    with pytest.raises(RuntimeError, match="GABRO_OIDC_JWKS_URL"):
        load_runtime_settings(environment)


def test_production_jwks_verifier_does_not_indefinitely_cache_known_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_path = tmp_path / "policies.json"
    policy_path.write_text(json.dumps(POLICIES), encoding="utf-8")
    settings = load_runtime_settings(runtime_environment(policy_path))
    captured: dict[str, object] = {}

    def jwks_client(*_args: object, **kwargs: object) -> _StaticJwksClient:
        captured.update(kwargs)
        return _StaticJwksClient(_SigningKey(object()))

    monkeypatch.setattr(runtime.jwt, "PyJWKClient", jwks_client)
    JwksVerifier(settings)

    assert captured["cache_keys"] is False
    assert captured["timeout"] == 5


def test_production_jwks_verifier_accepts_rs256_token_with_matching_verified_claims(
    tmp_path: Path,
) -> None:
    policy_path = tmp_path / "policies.json"
    policy_path.write_text(json.dumps(POLICIES), encoding="utf-8")
    settings = load_runtime_settings(runtime_environment(policy_path))
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    signing_key = jwt.PyJWK.from_dict({**public_jwk, "kid": "ephemeral-test-key"})
    verifier = JwksVerifier(settings)
    verifier._jwks = _StaticJwksClient(signing_key)
    verifier.refresh()
    token = jwt.encode(
        {
            "iss": settings.oidc.issuer,
            "aud": settings.oidc.audience,
            "exp": 4_000_000_000,
            "nbf": 0,
            "oid": "subject-123",
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "ephemeral-test-key"},
    )

    assert verifier(token)["oid"] == "subject-123"


def test_production_jwks_verifier_rejects_non_rs256_algorithm(tmp_path: Path) -> None:
    policy_path = tmp_path / "policies.json"
    policy_path.write_text(json.dumps(POLICIES), encoding="utf-8")
    settings = load_runtime_settings(runtime_environment(policy_path))
    ephemeral_secret = secrets.token_bytes(32)
    verifier = JwksVerifier(settings)
    verifier._jwks = _StaticJwksClient(_SigningKey(ephemeral_secret))
    token = jwt.encode(
        {
            "iss": settings.oidc.issuer,
            "aud": settings.oidc.audience,
            "exp": 4_000_000_000,
            "nbf": 0,
            "oid": "subject-123",
        },
        ephemeral_secret,
        algorithm="HS256",
    )

    with pytest.raises(jwt.InvalidAlgorithmError):
        verifier(token)


def test_rotated_signing_key_uses_one_single_flight_key_miss_refresh(
    tmp_path: Path,
) -> None:
    policy_path = tmp_path / "policies.json"
    policy_path.write_text(json.dumps(POLICIES), encoding="utf-8")
    settings = load_runtime_settings(runtime_environment(policy_path))
    old_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    new_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    old_key = jwt.PyJWK.from_dict(
        {
            **json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(old_private_key.public_key())),
            "kid": "old-key",
        }
    )
    new_key = jwt.PyJWK.from_dict(
        {
            **json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(new_private_key.public_key())),
            "kid": "new-key",
        }
    )
    jwks_client = _BlockingRotatingJwksClient(old_key, new_key)
    verifier = JwksVerifier(settings)
    verifier._jwks = jwks_client
    verifier.refresh()
    token = signed_token(settings, new_private_key, "new-key")

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(verifier, token)
        assert jwks_client.refresh_started.wait(timeout=2)
        second = executor.submit(verifier, token)
        jwks_client.allow_refresh.set()

        assert first.result(timeout=2)["oid"] == "subject-123"
        assert second.result(timeout=2)["oid"] == "subject-123"

    assert jwks_client.readiness_checks == 2


def test_repeated_unknown_signing_key_is_cooldown_limited(tmp_path: Path) -> None:
    policy_path = tmp_path / "policies.json"
    policy_path.write_text(json.dumps(POLICIES), encoding="utf-8")
    settings = load_runtime_settings(runtime_environment(policy_path))
    known_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    unknown_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    known_key = jwt.PyJWK.from_dict(
        {
            **json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(known_private_key.public_key())),
            "kid": "known-key",
        }
    )
    jwks_client = _StaticJwksClient(known_key)
    verifier = JwksVerifier(settings)
    verifier._jwks = jwks_client
    verifier.refresh()
    token = signed_token(settings, unknown_private_key, "unknown-key")

    for _attempt in range(2):
        with pytest.raises(jwt.InvalidTokenError, match="unknown signing key"):
            verifier(token)

    assert jwks_client.readiness_checks == 2


def test_runtime_startup_establishes_jwks_readiness_without_disclosing_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_path = tmp_path / "policies.json"
    policy_path.write_text(json.dumps(POLICIES), encoding="utf-8")
    settings = load_runtime_settings(runtime_environment(policy_path))
    jwks_client = _StaticJwksClient(_SigningKey(object()))
    monkeypatch.setenv("RESEARCHERS_KEY", "server-side-key")
    monkeypatch.setattr(runtime.jwt, "PyJWKClient", lambda *_args, **_kwargs: jwks_client)
    app = create_runtime_app(settings)

    async def request_when_started() -> httpx.Response:
        async with app.router.lifespan_context(app), httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://broker.test"
        ) as client:
            return await client.get("/readyz")

    response = asyncio.run(request_when_started())

    assert jwks_client.readiness_checks == 1
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert settings.jwks_url not in response.text


def test_fixed_window_rate_limiter_rejects_exhaustion_and_allows_next_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limiter = FixedWindowRateLimiter(requests=2, window_seconds=60, max_keys=2)
    monkeypatch.setattr(runtime.time, "time", lambda: 120.0)

    assert limiter(("oid", "policy", "203.0.113.7")) is True
    assert limiter(("oid", "policy", "203.0.113.7")) is True
    assert limiter(("oid", "policy", "203.0.113.7")) is False
    assert limiter(("other-oid", "policy", "203.0.113.7")) is True
    assert limiter(("third-oid", "policy", "203.0.113.7")) is False
    monkeypatch.setattr(runtime.time, "time", lambda: 180.0)
    assert limiter(("third-oid", "policy", "203.0.113.7")) is True


def test_health_and_readiness_do_not_disclose_runtime_configuration(tmp_path: Path) -> None:
    policy_path = tmp_path / "policies.json"
    policy_path.write_text(json.dumps(POLICIES), encoding="utf-8")
    settings = load_runtime_settings(runtime_environment(policy_path))
    app = create_runtime_app(settings, token_verifier=lambda _token: {})

    async def request(path: str) -> httpx.Response:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://broker.test"
        ) as client:
            return await client.get(path)

    health = asyncio.run(request("/healthz"))
    readiness = asyncio.run(request("/readyz"))

    assert health.status_code == 200
    assert health.json() == {"status": "ok"}
    assert readiness.status_code == 503
    assert readiness.json() == {"status": "unavailable"}
    for response in (health, readiness):
        assert "server-side-key" not in response.text
        assert "broker-app-id" not in response.text


def test_runtime_uses_environment_selected_server_side_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_path = tmp_path / "policies.json"
    policy_path.write_text(json.dumps(POLICIES), encoding="utf-8")
    environment = runtime_environment(policy_path)
    monkeypatch.setenv("RESEARCHERS_KEY", environment["RESEARCHERS_KEY"])
    settings = load_runtime_settings(environment)
    upstream_requests: list[httpx.Request] = []

    def verifier(_token: str) -> dict[str, object]:
        return {
            "iss": "https://login.microsoftonline.com/tenant-id/v2.0",
            "aud": "api://broker-app-id",
            "exp": 4_000_000_000,
            "nbf": 0,
            "scp": "Broker.Access",
            "oid": "subject-123",
            "groups": ["group-research"],
        }

    def upstream(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        return httpx.Response(200, json={"id": "chatcmpl-test"})

    app = create_runtime_app(
        settings,
        token_verifier=verifier,
        transport=httpx.MockTransport(upstream),
    )

    async def request() -> httpx.Response:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://broker.test"
        ) as client:
            return await client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer client-token"},
                json={"model": "gpt-4o-mini", "messages": []},
            )

    response = asyncio.run(request())

    assert response.status_code == 200
    assert upstream_requests[0].headers["authorization"] == "Bearer server-side-key"


class _SigningKey:
    def __init__(self, key: Any, key_id: str = "test-key") -> None:
        self.key = key
        self.key_id = key_id


class _StaticJwksClient:
    def __init__(self, signing_key: Any) -> None:
        self._signing_key = signing_key
        self.readiness_checks = 0

    def get_signing_key_from_jwt(self, _token: str) -> Any:
        return self._signing_key

    def get_signing_keys(self, *, refresh: bool = False) -> list[Any]:
        assert refresh is True
        self.readiness_checks += 1
        return [self._signing_key]


class _BlockingRotatingJwksClient:
    def __init__(self, initial_key: Any, rotated_key: Any) -> None:
        self._initial_key = initial_key
        self._rotated_key = rotated_key
        self.readiness_checks = 0
        self.refresh_started = Event()
        self.allow_refresh = Event()

    def get_signing_keys(self, *, refresh: bool = False) -> list[Any]:
        assert refresh is True
        self.readiness_checks += 1
        if self.readiness_checks == 1:
            return [self._initial_key]
        self.refresh_started.set()
        if not self.allow_refresh.wait(timeout=2):
            raise RuntimeError("test refresh timed out")
        return [self._rotated_key]


DOCUMENT_POLICIES = {
    "policies": [
        {
            "id": "cloud-platform-ai-agent",
            "group_ids": ["cf234f6f-4ea3-45bb-9747-ab7aae69894b"],
            "allowed_models": ["gpt-4o-mini"],
            "key_ref": "PLATFORM_AGENT_KEY",
            "priority": 200,
        }
    ]
}


def projected_key_directory(tmp_path: Path, *, with_key: bool = True) -> Path:
    """Mimic a projected Secret volume: the policy document beside its key files."""
    directory = tmp_path / "gatebroker"
    directory.mkdir()
    (directory / "policies.json").write_text(json.dumps(DOCUMENT_POLICIES), encoding="utf-8")
    if with_key:
        # Projections commonly append a trailing newline; the key must survive it.
        (directory / "PLATFORM_AGENT_KEY").write_text(
            "sk-projected-key\n", encoding="utf-8"
        )
    return directory


def document_environment(directory: Path) -> dict[str, str]:
    environment = runtime_environment(directory / "policies.json")
    del environment["RESEARCHERS_KEY"]
    environment["GABRO_KEY_DIR"] = str(directory)
    return environment


def test_key_directory_source_resolves_a_projected_key(tmp_path: Path) -> None:
    directory = projected_key_directory(tmp_path)
    settings = load_runtime_settings(document_environment(directory))

    resolver = runtime.build_key_resolver(settings)

    assert settings.key_directory == str(directory)
    assert resolver("PLATFORM_AGENT_KEY") == "sk-projected-key"


def test_key_source_defaults_to_the_process_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_path = tmp_path / "policies.json"
    policy_path.write_text(json.dumps(POLICIES), encoding="utf-8")
    settings = load_runtime_settings(runtime_environment(policy_path))
    monkeypatch.setenv("RESEARCHERS_KEY", "server-side-key")

    assert settings.key_directory == ""
    assert runtime.build_key_resolver(settings)("RESEARCHERS_KEY") == "server-side-key"


def test_key_directory_source_refuses_to_read_outside_its_directory(tmp_path: Path) -> None:
    directory = projected_key_directory(tmp_path)
    (tmp_path / "OTHER_KEY").write_text("sk-elsewhere", encoding="utf-8")
    resolver = runtime.build_key_resolver(load_runtime_settings(document_environment(directory)))

    with pytest.raises(KeyError):
        resolver("../OTHER_KEY")


def test_key_directory_source_refuses_a_symlink_to_a_file_outside_its_directory(
    tmp_path: Path,
) -> None:
    directory = projected_key_directory(tmp_path)
    outside_key = tmp_path / "outside-key"
    outside_key.write_text("sk-elsewhere", encoding="utf-8")
    (directory / "PLATFORM_AGENT_KEY").unlink()
    (directory / "PLATFORM_AGENT_KEY").symlink_to(outside_key)
    resolver = runtime.build_key_resolver(load_runtime_settings(document_environment(directory)))

    with pytest.raises(KeyError):
        resolver("PLATFORM_AGENT_KEY")


def kubernetes_projected_key_directory(tmp_path: Path) -> Path:
    """Build the symlink layout a Kubernetes Secret volume actually presents.

    kubelet writes the payload into a timestamped directory and links each key
    through `..data`, so every projected file is a symlink one level deeper than
    the mount point.
    """
    directory = tmp_path / "gatebroker"
    payload = directory / "..2026_08_12_10_00_00.123456789"
    payload.mkdir(parents=True)
    (payload / "policies.json").write_text(json.dumps(DOCUMENT_POLICIES), encoding="utf-8")
    (payload / "PLATFORM_AGENT_KEY").write_text(
        "sk-projected-key", encoding="utf-8"
    )
    (directory / "..data").symlink_to(payload.name)
    for key in ("policies.json", "PLATFORM_AGENT_KEY"):
        (directory / key).symlink_to(Path("..data") / key)
    return directory


def test_key_directory_source_reads_a_kubernetes_projected_secret(tmp_path: Path) -> None:
    """The containment check must not reject kubelet's own `..data` indirection."""
    directory = kubernetes_projected_key_directory(tmp_path)
    resolver = runtime.build_key_resolver(load_runtime_settings(document_environment(directory)))

    assert resolver("PLATFORM_AGENT_KEY") == "sk-projected-key"


def test_readiness_reports_ok_for_a_kubernetes_projected_secret(tmp_path: Path) -> None:
    directory = kubernetes_projected_key_directory(tmp_path)
    settings = load_runtime_settings(document_environment(directory))
    app = create_runtime_app(settings, token_verifier=lambda _token: {})

    async def request() -> httpx.Response:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://broker.test"
        ) as client:
            return await client.get("/readyz")

    assert asyncio.run(request()).status_code == 200


def test_readiness_reports_ok_when_every_policy_key_is_projected(tmp_path: Path) -> None:
    directory = projected_key_directory(tmp_path)
    settings = load_runtime_settings(document_environment(directory))
    app = create_runtime_app(settings, token_verifier=lambda _token: {})

    async def request() -> httpx.Response:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://broker.test"
        ) as client:
            return await client.get("/readyz")

    response = asyncio.run(request())

    assert response.status_code == 200
    assert "sk-projected-key" not in response.text


def test_readiness_reports_unavailable_when_a_projected_key_is_missing(tmp_path: Path) -> None:
    """A policy without a resolvable key must keep the broker out of service."""
    directory = projected_key_directory(tmp_path, with_key=False)
    settings = load_runtime_settings(document_environment(directory))
    app = create_runtime_app(settings, token_verifier=lambda _token: {})

    async def request() -> httpx.Response:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://broker.test"
        ) as client:
            return await client.get("/readyz")

    assert asyncio.run(request()).status_code == 503


def _generic_issuer_environment(policy_path: Path) -> dict[str, str]:
    environment = runtime_environment(policy_path)
    environment["GABRO_OIDC_ISSUER"] = "https://idp.example.test/realms/demo"
    environment["GABRO_OIDC_JWKS_URL"] = (
        "https://idp.example.test/realms/demo/protocol/openid-connect/certs"
    )
    environment["GABRO_OIDC_SUBJECT_CLAIM"] = "sub"
    return environment


def test_accepts_a_non_entra_issuer_with_its_own_jwks_endpoint(tmp_path: Path) -> None:
    """Any OIDC provider must be usable, not only Microsoft Entra."""
    policy_path = tmp_path / "policies.json"
    policy_path.write_text(json.dumps(POLICIES), encoding="utf-8")

    settings = load_runtime_settings(_generic_issuer_environment(policy_path))

    assert settings.oidc.issuer == "https://idp.example.test/realms/demo"
    assert settings.oidc.subject_claim == "sub"


def test_subject_claim_defaults_to_the_entra_object_id(tmp_path: Path) -> None:
    policy_path = tmp_path / "policies.json"
    policy_path.write_text(json.dumps(POLICIES), encoding="utf-8")

    settings = load_runtime_settings(runtime_environment(policy_path))

    assert settings.oidc.subject_claim == "oid"


@pytest.mark.parametrize(
    "jwks_url",
    [
        # A different host entirely: the whole point of the check.
        "https://attacker.example.test/realms/demo/protocol/openid-connect/certs",
        # Same host, but outside the issuer's own path.
        "https://idp.example.test/realms/other/protocol/openid-connect/certs",
        # Plaintext, so an on-path attacker could substitute signing keys.
        "http://idp.example.test/realms/demo/protocol/openid-connect/certs",
        # Query and fragment must not be smuggled in.
        "https://idp.example.test/realms/demo/certs?redirect=https://attacker.example.test",
        "https://idp.example.test/realms/demo/certs#x",
    ],
)
def test_rejects_a_jwks_endpoint_that_does_not_belong_to_the_issuer(
    tmp_path: Path, jwks_url: str
) -> None:
    """Signing keys decide authenticity, so their source must not be steerable."""
    policy_path = tmp_path / "policies.json"
    policy_path.write_text(json.dumps(POLICIES), encoding="utf-8")
    environment = _generic_issuer_environment(policy_path)
    environment["GABRO_OIDC_JWKS_URL"] = jwks_url

    with pytest.raises(RuntimeError, match="GABRO_OIDC_JWKS_URL"):
        load_runtime_settings(environment)


def test_rejects_a_plaintext_issuer(tmp_path: Path) -> None:
    policy_path = tmp_path / "policies.json"
    policy_path.write_text(json.dumps(POLICIES), encoding="utf-8")
    environment = _generic_issuer_environment(policy_path)
    environment["GABRO_OIDC_ISSUER"] = "http://idp.example.test/realms/demo"

    with pytest.raises(RuntimeError, match="GABRO_OIDC_ISSUER"):
        load_runtime_settings(environment)


def test_entra_issuers_keep_their_stricter_exact_jwks_rule(tmp_path: Path) -> None:
    """Entra's discovery URL is a known constant, so same-origin is not enough."""
    policy_path = tmp_path / "policies.json"
    policy_path.write_text(json.dumps(POLICIES), encoding="utf-8")
    environment = runtime_environment(policy_path)
    environment["GABRO_OIDC_JWKS_URL"] = (
        "https://login.microsoftonline.com/tenant-id/v2.0/keys"
    )

    with pytest.raises(RuntimeError, match="GABRO_OIDC_JWKS_URL"):
        load_runtime_settings(environment)


@pytest.mark.parametrize("claim", ["", "with space", "a-dash", "opt.ions", "1leading"])
def test_rejects_a_subject_claim_that_is_not_a_plain_name(tmp_path: Path, claim: str) -> None:
    policy_path = tmp_path / "policies.json"
    policy_path.write_text(json.dumps(POLICIES), encoding="utf-8")
    environment = _generic_issuer_environment(policy_path)
    environment["GABRO_OIDC_SUBJECT_CLAIM"] = claim

    with pytest.raises(RuntimeError, match="GABRO_OIDC_SUBJECT_CLAIM"):
        load_runtime_settings(environment)


def test_scope_claim_is_configurable_for_providers_that_use_the_oauth_spelling(
    tmp_path: Path,
) -> None:
    policy_path = tmp_path / "policies.json"
    policy_path.write_text(json.dumps(POLICIES), encoding="utf-8")
    environment = _generic_issuer_environment(policy_path)
    environment["GABRO_OIDC_SCOPE_CLAIM"] = "scope"

    settings = load_runtime_settings(environment)

    assert settings.oidc.scope_claim == "scope"


def test_scope_claim_defaults_to_the_entra_spelling(tmp_path: Path) -> None:
    policy_path = tmp_path / "policies.json"
    policy_path.write_text(json.dumps(POLICIES), encoding="utf-8")

    settings = load_runtime_settings(runtime_environment(policy_path))

    assert settings.oidc.scope_claim == "scp"


def test_rejects_a_scope_claim_that_is_not_a_plain_name(tmp_path: Path) -> None:
    policy_path = tmp_path / "policies.json"
    policy_path.write_text(json.dumps(POLICIES), encoding="utf-8")
    environment = _generic_issuer_environment(policy_path)
    environment["GABRO_OIDC_SCOPE_CLAIM"] = "not a claim"

    with pytest.raises(RuntimeError, match="GABRO_OIDC_SCOPE_CLAIM"):
        load_runtime_settings(environment)


def test_no_ca_bundle_means_the_default_trust_store(tmp_path: Path) -> None:
    policy_path = tmp_path / "policies.json"
    policy_path.write_text(json.dumps(POLICIES), encoding="utf-8")

    settings = load_runtime_settings(runtime_environment(policy_path))

    assert settings.tls_ca_bundle == ""
    assert runtime.build_ssl_context(settings) is None


def test_a_private_ca_bundle_becomes_a_verifying_context(tmp_path: Path) -> None:
    """An internal IdP or gateway behind a private CA must be reachable."""
    import ssl

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test ca")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2040, 1, 1, tzinfo=datetime.UTC))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    bundle = tmp_path / "ca.pem"
    bundle.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))

    policy_path = tmp_path / "policies.json"
    policy_path.write_text(json.dumps(POLICIES), encoding="utf-8")
    environment = runtime_environment(policy_path)
    environment["GABRO_TLS_CA_BUNDLE"] = str(bundle)

    settings = load_runtime_settings(environment)
    context = runtime.build_ssl_context(settings)

    assert settings.tls_ca_bundle == str(bundle)
    assert context is not None
    # Verification must not be weakened by supplying a CA.
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_rejects_an_unreadable_ca_bundle_at_startup(tmp_path: Path) -> None:
    """Fail on boot, not on the first request that needs the upstream."""
    policy_path = tmp_path / "policies.json"
    policy_path.write_text(json.dumps(POLICIES), encoding="utf-8")
    environment = runtime_environment(policy_path)
    environment["GABRO_TLS_CA_BUNDLE"] = str(tmp_path / "absent.pem")

    with pytest.raises(RuntimeError, match="GABRO_TLS_CA_BUNDLE"):
        load_runtime_settings(environment)
