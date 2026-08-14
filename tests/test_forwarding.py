# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable

import httpx
import pytest

from gatebroker import forwarding
from gatebroker.forwarding import _SUPPORTED_PATHS, _upstream_body, create_app
from gatebroker.oidc import TokenValidationConfig

POLICIES = '''
{
  "policies": [
    {
      "id": "researchers",
      "group_ids": ["group-research"],
      "allowed_models": ["gpt-4o-mini"],
      "key_ref": "RESEARCHERS_KEY",
      "priority": 10
    }
  ]
}
'''

TWO_POLICIES = '''
{
  "policies": [
    {
      "id": "researchers",
      "group_ids": ["group-research"],
      "allowed_models": ["gpt-4o-mini"],
      "key_ref": "RESEARCHERS_KEY",
      "priority": 10
    },
    {
      "id": "operators",
      "group_ids": ["group-operators"],
      "allowed_models": ["text-embedding-3-small"],
      "key_ref": "OPERATORS_KEY",
      "priority": 10
    }
  ]
}
'''


def verified_claims(token: str) -> dict[str, object]:
    return claims_for_group("group-research", oid="subject-123")


def claims_for_group(group: str, *, oid: str = "subject-123") -> dict[str, object]:
    return {
        "iss": "https://login.example.test/tenant/v2.0",
        "aud": "api://gatebroker",
        "exp": 4_000_000_000,
        "nbf": 0,
        "scp": "Broker.Access",
        "oid": oid,
        "groups": [group],
    }


def config() -> TokenValidationConfig:
    return TokenValidationConfig(
        issuer="https://login.example.test/tenant/v2.0",
        audience="api://gatebroker",
        required_delegated_scope="Broker.Access",
        allowed_app_roles=frozenset({"Broker.Automation"}),
    )


def app_with_upstream(
    upstream: Callable[[httpx.Request], httpx.Response],
    *,
    policies: str = POLICIES,
    verifier: Callable[[str], dict[str, object]] = verified_claims,
    key_resolver: Callable[[str], str] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    rate_limiter: Callable[[tuple[str, str, str]], bool] | None = None,
    max_request_bytes: int | None = None,
    max_response_bytes: int | None = None,
):
    bounds = {}
    if max_request_bytes is not None:
        bounds["max_request_bytes"] = max_request_bytes
    if max_response_bytes is not None:
        bounds["max_response_bytes"] = max_response_bytes
    return create_app(
        oidc_config=config(),
        token_verifier=verifier,
        policies_json=policies,
        upstream_base_url="https://gateway.internal",
        trusted_upstream_hosts=frozenset({"gateway.internal"}),
        key_resolver=key_resolver or (lambda _name: "test-policy-key"),
        rate_limiter=rate_limiter or (lambda _key: True),
        transport=transport or httpx.MockTransport(upstream),
        **bounds,
    )


def post(
    app, path: str, *, client_address: tuple[str, int] = ("127.0.0.1", 123), **kwargs: object
) -> httpx.Response:
    async def send() -> httpx.Response:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=client_address), base_url="https://broker.test"
        ) as client:
            return await client.post(path, **kwargs)

    return asyncio.run(send())


def get(app, path: str) -> httpx.Response:
    async def send() -> httpx.Response:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://broker.test"
        ) as client:
            return await client.get(path)

    return asyncio.run(send())


@pytest.mark.parametrize(
    "base_url",
    [
        "http://gateway.internal",
        "https://untrusted.example",
        "https://gateway.internal:8443@evil.example",
        "https://gateway.internal?redirect=https://evil.example",
        "https://gateway.internal#fragment",
        "ftp://gateway.internal",
    ],
)
def test_rejects_untrusted_or_non_tls_upstream_destination(base_url: str) -> None:
    with pytest.raises(ValueError, match="invalid upstream base URL"):
        create_app(
            oidc_config=config(),
            token_verifier=verified_claims,
            policies_json=POLICIES,
            upstream_base_url=base_url,
            trusted_upstream_hosts=frozenset({"gateway.internal"}),
            key_resolver=lambda _name: "test-policy-key",
            rate_limiter=lambda _key: True,
        )


@pytest.mark.parametrize(
    "base_url,trusted_host,opted_in",
    [
        # Plaintext is rejected without the explicit opt-in, even cluster-local.
        ("http://gateway.gateway.svc.cluster.local:4000", "gateway.gateway.svc.cluster.local", False),
        # The opt-in never unlocks plaintext toward non-cluster-local hosts.
        ("http://gateway.internal", "gateway.internal", True),
        ("http://gateway.example.com:4000", "gateway.example.com", True),
    ],
)
def test_rejects_plaintext_upstream_unless_explicitly_cluster_local(
    base_url: str, trusted_host: str, opted_in: bool
) -> None:
    with pytest.raises(ValueError, match="invalid upstream base URL"):
        create_app(
            oidc_config=config(),
            token_verifier=verified_claims,
            policies_json=POLICIES,
            upstream_base_url=base_url,
            trusted_upstream_hosts=frozenset({trusted_host}),
            key_resolver=lambda _name: "test-policy-key",
            rate_limiter=lambda _key: True,
            allow_cluster_local_plaintext_upstream=opted_in,
        )


def test_forwards_via_cluster_local_plaintext_upstream_when_opted_in() -> None:
    upstream_requests: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        return httpx.Response(200, json={"id": "chatcmpl-direct"})

    app = create_app(
        oidc_config=config(),
        token_verifier=verified_claims,
        policies_json=POLICIES,
        upstream_base_url="http://ai-gateway.ai-gateway.svc.cluster.local:4000",
        trusted_upstream_hosts=frozenset({"ai-gateway.ai-gateway.svc.cluster.local"}),
        key_resolver=lambda _name: "test-policy-key",
        rate_limiter=lambda _key: True,
        transport=httpx.MockTransport(upstream),
        allow_cluster_local_plaintext_upstream=True,
    )

    response = post(
        app,
        "/v1/chat/completions",
        headers={"Authorization": "Bearer client-token"},
        json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
    )

    assert response.status_code == 200
    assert response.json() == {"id": "chatcmpl-direct"}
    assert len(upstream_requests) == 1
    assert (
        str(upstream_requests[0].url)
        == "http://ai-gateway.ai-gateway.svc.cluster.local:4000/v1/chat/completions"
    )
    assert upstream_requests[0].headers["authorization"] == "Bearer test-policy-key"


def test_forwards_allowed_anthropic_message_with_server_key_and_authoritative_identity() -> None:
    upstream_requests: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        return httpx.Response(200, json={"id": "msg_test", "type": "message"})

    response = post(
        app_with_upstream(
            upstream,
            policies=POLICIES.replace("gpt-4o-mini", "claude-3-5-haiku"),
        ),
        "/v1/messages",
        headers={
            "Authorization": "Bearer client-token",
            "Anthropic-Version": "2023-06-01",
            "X-Request-ID": "request-123",
            "X-Api-Key": "client-supplied-key",
        },
        json={
            "model": "claude-3-5-haiku",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hi"}],
            "metadata": {"user_id": "client-identity"},
            "user": "client-identity",
        },
    )

    assert response.status_code == 200
    assert response.json() == {"id": "msg_test", "type": "message"}
    assert len(upstream_requests) == 1
    upstream_request = upstream_requests[0]
    assert upstream_request.url == "https://gateway.internal/v1/messages"
    assert upstream_request.headers["authorization"] == "Bearer test-policy-key"
    assert upstream_request.headers["anthropic-version"] == "2023-06-01"
    assert upstream_request.headers["x-request-id"] == "request-123"
    assert "x-api-key" not in upstream_request.headers
    assert json.loads(upstream_request.content) == {
        "model": "claude-3-5-haiku",
        "max_tokens": 64,
        "messages": [{"role": "user", "content": "hi"}],
        "metadata": {"user_id": "subject-123"},
    }


def test_forwards_anthropic_beta_query_and_header_for_non_streaming_message() -> None:
    upstream_requests: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        return httpx.Response(
            200,
            json={"id": "msg-request", "type": "message"},
            headers={"request-id": "msg-request"},
        )

    response = post(
        app_with_upstream(
            upstream,
            policies=POLICIES.replace("gpt-4o-mini", "claude-3-5-haiku"),
        ),
        "/v1/messages?beta=true",
        headers={
            "Authorization": "Bearer client-token",
            "Anthropic-Version": "2023-06-01",
            "Anthropic-Beta": "prompt-caching-2024-07-31",
        },
        json={
            "model": "claude-3-5-haiku",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hi"}],
        },
    )

    assert response.status_code == 200
    assert response.json() == {"id": "msg-request", "type": "message"}
    assert response.headers["request-id"] == "msg-request"
    assert upstream_requests[0].url == "https://gateway.internal/v1/messages?beta=true"
    assert upstream_requests[0].headers["anthropic-beta"] == "prompt-caching-2024-07-31"


def test_forwards_anthropic_messages_streaming_to_upstream() -> None:
    upstream_requests: list[httpx.Request] = []
    sse_body = b'event: message_stop\ndata: {"type": "message_stop"}\n\n'

    def upstream(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        return httpx.Response(
            200, content=sse_body, headers={"content-type": "text/event-stream"}
        )

    response = post(
        app_with_upstream(
            upstream,
            policies=POLICIES.replace("gpt-4o-mini", "claude-3-5-haiku"),
        ),
        "/v1/messages",
        headers={
            "Authorization": "Bearer client-token",
            "Anthropic-Version": "2023-06-01",
        },
        json={
            "model": "claude-3-5-haiku",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hi"}],
            "stream": True,
        },
    )

    assert response.status_code == 200
    assert response.content == sse_body
    assert response.headers["content-type"] == "text/event-stream"
    assert len(upstream_requests) == 1
    assert upstream_requests[0].headers["anthropic-version"] == "2023-06-01"
    assert json.loads(upstream_requests[0].content)["stream"] is True
    assert json.loads(upstream_requests[0].content)["metadata"] == {"user_id": "subject-123"}


@pytest.mark.parametrize(
    ("path", "body"),
    [
        (
            "/v1/messages",
            {
                "model": "claude-3-5-haiku",
                "max_tokens": 64,
                "messages": [{"role": "user", "content": "hi"}],
                "stream": "true",
            },
        ),
        (
            "/v1/embeddings",
            {"model": "claude-3-5-haiku", "input": "hi", "stream": True},
        ),
    ],
)
def test_rejects_non_boolean_or_embeddings_streaming_without_upstream_call(
    path: str, body: dict[str, object]
) -> None:
    upstream_requests: list[httpx.Request] = []

    response = post(
        app_with_upstream(
            lambda request: upstream_requests.append(request) or httpx.Response(200),
            policies=POLICIES.replace("gpt-4o-mini", "claude-3-5-haiku"),
        ),
        path,
        headers={
            "Authorization": "Bearer client-token",
            "Anthropic-Version": "2023-06-01",
        },
        json=body,
    )

    assert response.status_code == 400
    assert response.json()["error"]["message"] == "invalid request"
    assert upstream_requests == []


def test_rejects_unallowlisted_query_parameters_without_upstream_call() -> None:
    upstream_requests: list[httpx.Request] = []

    response = post(
        app_with_upstream(lambda request: upstream_requests.append(request) or httpx.Response(200)),
        "/v1/chat/completions?target=attacker",
        headers={"Authorization": "Bearer client-token"},
        json={"model": "gpt-4o-mini", "messages": []},
    )

    assert response.status_code == 400
    assert upstream_requests == []


@pytest.mark.parametrize(
    "headers",
    [
        [
            ("Authorization", "Bearer client-token"),
            ("Authorization", "Bearer second-token"),
        ],
        [
            ("Authorization", "Bearer client-token"),
            ("Anthropic-Version", "2023-06-01"),
            ("Anthropic-Version", "2023-06-01"),
        ],
    ],
)
def test_rejects_duplicate_security_control_headers(
    headers: list[tuple[str, str]],
) -> None:
    calls = 0

    def upstream(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200)

    response = post(
        app_with_upstream(
            upstream,
            policies=POLICIES.replace("gpt-4o-mini", "claude-3-5-haiku"),
        ),
        "/v1/messages",
        headers=headers,
        json={
            "model": "claude-3-5-haiku",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hi"}],
        },
    )

    assert response.status_code in {400, 401}
    assert calls == 0


def test_role_only_identity_resolves_an_app_role_policy() -> None:
    policies = '''
    {"policies": [{
      "id": "automation",
      "app_roles": ["Broker.Automation"],
      "allowed_models": ["gpt-4o-mini"],
      "key_ref": "AUTOMATION_KEY",
      "priority": 10
    }]}
    '''

    def verifier(_token: str) -> dict[str, object]:
        claims = claims_for_group("unused")
        claims.pop("groups")
        claims["scp"] = None
        claims["roles"] = ["Broker.Automation"]
        return claims

    response = post(
        app_with_upstream(
            lambda _request: httpx.Response(200),
            policies=policies,
            verifier=verifier,
        ),
        "/v1/chat/completions",
        headers={"Authorization": "Bearer client-token"},
        json={"model": "gpt-4o-mini", "messages": []},
    )

    assert response.status_code == 200


def test_denies_anthropic_message_without_version_header_without_upstream_call() -> None:
    upstream_requests: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        return httpx.Response(200)

    response = post(
        app_with_upstream(
            upstream,
            policies=POLICIES.replace("gpt-4o-mini", "claude-3-5-haiku"),
        ),
        "/v1/messages",
        headers={"Authorization": "Bearer client-token"},
        json={
            "model": "claude-3-5-haiku",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hi"}],
        },
    )

    assert response.status_code == 400
    assert response.json()["error"]["message"] == "invalid request"
    assert upstream_requests == []


@pytest.mark.parametrize(
    "body",
    [
        {"model": "claude-3-5-haiku"},
        {"model": "claude-3-5-haiku", "max_tokens": 64},
        {"model": "claude-3-5-haiku", "messages": []},
        {"model": "claude-3-5-haiku", "max_tokens": "64", "messages": []},
        {"model": "claude-3-5-haiku", "max_tokens": 64, "messages": "invalid"},
        {"model": "claude-3-5-haiku", "max_tokens": 64, "messages": ["invalid"]},
        {"model": "claude-3-5-haiku", "max_tokens": 64, "messages": [{"role": "user"}]},
        {"model": "claude-3-5-haiku", "max_tokens": 64, "messages": [{"content": "hi"}]},
    ],
)
def test_denies_malformed_anthropic_messages_without_upstream_call(body: dict[str, object]) -> None:
    upstream_requests: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        return httpx.Response(200)

    response = post(
        app_with_upstream(
            upstream,
            policies=POLICIES.replace("gpt-4o-mini", "claude-3-5-haiku"),
        ),
        "/v1/messages",
        headers={
            "Authorization": "Bearer client-token",
            "Anthropic-Version": "2023-06-01",
        },
        json=body,
    )

    assert response.status_code == 400
    assert response.json()["error"]["message"] == "invalid request"
    assert upstream_requests == []


def test_forwards_anthropic_message_but_denies_disallowed_models_before_key_lookup() -> None:
    upstream_calls = 0
    key_calls = 0

    def upstream(_request: httpx.Request) -> httpx.Response:
        nonlocal upstream_calls
        upstream_calls += 1
        return httpx.Response(200, content=b"data: done\n\n")

    def key_resolver(_name: str) -> str:
        nonlocal key_calls
        key_calls += 1
        return "test-policy-key"

    app = app_with_upstream(
        upstream,
        policies=POLICIES.replace("gpt-4o-mini", "claude-3-5-haiku"),
        key_resolver=key_resolver,
    )
    headers = {
        "Authorization": "Bearer client-token",
        "Anthropic-Version": "2023-06-01",
    }
    allowed = post(
        app,
        "/v1/messages",
        headers=headers,
        json={
            "model": "claude-3-5-haiku",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hi"}],
        },
    )
    denied_model = post(
        app,
        "/v1/messages",
        headers=headers,
        json={
            "model": "not-entitled",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hi"}],
        },
    )

    assert allowed.status_code == 200
    assert allowed.content == b"data: done\n\n"
    assert denied_model.status_code == 403
    assert key_calls == 1
    assert upstream_calls == 1


def test_forwards_anthropic_allowed_fields_and_removes_non_allowlisted_fields() -> None:
    upstream_requests: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        return httpx.Response(200)

    response = post(
        app_with_upstream(
            upstream,
            policies=POLICIES.replace("gpt-4o-mini", "claude-3-5-haiku"),
        ),
        "/v1/messages",
        headers={
            "Authorization": "Bearer client-token",
            "Anthropic-Version": "2023-06-01",
        },
        json={
            "model": "claude-3-5-haiku",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hi"}],
            "system": "system prompt",
            "temperature": 0.2,
            "top_p": 0.9,
            "tools": [{"name": "lookup", "input_schema": {"type": "object"}}],
            "tool_choice": {"type": "auto"},
            "thinking": {"type": "enabled", "budget_tokens": 32},
            "metadata": {"user_id": "client-identity"},
            "routing": {"target": "external"},
        },
    )

    assert response.status_code == 200
    assert json.loads(upstream_requests[0].content) == {
        "model": "claude-3-5-haiku",
        "max_tokens": 64,
        "messages": [{"role": "user", "content": "hi"}],
        "system": "system prompt",
        "temperature": 0.2,
        "top_p": 0.9,
        "tools": [{"name": "lookup", "input_schema": {"type": "object"}}],
        "tool_choice": {"type": "auto"},
        "thinking": {"type": "enabled", "budget_tokens": 32},
        "metadata": {"user_id": "subject-123"},
    }


def test_forwards_allowed_chat_with_server_key_and_authoritative_identity() -> None:
    upstream_requests: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        return httpx.Response(200, json={"id": "chatcmpl-test"})

    response = post(
        app_with_upstream(upstream),
        "/v1/chat/completions",
        headers={"Authorization": "Bearer client-token"},
        json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
    )

    assert response.status_code == 200
    assert response.json() == {"id": "chatcmpl-test"}
    assert len(upstream_requests) == 1
    upstream_request = upstream_requests[0]
    assert upstream_request.url == "https://gateway.internal/v1/chat/completions"
    assert upstream_request.headers["authorization"] == "Bearer test-policy-key"
    assert json.loads(upstream_request.content)["user"] == "subject-123"


def test_emits_a_safe_audit_event_for_an_authorized_request(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger="uvicorn.error"):
        response = post(
            app_with_upstream(lambda _request: httpx.Response(200)),
            "/v1/chat/completions",
            headers={"Authorization": "Bearer client-token"},
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "private prompt"}]},
        )

    assert response.status_code == 200
    audit_records = [record.getMessage() for record in caplog.records if record.name == "uvicorn.error"]
    assert len(audit_records) == 1
    event = json.loads(audit_records[0])
    assert event["event"] == "broker_request"
    assert event["outcome"] == "forwarded"
    assert event["path"] == "/v1/chat/completions"
    assert event["status_code"] == 200
    assert event["policy_id"] == "researchers"
    assert event["model"] == "gpt-4o-mini"
    assert isinstance(event["duration_ms"], int)
    log_output = audit_records[0]
    for prohibited_value in ("client-token", "subject-123", "private prompt", "test-policy-key", "127.0.0.1"):
        assert prohibited_value not in log_output


def test_emits_a_safe_audit_event_for_authentication_failure(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger="uvicorn.error"):
        response = post(
            app_with_upstream(
                lambda _request: httpx.Response(200),
                verifier=lambda _token: (_ for _ in ()).throw(ValueError("invalid token")),
            ),
            "/v1/chat/completions",
            headers={"Authorization": "Bearer malformed-token"},
            json={"model": "gpt-4o-mini", "messages": []},
        )

    assert response.status_code == 401
    audit_records = [record.getMessage() for record in caplog.records if record.name == "uvicorn.error"]
    assert len(audit_records) == 1
    event = json.loads(audit_records[0])
    assert event == {
        "event": "broker_request",
        "outcome": "authentication_failed",
        "path": "/v1/chat/completions",
        "status_code": 401,
        "duration_ms": event["duration_ms"],
        "detail": "TokenValidationError",
    }
    assert isinstance(event["duration_ms"], int)
    assert "malformed-token" not in audit_records[0]
    assert "invalid token" not in audit_records[0]


def test_emits_service_unavailable_when_the_server_side_key_cannot_be_resolved(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="uvicorn.error"):
        response = post(
            app_with_upstream(
                lambda _request: httpx.Response(200),
                key_resolver=lambda _name: (_ for _ in ()).throw(RuntimeError("key store unavailable")),
            ),
            "/v1/chat/completions",
            headers={"Authorization": "Bearer client-token"},
            json={"model": "gpt-4o-mini", "messages": []},
        )

    assert response.status_code == 503
    audit_records = [record.getMessage() for record in caplog.records if record.name == "uvicorn.error"]
    assert len(audit_records) == 1
    event = json.loads(audit_records[0])
    assert event["outcome"] == "service_unavailable"
    assert event["status_code"] == 503
    assert event["policy_id"] == "researchers"
    assert event["model"] == "gpt-4o-mini"
    assert event["detail"] == "RuntimeError"
    assert "key store unavailable" not in audit_records[0]


def test_audit_detail_classifies_envoy_denial(caplog: pytest.LogCaptureFixture) -> None:
    """A policy-layer denial (e.g. Envoy "Access denied") must be visible in the audit log."""
    with caplog.at_level(logging.INFO, logger="uvicorn.error"):
        response = post(
            app_with_upstream(lambda _request: httpx.Response(403, content=b"Access denied")),
            "/v1/chat/completions",
            headers={"Authorization": "Bearer client-token"},
            json={"model": "gpt-4o-mini", "messages": []},
        )

    assert response.status_code == 403
    assert response.json()["error"]["message"] == "upstream request failed"
    assert "Access denied" not in response.text
    audit_records = [record.getMessage() for record in caplog.records if record.name == "uvicorn.error"]
    assert len(audit_records) == 1
    event = json.loads(audit_records[0])
    assert event["outcome"] == "upstream_failed"
    assert event["status_code"] == 403
    assert event["detail"] == "envoy_access_denied"


def test_audit_detail_does_not_log_an_echoed_server_key(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger="uvicorn.error"):
        response = post(
            app_with_upstream(
                lambda _request: httpx.Response(
                    401, content=b'{"error": "invalid key test-policy-key provided"}'
                )
            ),
            "/v1/chat/completions",
            headers={"Authorization": "Bearer client-token"},
            json={"model": "gpt-4o-mini", "messages": []},
        )

    assert response.status_code == 401
    audit_records = [record.getMessage() for record in caplog.records if record.name == "uvicorn.error"]
    assert len(audit_records) == 1
    event = json.loads(audit_records[0])
    assert "test-policy-key" not in audit_records[0]
    assert event["detail"] == "upstream_key_rejected"


def test_audit_detail_does_not_log_upstream_body_content(caplog: pytest.LogCaptureFixture) -> None:
    noisy_body = ("prompt-like secret text\nline two\t" + "x" * 5_000).encode()
    with caplog.at_level(logging.INFO, logger="uvicorn.error"):
        response = post(
            app_with_upstream(lambda _request: httpx.Response(500, content=noisy_body)),
            "/v1/chat/completions",
            headers={"Authorization": "Bearer client-token"},
            json={"model": "gpt-4o-mini", "messages": []},
        )

    assert response.status_code == 500
    audit_records = [record.getMessage() for record in caplog.records if record.name == "uvicorn.error"]
    event = json.loads(audit_records[0])
    assert event["detail"] == "upstream_plaintext_error"
    assert "prompt-like secret text" not in audit_records[0]
    assert "line two" not in audit_records[0]


def test_audit_detail_classifies_tool_schema_rejection(caplog: pytest.LogCaptureFixture) -> None:
    error_body = json.dumps(
        {
            "error": {
                "message": "Invalid 'tools[0].description': string too short.",
                "type": "invalid_request_error",
                "param": "tools[0].description",
            }
        }
    ).encode()
    with caplog.at_level(logging.INFO, logger="uvicorn.error"):
        response = post(
            app_with_upstream(
                lambda _request: httpx.Response(
                    400,
                    content=error_body,
                    headers={"content-type": "application/json"},
                )
            ),
            "/v1/chat/completions",
            headers={"Authorization": "Bearer client-token"},
            json={"model": "gpt-4o-mini", "messages": []},
        )

    assert response.status_code == 400
    audit_records = [record.getMessage() for record in caplog.records if record.name == "uvicorn.error"]
    event = json.loads(audit_records[0])
    assert event["detail"] == "upstream_tool_schema_rejected"
    assert "tools[0].description" not in audit_records[0]


def test_audit_detail_names_upstream_transport_failure(caplog: pytest.LogCaptureFixture) -> None:
    class _FailingTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("dial tcp refused", request=request)

    with caplog.at_level(logging.INFO, logger="uvicorn.error"):
        response = post(
            app_with_upstream(
                lambda _request: httpx.Response(200), transport=_FailingTransport()
            ),
            "/v1/chat/completions",
            headers={"Authorization": "Bearer client-token"},
            json={"model": "gpt-4o-mini", "messages": []},
        )

    assert response.status_code == 502
    audit_records = [record.getMessage() for record in caplog.records if record.name == "uvicorn.error"]
    event = json.loads(audit_records[0])
    assert event["outcome"] == "upstream_failed"
    assert event["detail"] == "ConnectError"
    assert "dial tcp refused" not in audit_records[0]


def test_does_not_redirect_or_forward_unsupported_trailing_path() -> None:
    upstream_requests: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        return httpx.Response(200)

    response = post(
        app_with_upstream(upstream),
        "/v1/chat/completions/",
        headers={"Authorization": "Bearer client-token"},
        json={"model": "gpt-4o-mini", "messages": []},
        follow_redirects=False,
    )

    assert response.status_code == 404
    assert upstream_requests == []


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_does_not_expose_fastapi_documentation_routes(path: str) -> None:
    response = get(app_with_upstream(lambda _request: httpx.Response(200)), path)

    assert response.status_code == 404


def test_selects_each_matching_policy_server_side_key() -> None:
    upstream_requests: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        return httpx.Response(200, json={"ok": True})

    def verifier(token: str) -> dict[str, object]:
        return claims_for_group(
            "group-research" if token == "researcher" else "group-operators",
            oid=f"oid-{token}",
        )

    app = app_with_upstream(
        upstream,
        policies=TWO_POLICIES,
        verifier=verifier,
        key_resolver=lambda name: {
            "RESEARCHERS_KEY": "research-key",
            "OPERATORS_KEY": "operators-key",
        }[name],
    )

    assert post(app, "/v1/chat/completions", headers={"Authorization": "Bearer researcher"}, json={"model": "gpt-4o-mini", "messages": []}).status_code == 200
    assert post(app, "/v1/embeddings", headers={"Authorization": "Bearer operator"}, json={"model": "text-embedding-3-small", "input": "hello"}).status_code == 200

    assert [request.headers["authorization"] for request in upstream_requests] == [
        "Bearer research-key",
        "Bearer operators-key",
    ]
    assert [json.loads(request.content)["user"] for request in upstream_requests] == [
        "oid-researcher",
        "oid-operator",
    ]


@pytest.mark.parametrize(
    "authorization", [None, "", "Basic client-token", "Bearer", "Bearer ", "Bearer client token"]
)
def test_denies_missing_or_malformed_bearer_without_upstream_call(
    authorization: str | None,
) -> None:
    calls = 0

    def upstream(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200)

    headers = {} if authorization is None else {"Authorization": authorization}
    response = post(
        app_with_upstream(upstream),
        "/v1/chat/completions",
        headers=headers,
        json={"model": "gpt-4o-mini", "messages": []},
    )

    assert response.status_code == 401
    assert response.json()["error"]["message"] == "authentication failed"
    assert calls == 0


@pytest.mark.parametrize(
    ("policies", "groups"),
    [
        (POLICIES, ["unmatched-group"]),
        (
            TWO_POLICIES,
            ["group-research", "group-operators"],
        ),
    ],
)
def test_denies_no_match_or_ambiguous_policy_without_upstream_call(
    policies: str, groups: list[str]
) -> None:
    calls = 0

    def upstream(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200)

    def verifier(_token: str) -> dict[str, object]:
        claims = claims_for_group(groups[0])
        claims["groups"] = groups
        return claims

    response = post(
        app_with_upstream(upstream, policies=policies, verifier=verifier),
        "/v1/chat/completions",
        headers={"Authorization": "Bearer client-token"},
        json={"model": "gpt-4o-mini", "messages": []},
    )

    assert response.status_code == 403
    assert response.json()["error"]["message"] == "request denied"
    assert calls == 0


def test_denies_disallowed_model_without_upstream_call() -> None:
    calls = 0

    def upstream(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200)

    response = post(
        app_with_upstream(upstream),
        "/v1/chat/completions",
        headers={"Authorization": "Bearer client-token"},
        json={"model": "not-entitled", "messages": []},
    )

    assert response.status_code == 403
    assert calls == 0


def test_rate_limiter_receives_validated_identity_policy_and_client_ip() -> None:
    keys: list[tuple[str, str, str]] = []

    def limiter(key: tuple[str, str, str]) -> bool:
        keys.append(key)
        return True

    response = post(
        app_with_upstream(lambda _request: httpx.Response(200), rate_limiter=limiter),
        "/v1/chat/completions",
        client_address=("203.0.113.7", 4567),
        headers={"Authorization": "Bearer client-token"},
        json={"model": "gpt-4o-mini", "messages": []},
    )

    assert response.status_code == 200
    assert keys == [("subject-123", "researchers", "203.0.113.7")]


def test_rate_limit_rejection_denies_without_key_or_upstream_call() -> None:
    upstream_calls = 0
    key_calls = 0

    def upstream(_request: httpx.Request) -> httpx.Response:
        nonlocal upstream_calls
        upstream_calls += 1
        return httpx.Response(200)

    def key_resolver(_name: str) -> str:
        nonlocal key_calls
        key_calls += 1
        return "test-policy-key"

    response = post(
        app_with_upstream(upstream, key_resolver=key_resolver, rate_limiter=lambda _key: False),
        "/v1/chat/completions",
        headers={"Authorization": "Bearer client-token"},
        json={"model": "gpt-4o-mini", "messages": []},
    )

    assert response.status_code == 429
    assert response.json()["error"]["message"] == "request denied"
    assert key_calls == 0
    assert upstream_calls == 0


def test_invalid_rate_limiter_result_fails_closed_without_upstream_call() -> None:
    upstream_calls = 0

    def upstream(_request: httpx.Request) -> httpx.Response:
        nonlocal upstream_calls
        upstream_calls += 1
        return httpx.Response(200)

    response = post(
        app_with_upstream(upstream, rate_limiter=lambda _key: "invalid"),  # type: ignore[arg-type, return-value]
        "/v1/chat/completions",
        headers={"Authorization": "Bearer client-token"},
        json={"model": "gpt-4o-mini", "messages": []},
    )

    assert response.status_code == 503
    assert response.json()["error"]["message"] == "service unavailable"
    assert upstream_calls == 0


def test_rate_limiter_exception_fails_closed_without_upstream_call() -> None:
    upstream_calls = 0

    def upstream(_request: httpx.Request) -> httpx.Response:
        nonlocal upstream_calls
        upstream_calls += 1
        return httpx.Response(200)

    def broken_limiter(_key: tuple[str, str, str]) -> bool:
        raise RuntimeError("limiter failure that must not leak")

    response = post(
        app_with_upstream(upstream, rate_limiter=broken_limiter),
        "/v1/chat/completions",
        headers={"Authorization": "Bearer client-token"},
        json={"model": "gpt-4o-mini", "messages": []},
    )

    assert response.status_code == 503
    assert response.json()["error"]["message"] == "service unavailable"
    assert "limiter failure" not in response.text
    assert upstream_calls == 0


def test_invalid_or_unauthorized_requests_do_not_consume_rate_limit_slots() -> None:
    keys: list[tuple[str, str, str]] = []
    upstream_calls = 0

    def limiter(key: tuple[str, str, str]) -> bool:
        keys.append(key)
        return True

    def upstream(_request: httpx.Request) -> httpx.Response:
        nonlocal upstream_calls
        upstream_calls += 1
        return httpx.Response(200)

    unauthorized_app = app_with_upstream(upstream, rate_limiter=limiter)
    invalid_app = app_with_upstream(
        upstream,
        rate_limiter=limiter,
        verifier=lambda _token: (_ for _ in ()).throw(ValueError("invalid token")),
    )
    malformed_token = post(
        invalid_app,
        "/v1/chat/completions",
        headers={"Authorization": "Bearer malformed-token"},
        json={"model": "gpt-4o-mini", "messages": []},
    )
    unauthorized_model = post(
        unauthorized_app,
        "/v1/chat/completions",
        headers={"Authorization": "Bearer client-token"},
        json={"model": "not-entitled", "messages": []},
    )

    assert malformed_token.status_code == 401
    assert unauthorized_model.status_code == 403
    assert keys == []
    assert upstream_calls == 0


def test_forwards_chat_completion_streaming_to_upstream() -> None:
    calls = 0

    def upstream(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, content=b"data: [DONE]\n\n", headers={"content-type": "text/event-stream"})

    response = post(
        app_with_upstream(upstream),
        "/v1/chat/completions",
        headers={"Authorization": "Bearer client-token"},
        json={"model": "gpt-4o-mini", "messages": [], "stream": True},
    )

    assert response.status_code == 200
    assert response.content == b"data: [DONE]\n\n"
    assert response.headers["content-type"] == "text/event-stream"
    assert calls == 1


def test_rebuilds_body_and_headers_without_client_controlled_routing_data() -> None:
    upstream_requests: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        return httpx.Response(200, json={"ok": True})

    response = post(
        app_with_upstream(upstream),
        "/v1/chat/completions",
        headers={
            "Authorization": "Bearer client-token",
            "Accept": "application/json",
            "X-Request-ID": "request-123",
            "X-Untrusted": "discard-me",
        },
        json={
            "model": "gpt-4o-mini",
            "messages": [],
            "temperature": 0.4,
            "user": "client-controlled-user",
            "metadata": {"client": "controlled"},
            "team_id": "client-team",
            "max_budget": 1_000_000,
            "rpm_limit": 1_000_000,
            "tpm_limit": 1_000_000,
            "provider_params": {"api_key": "client-key"},
            "router_settings": {"model_group_alias": "untrusted"},
        },
    )

    assert response.status_code == 200
    upstream_request = upstream_requests[0]
    assert json.loads(upstream_request.content) == {
        "model": "gpt-4o-mini",
        "messages": [],
        "temperature": 0.4,
        "user": "subject-123",
    }
    assert upstream_request.headers["authorization"] == "Bearer test-policy-key"
    assert upstream_request.headers["x-gabro-policy-id"] == "researchers"
    assert upstream_request.headers["accept"] == "application/json"
    assert upstream_request.headers["x-request-id"] == "request-123"
    assert "x-untrusted" not in upstream_request.headers


class _OverLimitRequestStream(httpx.AsyncByteStream):
    """Yields one byte more than the configured bound, then fails if read again."""

    def __init__(self, limit: int) -> None:
        self.chunks_yielded = 0
        self._limit = limit

    async def __aiter__(self):
        self.chunks_yielded += 1
        yield b"x" * self._limit
        self.chunks_yielded += 1
        yield b"x"
        raise AssertionError("broker read beyond the request limit")

    async def aclose(self) -> None:
        pass


def test_stops_consuming_chunked_body_when_request_limit_is_exceeded() -> None:
    calls = 0

    def upstream(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200)

    limit = 4096
    stream = _OverLimitRequestStream(limit)
    response = post(
        app_with_upstream(upstream, max_request_bytes=limit),
        "/v1/chat/completions",
        headers={"Authorization": "Bearer client-token", "Content-Type": "application/json"},
        content=stream,
    )

    assert response.status_code == 400
    assert response.json()["error"]["message"] == "invalid request"
    assert stream.chunks_yielded == 2
    assert calls == 0


def test_denies_deeply_nested_json_without_upstream_call() -> None:
    calls = 0

    def upstream(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200)

    content = b'{"model":"gpt-4o-mini","messages":' + (b"[" * 2_000) + (b"]" * 2_000) + b"}"
    response = post(
        app_with_upstream(upstream),
        "/v1/chat/completions",
        headers={"Authorization": "Bearer client-token", "Content-Type": "application/json"},
        content=content,
    )

    assert response.status_code == 400
    assert response.json()["error"]["message"] == "invalid request"
    assert calls == 0


@pytest.mark.parametrize(
    "content",
    [b"", b"{", b"[]", b'{"messages": []}', b'{"model": 5}', b'{"model": ""}'],
)
def test_denies_malformed_or_model_less_request_without_upstream_call(content: bytes) -> None:
    calls = 0

    def upstream(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200)

    response = post(
        app_with_upstream(upstream),
        "/v1/chat/completions",
        headers={"Authorization": "Bearer client-token", "Content-Type": "application/json"},
        content=content,
    )

    assert response.status_code == 400
    assert response.json()["error"]["message"] == "invalid request"
    assert calls == 0


class _OverLimitResponseStream(httpx.AsyncByteStream):
    def __init__(self) -> None:
        self.chunks_yielded = 0
        self.closed = False

    async def __aiter__(self):
        self.chunks_yielded += 1
        yield b"x" * 10_485_760
        self.chunks_yielded += 1
        yield b"x"
        raise AssertionError("broker read beyond the response limit")

    async def aclose(self) -> None:
        self.closed = True


class _ChunkedResponseStream(httpx.AsyncByteStream):
    def __init__(self, chunk_count: int) -> None:
        self.chunk_count = chunk_count
        self.chunks_yielded = 0
        self.closed = False

    async def __aiter__(self):
        for _ in range(self.chunk_count):
            self.chunks_yielded += 1
            yield b"data: chunk\n\n"
            await asyncio.sleep(0)

    async def aclose(self) -> None:
        self.closed = True


class _StreamingResponseTransport(httpx.AsyncBaseTransport):
    def __init__(self, stream: httpx.AsyncByteStream) -> None:
        self.stream = stream

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=self.stream, request=request)


class _FailingTransport(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.closed = False

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("upstream unavailable", request=request)

    async def aclose(self) -> None:
        self.closed = True


def test_stops_reading_and_closes_over_limit_upstream_response() -> None:
    stream = _OverLimitResponseStream()
    response = post(
        app_with_upstream(
            lambda _request: httpx.Response(500),
            transport=_StreamingResponseTransport(stream),
        ),
        "/v1/chat/completions",
        headers={"Authorization": "Bearer client-token"},
        json={"model": "gpt-4o-mini", "messages": []},
    )

    assert response.status_code == 502
    assert response.json()["error"]["message"] == "upstream response failed"
    assert stream.chunks_yielded == 2
    assert stream.closed is True


def test_pooled_upstream_client_closes_at_shutdown_after_connection_failure() -> None:
    transport = _FailingTransport()
    app = app_with_upstream(lambda _request: httpx.Response(500), transport=transport)

    async def send() -> httpx.Response:
        async with app.router.lifespan_context(app), httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="https://broker.test",
        ) as client:
            response = await client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer client-token"},
                json={"model": "gpt-4o-mini", "messages": []},
            )
            assert transport.closed is False
            return response

    response = asyncio.run(send())

    assert response.status_code == 502
    assert response.json()["error"]["message"] == "upstream request failed"
    assert transport.closed is True


def test_stops_and_closes_an_over_limit_streaming_response() -> None:
    stream = _OverLimitResponseStream()
    response = post(
        app_with_upstream(
            lambda _request: httpx.Response(500),
            transport=_StreamingResponseTransport(stream),
        ),
        "/v1/chat/completions",
        headers={"Authorization": "Bearer client-token"},
        json={"model": "gpt-4o-mini", "messages": [], "stream": True},
    )

    assert response.status_code == 200
    assert len(response.content) == 10_485_760
    assert stream.chunks_yielded == 2
    assert stream.closed is True


def test_client_disconnect_closes_the_upstream_anthropic_stream() -> None:
    stream = _ChunkedResponseStream(chunk_count=100_000)
    app = app_with_upstream(
        lambda _request: httpx.Response(500),
        policies=POLICIES.replace("gpt-4o-mini", "claude-3-5-haiku"),
        transport=_StreamingResponseTransport(stream),
    )

    body = json.dumps(
        {
            "model": "claude-3-5-haiku",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hi"}],
            "stream": True,
        }
    ).encode()
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/v1/messages",
        "raw_path": b"/v1/messages",
        "query_string": b"",
        "root_path": "",
        "headers": [
            (b"host", b"broker.test"),
            (b"authorization", b"Bearer client-token"),
            (b"anthropic-version", b"2023-06-01"),
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ],
        "client": ("127.0.0.1", 123),
        "server": ("broker.test", 443),
    }
    incoming = iter(
        [
            {"type": "http.request", "body": body, "more_body": False},
            {"type": "http.disconnect"},
        ]
    )
    sent: list[dict[str, object]] = []

    async def receive() -> dict[str, object]:
        return next(incoming)

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    asyncio.run(app(scope, receive, send))

    start = next(message for message in sent if message["type"] == "http.response.start")
    assert start["status"] == 200
    assert stream.closed is True
    assert stream.chunks_yielded < 100_000


def test_stops_and_closes_an_over_limit_anthropic_streaming_response() -> None:
    stream = _OverLimitResponseStream()
    response = post(
        app_with_upstream(
            lambda _request: httpx.Response(500),
            policies=POLICIES.replace("gpt-4o-mini", "claude-3-5-haiku"),
            transport=_StreamingResponseTransport(stream),
        ),
        "/v1/messages",
        headers={
            "Authorization": "Bearer client-token",
            "Anthropic-Version": "2023-06-01",
        },
        json={
            "model": "claude-3-5-haiku",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hi"}],
            "stream": True,
        },
    )

    assert response.status_code == 200
    assert len(response.content) == 10_485_760
    assert stream.chunks_yielded == 2
    assert stream.closed is True


def test_sanitizes_upstream_error_without_server_key_or_body_leakage() -> None:
    def upstream(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, content=b"raw upstream response test-policy-key")

    response = post(
        app_with_upstream(upstream),
        "/v1/chat/completions",
        headers={"Authorization": "Bearer client-token"},
        json={"model": "gpt-4o-mini", "messages": []},
    )

    assert response.status_code == 429
    assert response.json() == {
        "error": {"message": "upstream request failed", "type": "broker_error"}
    }
    assert "test-policy-key" not in response.text


def test_sanitizes_verifier_and_key_resolver_errors() -> None:
    calls = 0

    def upstream(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200)

    def broken_verifier(_token: str) -> dict[str, object]:
        raise RuntimeError("token error that must not leak")

    verifier_response = post(
        app_with_upstream(upstream, verifier=broken_verifier),
        "/v1/chat/completions",
        headers={"Authorization": "Bearer client-token"},
        json={"model": "gpt-4o-mini", "messages": []},
    )
    resolver_response = post(
        app_with_upstream(
            upstream,
            key_resolver=lambda _name: (_ for _ in ()).throw(
                RuntimeError("key error that must not leak")
            ),
        ),
        "/v1/chat/completions",
        headers={"Authorization": "Bearer client-token"},
        json={"model": "gpt-4o-mini", "messages": []},
    )

    assert verifier_response.status_code == 401
    assert resolver_response.status_code == 503
    assert "token error" not in verifier_response.text
    assert "key error" not in resolver_response.text
    assert calls == 0


def test_responses_endpoint_is_supported() -> None:
    assert '/v1/responses' in _SUPPORTED_PATHS


def test_responses_body_preserves_supported_fields() -> None:
    body = {'model': 'gpt-4.1-mini', 'input': 'hello', 'instructions': 'be concise', 'max_output_tokens': 32, 'stream': True}
    assert _upstream_body('/v1/responses', body, 'subject-123') == {**body, 'store': False, 'user': 'subject-123'}


def test_responses_body_preserves_tool_and_reasoning_configuration() -> None:
    body = {'model': 'gpt-4.1-mini', 'input': 'hello', 'tools': [{'type': 'web_search'}], 'tool_choice': 'auto', 'parallel_tool_calls': True, 'reasoning': {'effort': 'medium'}, 'text': {'verbosity': 'low'}, 'store': False}
    assert _upstream_body('/v1/responses', body, 'subject-123') == {**body, 'store': False, 'include': ['reasoning.encrypted_content'], 'user': 'subject-123'}


def test_responses_body_injects_encrypted_reasoning_include_when_missing() -> None:
    body = {'model': 'gpt-5-codex', 'input': 'hello', 'reasoning': {'effort': 'high'}}
    result = _upstream_body('/v1/responses', body, 'subject-123')
    assert result['include'] == ['reasoning.encrypted_content']
    assert result['store'] is False


def test_responses_body_preserves_and_dedupes_client_include() -> None:
    body = {
        'model': 'gpt-5-codex',
        'input': 'hello',
        'reasoning': {'effort': 'high'},
        'include': ['message.output_text.logprobs', 'reasoning.encrypted_content'],
    }
    result = _upstream_body('/v1/responses', body, 'subject-123')
    assert result['include'] == ['message.output_text.logprobs', 'reasoning.encrypted_content']


def test_responses_body_appends_encrypted_reasoning_to_client_include() -> None:
    body = {
        'model': 'gpt-5-codex',
        'input': 'hello',
        'reasoning': {'effort': 'high'},
        'include': ['message.output_text.logprobs'],
    }
    result = _upstream_body('/v1/responses', body, 'subject-123')
    assert result['include'] == ['message.output_text.logprobs', 'reasoning.encrypted_content']


def test_responses_body_leaves_include_untouched_without_reasoning() -> None:
    body = {'model': 'gpt-4.1-mini', 'input': 'hello', 'include': ['message.output_text.logprobs']}
    result = _upstream_body('/v1/responses', body, 'subject-123')
    assert result['include'] == ['message.output_text.logprobs']
    assert 'reasoning' not in result


def test_responses_body_omits_blank_description_on_builtin_computer_tool() -> None:
    body = {
        "model": "gpt-4.1-mini",
        "input": "hello",
        "tools": [
            {"type": "computer", "description": ""},
            {"type": "web_search_preview_2025_03_11", "description": None},
            {"type": "computer_use", "name": "legacy_computer_use", "description": ""},
        ],
    }
    result = _upstream_body("/v1/responses", body, "subject-123")
    tools = result["tools"]
    # Real built-in types (including version-suffixed aliases) drop blank descriptions.
    assert "description" not in tools[0]
    assert "description" not in tools[1]
    # ``computer_use`` is not a valid built-in type; treat a named blank tool as
    # client-defined and fill it rather than silently dropping the field.
    assert tools[2]["description"] == "legacy_computer_use"


def test_responses_body_fills_empty_tool_descriptions() -> None:
    body = {
        "model": "gpt-4.1-mini",
        "input": "hello",
        "tools": [
            {
                "type": "function",
                "name": "lookup",
                "description": "",
                "parameters": {"type": "object"},
            },
            {
                "type": "function",
                "function": {
                    "name": "nested",
                    "description": "   ",
                    "parameters": {"type": "object"},
                },
            },
            {
                "type": "function",
                "name": "kept",
                "description": "Useful tool",
                "parameters": {"type": "object"},
            },
            {
                "type": "function",
                "parameters": {"type": "object"},
            },
            {
                "type": "custom",
                "name": "apply_patch_freeform",
                "description": "",
            },
            {
                "type": "custom",
                "name": "null_desc",
                "description": None,
            },
            {
                "type": "web_search",
                "description": "",
            },
            {
                "type": "web_search",
            },
        ],
    }

    assert _upstream_body("/v1/responses", body, "subject-123") == {
        "model": "gpt-4.1-mini",
        "input": "hello",
        "tools": [
            {
                "type": "function",
                "name": "lookup",
                "description": "lookup",
                "parameters": {"type": "object"},
            },
            {
                "type": "function",
                "description": "nested",
                "function": {
                    "name": "nested",
                    "description": "nested",
                    "parameters": {"type": "object"},
                },
            },
            {
                "type": "function",
                "name": "kept",
                "description": "Useful tool",
                "parameters": {"type": "object"},
            },
            {
                "type": "function",
                "description": "No description provided.",
                "parameters": {"type": "object"},
            },
            {
                "type": "custom",
                "name": "apply_patch_freeform",
                "description": "apply_patch_freeform",
            },
            {
                "type": "custom",
                "name": "null_desc",
                "description": "null_desc",
            },
            {
                "type": "web_search",
            },
            {
                "type": "web_search",
            },
        ],
        "store": False,
        "user": "subject-123",
    }
    # Shallow copies must not mutate the client-provided body.
    assert body["tools"][0]["description"] == ""
    assert body["tools"][1]["function"]["description"] == "   "
    assert "description" not in body["tools"][3]
    assert body["tools"][4]["description"] == ""
    assert body["tools"][5]["description"] is None
    assert body["tools"][6]["description"] == ""


def test_responses_body_fills_empty_tool_descriptions_nested_under_input() -> None:
    body = {
        "model": "gpt-4.1-mini",
        "input": [
            {
                "type": "message",
                "role": "user",
                "content": "hi",
                "tools": [
                    {
                        "type": "function",
                        "name": "lookup",
                        "description": "",
                        "parameters": {"type": "object"},
                    },
                    {
                        "type": "custom",
                        "name": "apply_patch_freeform",
                        "description": "",
                    },
                ],
            }
        ],
    }

    assert _upstream_body("/v1/responses", body, "subject-123") == {
        "model": "gpt-4.1-mini",
        "input": [
            {
                "type": "message",
                "role": "user",
                "content": "hi",
                "tools": [
                    {
                        "type": "function",
                        "name": "lookup",
                        "description": "lookup",
                        "parameters": {"type": "object"},
                    },
                    {
                        "type": "custom",
                        "name": "apply_patch_freeform",
                        "description": "apply_patch_freeform",
                    },
                ],
            }
        ],
        "store": False,
        "user": "subject-123",
    }
    assert body["input"][0]["tools"][0]["description"] == ""
    assert body["input"][0]["tools"][1]["description"] == ""


def test_forwards_responses_with_empty_tool_descriptions_sanitized() -> None:
    upstream_requests: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        return httpx.Response(200, json={"id": "resp_test"})

    response = post(
        app_with_upstream(upstream),
        "/v1/responses",
        headers={"Authorization": "Bearer client-token"},
        json={
            "model": "gpt-4o-mini",
            "input": [
                {
                    "role": "user",
                    "content": "hi",
                    "tools": [
                        {
                            "type": "function",
                            "name": "lookup",
                            "description": "",
                            "parameters": {"type": "object"},
                        }
                    ],
                }
            ],
            "tools": [
                {
                    "type": "function",
                    "name": "top_level",
                    "description": "",
                    "parameters": {"type": "object"},
                }
            ],
        },
    )

    assert response.status_code == 200
    assert response.json() == {"id": "resp_test"}
    assert json.loads(upstream_requests[0].content) == {
        "model": "gpt-4o-mini",
        "input": [
            {
                "role": "user",
                "content": "hi",
                "tools": [
                    {
                        "type": "function",
                        "name": "lookup",
                        "description": "lookup",
                        "parameters": {"type": "object"},
                    }
                ],
            }
        ],
        "tools": [
            {
                "type": "function",
                "name": "top_level",
                "description": "top_level",
                "parameters": {"type": "object"},
            }
        ],
        "store": False,
        "user": "subject-123",
    }


def test_forwards_streaming_responses_with_a_bounded_body() -> None:
    upstream_requests: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        return httpx.Response(
            200,
            content=b"data: response.completed\n\n",
            headers={"content-type": "text/event-stream"},
        )

    response = post(
        app_with_upstream(upstream),
        "/v1/responses",
        headers={"Authorization": "Bearer client-token"},
        json={
            "model": "gpt-4o-mini",
            "input": "hello",
            "stream": True,
            "store": True,
            "metadata": {"untrusted": "value"},
        },
    )

    assert response.status_code == 200
    assert response.content == b"data: response.completed\n\n"
    assert response.headers["content-type"] == "text/event-stream"
    assert len(upstream_requests) == 1
    assert upstream_requests[0].url == "https://gateway.internal/v1/responses"
    assert json.loads(upstream_requests[0].content) == {
        "model": "gpt-4o-mini",
        "input": "hello",
        "stream": True,
        "store": False,
        "user": "subject-123",
    }


def test_accepts_nesting_up_to_the_documented_depth_limit() -> None:
    """The bound must not reject a request that carries a nested tool schema."""
    depth = forwarding._MAX_JSON_DEPTH - 2
    nested = ("[" * depth) + ("]" * depth)
    content = (
        b'{"model":"gpt-4o-mini","messages":[],"metadata":' + nested.encode() + b"}"
    )

    response = post(
        app_with_upstream(lambda _request: httpx.Response(200)),
        "/v1/chat/completions",
        headers={"Authorization": "Bearer client-token", "Content-Type": "application/json"},
        content=content,
    )

    assert response.status_code == 200


def test_depth_limit_ignores_brackets_inside_json_strings() -> None:
    """A string full of brackets is data, not nesting."""
    payload = "[" * (forwarding._MAX_JSON_DEPTH * 4)
    content = (
        b'{"model":"gpt-4o-mini","messages":[{"role":"user","content":"'
        + payload.encode()
        + b'"}]}'
    )

    response = post(
        app_with_upstream(lambda _request: httpx.Response(200)),
        "/v1/chat/completions",
        headers={"Authorization": "Bearer client-token", "Content-Type": "application/json"},
        content=content,
    )

    assert response.status_code == 200


def test_depth_limit_does_not_depend_on_the_interpreter_recursion_limit() -> None:
    """The bound is enforced by an iterative scan, not by a RecursionError."""
    depth = forwarding._MAX_JSON_DEPTH + 1
    assert forwarding._exceeds_max_json_depth(
        ("[" * depth).encode() + ("]" * depth).encode()
    )
    assert not forwarding._exceeds_max_json_depth(b'{"a": [1, 2, {"b": []}]}')
    assert not forwarding._exceeds_max_json_depth(rb'{"a": "\\[[[["}')


@pytest.mark.parametrize(
    "base_url",
    ["https://gateway.internal", "https://gateway.internal:443", "https://gateway.internal:4000"],
)
def test_accepts_a_tls_upstream_on_any_port(base_url: str) -> None:
    """A gateway on a non-default TLS port is normal, and no less protected."""
    app = create_app(
        oidc_config=config(),
        token_verifier=verified_claims,
        policies_json=POLICIES,
        upstream_base_url=base_url,
        trusted_upstream_hosts=frozenset({"gateway.internal"}),
        key_resolver=lambda _name: "test-policy-key",
        rate_limiter=lambda _key: True,
        transport=httpx.MockTransport(lambda _request: httpx.Response(200)),
    )

    response = post(
        app,
        "/v1/chat/completions",
        headers={"Authorization": "Bearer client-token"},
        json={"model": "gpt-4o-mini", "messages": []},
    )

    assert response.status_code == 200


def test_a_request_within_the_configured_bound_is_forwarded() -> None:
    upstream_requests: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        return httpx.Response(200, json={"ok": True})

    # Comfortably larger than the old megabyte bound, which is the point of raising it.
    padding = "p" * 2_000_000
    response = post(
        app_with_upstream(upstream),
        "/v1/chat/completions",
        headers={"Authorization": "Bearer client-token"},
        json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": padding}]},
    )

    assert response.status_code == 200
    assert len(upstream_requests) == 1


def test_a_request_over_the_configured_bound_is_refused_without_calling_upstream() -> None:
    calls = 0

    def upstream(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200)

    response = post(
        app_with_upstream(upstream, max_request_bytes=2048),
        "/v1/chat/completions",
        headers={"Authorization": "Bearer client-token"},
        json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "p" * 4096}]},
    )

    assert response.status_code == 400
    assert calls == 0


def test_a_response_over_the_configured_bound_is_refused() -> None:
    def upstream(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"r" * 8192)

    response = post(
        app_with_upstream(upstream, max_response_bytes=4096),
        "/v1/chat/completions",
        headers={"Authorization": "Bearer client-token"},
        json={"model": "gpt-4o-mini", "messages": []},
    )

    assert response.status_code == 502


@pytest.mark.parametrize("bound", [0, -1, 512, forwarding.MAX_CONFIGURABLE_BYTES + 1, True])
def test_create_app_refuses_an_unusable_size_bound(bound: object) -> None:
    """A library caller gets the same protection as a deployment."""
    with pytest.raises(ValueError, match="max_request_bytes"):
        create_app(
            oidc_config=config(),
            token_verifier=verified_claims,
            policies_json=POLICIES,
            upstream_base_url="https://gateway.internal",
            trusted_upstream_hosts=frozenset({"gateway.internal"}),
            key_resolver=lambda _name: "test-policy-key",
            rate_limiter=lambda _key: True,
            max_request_bytes=bound,
        )


def _get(app, path: str, headers: dict[str, str] | None = None):
    async def send():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://broker") as client:
            return await client.get(path, headers=headers or {})

    return asyncio.run(send())


def test_models_lists_only_what_the_callers_policy_allows() -> None:
    """So a client never has to carry its own copy of the model list."""
    calls = 0

    def upstream(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200)

    response = _get(
        app_with_upstream(upstream), "/v1/models", {"Authorization": "Bearer client-token"}
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["object"] == "list"
    assert [entry["id"] for entry in payload["data"]] == ["gpt-4o-mini"]
    # Answered from the policy, so the gateway is never contacted and no key is needed.
    assert calls == 0


def test_models_never_reveals_another_policys_models() -> None:
    response = _get(
        app_with_upstream(lambda _request: httpx.Response(200)),
        "/v1/models",
        {"Authorization": "Bearer client-token"},
    )

    assert "gpt-4o" not in {entry["id"] for entry in response.json()["data"]}


def test_models_requires_a_valid_token() -> None:
    app = app_with_upstream(lambda _request: httpx.Response(200))

    assert _get(app, "/v1/models").status_code == 401
    assert _get(app, "/v1/models", {"Authorization": "Bearer"}).status_code == 401
    assert _get(app, "/v1/models", {"Authorization": "Basic tok"}).status_code == 401


def test_models_denies_a_caller_who_resolves_to_no_policy() -> None:
    def unentitled(token: str) -> dict[str, object]:
        return {**verified_claims(token), "groups": ["group-unknown"]}

    response = _get(
        app_with_upstream(lambda _request: httpx.Response(200), verifier=unentitled),
        "/v1/models",
        {"Authorization": "Bearer client-token"},
    )

    assert response.status_code == 403
    assert response.json()["error"]["message"] == "request denied"


def test_models_is_audited_without_disclosing_the_caller(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="uvicorn.error"):
        _get(
            app_with_upstream(lambda _request: httpx.Response(200)),
            "/v1/models",
            {"Authorization": "Bearer client-token"},
        )

    records = [record.getMessage() for record in caplog.records if record.name == "uvicorn.error"]
    assert len(records) == 1
    event = json.loads(records[0])
    assert event["outcome"] == "models_listed"
    assert event["path"] == "/v1/models"
    assert event["policy_id"] == "researchers"
    assert "subject-123" not in records[0]
