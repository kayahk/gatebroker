# SPDX-License-Identifier: Apache-2.0
"""Fail-closed forwarding for supported OpenAI- and Anthropic-compatible paths."""

from __future__ import annotations

import json
import logging
import ssl
import time
from collections.abc import AsyncIterator, Callable, Mapping
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from starlette.concurrency import run_in_threadpool

from .oidc import TokenValidationConfig, TokenVerifier, validate_access_token
from .policy import EntitlementResolutionError, load_policies, resolve_entitlement

KeyResolver = Callable[[str], str]
RateLimitKey = tuple[str, str, str]
RateLimiter = Callable[[RateLimitKey], bool]

_SUPPORTED_PATHS = frozenset(
    {"/v1/chat/completions", "/v1/embeddings", "/v1/messages", "/v1/models", "/v1/responses"}
)
_ALLOWED_FIELDS: Mapping[str, frozenset[str]] = {
    "/v1/chat/completions": frozenset(
        {
            "messages",
            "temperature",
            "top_p",
            "n",
            "stream",
            "stop",
            "max_tokens",
            "max_completion_tokens",
            "presence_penalty",
            "frequency_penalty",
            "logit_bias",
            "response_format",
            "seed",
            "tools",
            "tool_choice",
            "parallel_tool_calls",
            "functions",
            "function_call",
            "service_tier",
            "reasoning_effort",
        }
    ),
    "/v1/embeddings": frozenset({"input", "encoding_format", "dimensions"}),
    "/v1/responses": frozenset({"include", "input", "instructions", "max_output_tokens", "parallel_tool_calls", "reasoning", "stream", "text", "tool_choice", "tools"}),
    "/v1/messages": frozenset(
        {
            "messages",
            "max_tokens",
            "system",
            "temperature",
            "top_p",
            "top_k",
            "stop_sequences",
            "tools",
            "tool_choice",
            "thinking",
            "stream",
        }
    ),
}
_STREAMING_PATHS = frozenset({"/v1/chat/completions", "/v1/messages", "/v1/responses"})
_SAFE_REQUEST_HEADERS = frozenset({"accept", "x-request-id"})
_ENDPOINT_REQUEST_HEADERS: Mapping[str, frozenset[str]] = {
    "/v1/messages": frozenset({"anthropic-version", "anthropic-beta"}),
}
_SAFE_RESPONSE_HEADERS = frozenset({"content-type", "request-id", "x-request-id"})
DEFAULT_MAX_REQUEST_BYTES = 10_485_760
DEFAULT_MAX_RESPONSE_BYTES = 10_485_760
# A request body is read into memory before it is parsed, so the memory a hostile
# caller can pin is this bound multiplied by the number of concurrent requests. The
# ceiling exists so that a mistyped setting cannot turn a refusal into an outage;
# choosing a value near it still requires thinking about concurrency.
MAX_CONFIGURABLE_BYTES = 104_857_600
# Generous for a request that carries nested tool or response schemas, and far
# below what would threaten the parser.
_MAX_JSON_DEPTH = 64
_QUOTE = 0x22
_BACKSLASH = 0x5C
_OPENING_BRACKETS = frozenset({0x7B, 0x5B})
_CLOSING_BRACKETS = frozenset({0x7D, 0x5D})
_MAX_DETAIL_SNIPPET_BYTES = 2_048
_AUDIT_LOGGER = logging.getLogger("uvicorn.error")


def _audit_event(
    *,
    outcome: str,
    path: str,
    status_code: int,
    started_at: float,
    policy_id: str | None = None,
    model: str | None = None,
    detail: str | None = None,
) -> None:
    """Emit an operational event without identity, request, or secret material."""
    event: dict[str, object] = {
        "event": "broker_request",
        "outcome": outcome,
        "path": path,
        "status_code": status_code,
        "duration_ms": int((time.perf_counter() - started_at) * 1_000),
    }
    if policy_id is not None:
        event["policy_id"] = policy_id
    if model is not None:
        event["model"] = model
    if detail is not None:
        event["detail"] = detail
    _AUDIT_LOGGER.info(json.dumps(event, separators=(",", ":"), sort_keys=True))


async def _upstream_error_detail(response: httpx.Response) -> str:
    """Classify a bounded upstream error body without logging its contents.

    Upstream error bodies are untrusted: they can echo prompts, identity data,
    or credentials. Return only a small allowlisted diagnostic classification.
    """
    body = bytearray()
    try:
        async for chunk in response.aiter_bytes():
            remaining = _MAX_DETAIL_SNIPPET_BYTES - len(body)
            if remaining <= 0:
                break
            body.extend(chunk[:remaining])
    except httpx.HTTPError:
        return "upstream_error_body_unavailable"

    text = " ".join(bytes(body).decode("utf-8", errors="replace").split())
    normalized = text.casefold()
    if text == "Access denied":
        return "envoy_access_denied"
    if "rate limit" in normalized:
        return "upstream_rate_limited"
    if "budget" in normalized:
        return "upstream_budget_denied"
    if "invalid api key" in normalized or "invalid key" in normalized:
        return "upstream_key_rejected"
    if "model" in normalized and ("not allowed" in normalized or "access denied" in normalized):
        return "upstream_model_denied"
    if "description" in normalized and ("tool" in normalized or "function" in normalized):
        return "upstream_tool_schema_rejected"
    if "json" in response.headers.get("content-type", "").casefold():
        return "upstream_json_error"
    return "upstream_plaintext_error"


def create_app(
    *,
    oidc_config: TokenValidationConfig,
    token_verifier: TokenVerifier,
    policies_json: str,
    upstream_base_url: str,
    trusted_upstream_hosts: frozenset[str],
    key_resolver: KeyResolver,
    rate_limiter: RateLimiter,
    transport: httpx.AsyncBaseTransport | None = None,
    allow_cluster_local_plaintext_upstream: bool = False,
    ssl_context: ssl.SSLContext | None = None,
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
) -> FastAPI:
    """Create a broker that authenticates, selects one policy, and forwards safely."""
    policies = load_policies(policies_json)
    max_request_bytes = _validated_byte_bound(max_request_bytes, "max_request_bytes")
    max_response_bytes = _validated_byte_bound(max_response_bytes, "max_response_bytes")
    if not isinstance(upstream_base_url, str) or not upstream_base_url:
        raise ValueError("upstream configuration is required")
    if not trusted_upstream_hosts:
        raise ValueError("upstream configuration is required")
    base_url = _validated_base_url(
        upstream_base_url,
        trusted_upstream_hosts,
        allow_cluster_local_plaintext=allow_cluster_local_plaintext_upstream,
    )
    app = FastAPI(
        redirect_slashes=False,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    upstream_client = httpx.AsyncClient(
        transport=transport,
        # No ambient environment variable may redirect this client through a proxy,
        # so a private CA has to be supplied deliberately rather than inherited.
        trust_env=False,
        follow_redirects=False,
        timeout=httpx.Timeout(300.0, connect=5.0, write=30.0, pool=5.0),
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        **({} if ssl_context is None else {"verify": ssl_context}),
    )
    app.router.on_shutdown.append(upstream_client.aclose)

    @app.get("/v1/models")
    async def list_models(request: Request) -> Response:
        """Report the models the caller's own entitlement policy allows.

        Answered from the resolved policy, without calling the upstream gateway: the
        policy *is* the answer, so this needs no server-side key and cannot be used to
        probe the gateway. It discloses nothing a caller could not already learn by
        trying a model and comparing 200 against 403, and never mentions another
        policy's models.

        It exists so a client does not have to carry its own copy of the model list. A
        local agent that hardcodes one drifts from the entitlement as soon as the policy
        changes, and pins users to a subset of what they are allowed.
        """
        path = request.url.path
        started_at = time.perf_counter()

        authorization = request.headers.getlist("authorization")
        token = _bearer_token(authorization[0]) if len(authorization) == 1 else None
        if token is None:
            _audit_event(
                outcome="authentication_failed", path=path, status_code=401, started_at=started_at
            )
            return _error(401, "authentication failed")

        try:
            identity = await run_in_threadpool(
                validate_access_token,
                token,
                oidc_config,
                token_verifier,
                now=time.time(),
            )
        except Exception as error:
            _audit_event(
                outcome="authentication_failed",
                path=path,
                status_code=401,
                started_at=started_at,
                detail=type(error).__name__,
            )
            return _error(401, "authentication failed")

        try:
            policy = resolve_entitlement(
                policies=policies,
                token_group_ids=set(identity.group_ids),
                token_app_roles=set(identity.app_roles),
            )
        except EntitlementResolutionError:
            _audit_event(
                outcome="authorization_denied", path=path, status_code=403, started_at=started_at
            )
            return _error(403, "request denied")

        _audit_event(
            outcome="models_listed",
            path=path,
            status_code=200,
            started_at=started_at,
            policy_id=policy.id,
        )
        return JSONResponse(
            {
                "object": "list",
                "data": [
                    {"id": model, "object": "model", "owned_by": "gateway"}
                    for model in sorted(policy.allowed_models)
                ],
            }
        )

    @app.post("/v1/chat/completions")
    @app.post("/v1/embeddings")
    @app.post("/v1/messages")
    @app.post("/v1/responses")
    async def forward(request: Request) -> Response:
        path = request.url.path
        started_at = time.perf_counter()

        def audited_error(
            status_code: int,
            message: str,
            outcome: str,
            *,
            policy_id: str | None = None,
            model: str | None = None,
            detail: str | None = None,
        ) -> JSONResponse:
            _audit_event(
                outcome=outcome,
                path=path,
                status_code=status_code,
                started_at=started_at,
                policy_id=policy_id,
                model=model,
                detail=detail,
            )
            return _error(status_code, message)

        authorization = request.headers.getlist("authorization")
        token = _bearer_token(authorization[0]) if len(authorization) == 1 else None
        if token is None:
            return audited_error(401, "authentication failed", "authentication_failed")

        try:
            identity = await run_in_threadpool(
                validate_access_token,
                token,
                oidc_config,
                token_verifier,
                now=time.time(),
            )
        except Exception as error:
            # Exception class names only: messages could carry claim values.
            return audited_error(
                401,
                "authentication failed",
                "authentication_failed",
                detail=type(error).__name__,
            )

        body = await _request_object(request, max_request_bytes)
        if (
            body is None
            or not _valid_model(body)
            or not _stream_is_supported(path, body)
            or not _valid_endpoint_body(path, body)
            or not _valid_endpoint_headers(path, request)
            or not _valid_query(path, request)
        ):
            return audited_error(400, "invalid request", "invalid_request")
        model = body["model"]

        try:
            policy = resolve_entitlement(
                policies=policies,
                token_group_ids=set(identity.group_ids),
                token_app_roles=set(identity.app_roles),
            )
        except EntitlementResolutionError:
            return audited_error(403, "request denied", "authorization_denied")
        if body["model"] not in policy.allowed_models:
            return audited_error(403, "request denied", "authorization_denied", policy_id=policy.id)

        try:
            client_ip = request.client.host if request.client is not None else ""
            rate_limit_result = rate_limiter((identity.subject, policy.id, client_ip))
        except Exception as error:
            return audited_error(503, "service unavailable", "service_unavailable", policy_id=policy.id, model=model, detail=type(error).__name__)
        if rate_limit_result is False:
            return audited_error(429, "request denied", "rate_limit_denied", policy_id=policy.id, model=model)
        if rate_limit_result is not True:
            return audited_error(503, "service unavailable", "service_unavailable", policy_id=policy.id, model=model, detail="rate limiter returned a non-boolean result")

        try:
            key = key_resolver(policy.key_ref)
        except Exception as error:
            return audited_error(503, "service unavailable", "service_unavailable", policy_id=policy.id, model=model, detail=type(error).__name__)
        if not isinstance(key, str) or not key:
            return audited_error(503, "service unavailable", "service_unavailable", policy_id=policy.id, model=model, detail="resolved key is empty or not a string")

        upstream_body = _upstream_body(path, body, identity.subject)
        headers = _safe_upstream_headers(path, request)
        headers["authorization"] = f"Bearer {key}"
        headers["x-gabro-policy-id"] = policy.id
        upstream: httpx.Response | None = None
        try:
            upstream = await upstream_client.send(
                upstream_client.build_request(
                    "POST",
                    _upstream_url(base_url, path, request),
                    json=upstream_body,
                    headers=headers,
                ),
                stream=True,
            )
            if not 200 <= upstream.status_code < 300:
                try:
                    detail = await _upstream_error_detail(upstream)
                finally:
                    await upstream.aclose()
                return audited_error(upstream.status_code, "upstream request failed", "upstream_failed", policy_id=policy.id, model=model, detail=detail)
            if body.get("stream") is True:
                return StreamingResponse(
                    _relay_stream(
                        upstream, path, started_at, policy.id, model, max_response_bytes
                    ),
                    status_code=upstream.status_code,
                    headers=_safe_response_headers(upstream),
                )
            try:
                content = await _bounded_response_content(upstream, max_response_bytes)
            finally:
                await upstream.aclose()
            if content is None:
                return audited_error(502, "upstream response failed", "upstream_failed", policy_id=policy.id, model=model, detail="upstream response exceeded the size limit")
            _audit_event(
                outcome="forwarded",
                path=path,
                status_code=upstream.status_code,
                started_at=started_at,
                policy_id=policy.id,
                model=model,
            )
            return Response(
                content=content,
                status_code=upstream.status_code,
                headers=_safe_response_headers(upstream),
            )
        except httpx.HTTPError as error:
            if upstream is not None:
                await upstream.aclose()
            return audited_error(502, "upstream request failed", "upstream_failed", policy_id=policy.id, model=model, detail=type(error).__name__)

    return app


async def _relay_stream(
    upstream: httpx.Response,
    path: str,
    started_at: float,
    policy_id: str,
    model: str,
    max_response_bytes: int,
) -> AsyncIterator[bytes]:
    received = 0
    try:
        async for chunk in upstream.aiter_bytes():
            received += len(chunk)
            if received > max_response_bytes:
                _audit_event(outcome="upstream_failed", path=path, status_code=502, started_at=started_at, policy_id=policy_id, model=model, detail="upstream response exceeded the size limit")
                return
            yield chunk
        _audit_event(outcome="forwarded", path=path, status_code=upstream.status_code, started_at=started_at, policy_id=policy_id, model=model)
    except httpx.HTTPError as error:
        _audit_event(outcome="upstream_failed", path=path, status_code=502, started_at=started_at, policy_id=policy_id, model=model, detail=type(error).__name__)
    finally:
        await upstream.aclose()


def _stream_is_supported(path: str, body: Mapping[str, Any]) -> bool:
    if "stream" not in body:
        return True
    stream = body.get("stream")
    return isinstance(stream, bool) and (not stream or path in _STREAMING_PATHS)


def _valid_query(path: str, request: Request) -> bool:
    query = request.url.query
    return not query or (path == "/v1/messages" and query == "beta=true")


def _upstream_url(base_url: httpx.URL, path: str, request: Request) -> str:
    url = base_url.join(path.lstrip("/"))
    if request.query_params:
        url = url.copy_with(query=request.url.query.encode("ascii"))
    return str(url)


def _validated_base_url(
    value: str,
    trusted_hosts: frozenset[str],
    *,
    allow_cluster_local_plaintext: bool = False,
) -> httpx.URL:
    url = httpx.URL(value)
    if (
        not url.host
        or url.host not in trusted_hosts
        or url.query
        or url.fragment
        or url.userinfo
    ):
        raise ValueError("invalid upstream base URL")
    if url.scheme == "https":
        # Any port is allowed over TLS. Gateways commonly listen on something other
        # than 443, and the port carries no security meaning once the scheme, the
        # exact host allowlist, and certificate validation have been applied.
        pass
    elif url.scheme == "http":
        # Plaintext is permitted only as an explicit deployment decision and
        # only toward in-cluster Service DNS names, never external hosts. The
        # wire-security posture is equivalent to the platform Gateway's own
        # plaintext backend leg; do not point this at anything routable
        # outside the cluster.
        if not allow_cluster_local_plaintext or not _cluster_local_host(url.host):
            raise ValueError("invalid upstream base URL")
    else:
        raise ValueError("invalid upstream base URL")
    return url.copy_with(path=url.path.rstrip("/") + "/")


def _cluster_local_host(host: str) -> bool:
    return host.endswith(".svc.cluster.local") or host.endswith(".svc")


def _bearer_token(value: str | None) -> str | None:
    if not isinstance(value, str):
        return None
    scheme, separator, token = value.partition(" ")
    if (
        scheme.lower() != "bearer"
        or not separator
        or not token
        or token.strip() != token
        or any(character.isspace() for character in token)
    ):
        return None
    return token


async def _request_object(request: Request, max_request_bytes: int) -> dict[str, Any] | None:
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > max_request_bytes:
                return None
        except ValueError:
            return None
    try:
        chunks: list[bytes] = []
        received = 0
        async for chunk in request.stream():
            received += len(chunk)
            if received > max_request_bytes:
                return None
            chunks.append(chunk)
        raw_body = b"".join(chunks)
        if _exceeds_max_json_depth(raw_body):
            return None
        body = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, MemoryError):
        return None
    return body if isinstance(body, dict) else None


def _validated_byte_bound(value: int, name: str) -> int:
    """Reject a bound that is not a usable size.

    The caps are a memory defence, so an unbounded or nonsensical value would convert
    a refusal into an outage. Rejecting at construction keeps that from being a runtime
    surprise on the first large request.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be a positive integer")
    if value < 1024:
        raise ValueError(f"{name} must be at least 1024 bytes")
    if value > MAX_CONFIGURABLE_BYTES:
        raise ValueError(f"{name} must not exceed {MAX_CONFIGURABLE_BYTES} bytes")
    return value


def _exceeds_max_json_depth(raw_body: bytes) -> bool:
    """Report whether container nesting exceeds the accepted depth.

    How deeply ``json`` will recurse before failing is an interpreter detail that
    differs between Python versions, so the bound is enforced here rather than
    inferred from a ``RecursionError``. Scanning bytes keeps the check iterative,
    so a hostile body cannot exhaust the stack while being measured.
    """
    depth = 0
    in_string = False
    escaped = False
    for byte in raw_body:
        if in_string:
            if escaped:
                escaped = False
            elif byte == _BACKSLASH:
                escaped = True
            elif byte == _QUOTE:
                in_string = False
        elif byte == _QUOTE:
            in_string = True
        elif byte in _OPENING_BRACKETS:
            depth += 1
            if depth > _MAX_JSON_DEPTH:
                return True
        elif byte in _CLOSING_BRACKETS:
            depth -= 1
    return False


def _valid_endpoint_body(path: str, body: Mapping[str, Any]) -> bool:
    if path != "/v1/messages":
        return True
    max_tokens = body.get("max_tokens")
    messages = body.get("messages")
    return (
        isinstance(max_tokens, int)
        and not isinstance(max_tokens, bool)
        and max_tokens > 0
        and isinstance(messages, list)
        and bool(messages)
        and all(
            isinstance(message, Mapping)
            and "role" in message
            and "content" in message
            for message in messages
        )
    )


def _valid_endpoint_headers(path: str, request: Request) -> bool:
    if path != "/v1/messages":
        return True
    versions = request.headers.getlist("anthropic-version")
    beta_values = request.headers.getlist("anthropic-beta")
    return (
        len(versions) == 1
        and bool(versions[0].strip())
        and versions[0] == versions[0].strip()
        and len(beta_values) <= 1
        and all(value.strip() and value == value.strip() for value in beta_values)
    )


def _valid_model(body: Mapping[str, Any]) -> bool:
    model = body.get("model")
    return isinstance(model, str) and bool(model.strip())


def _upstream_body(path: str, body: Mapping[str, Any], oid: str) -> dict[str, Any]:
    allowed = _ALLOWED_FIELDS[path]
    result = {field: body[field] for field in allowed if field in body}
    result["model"] = body["model"]
    if path == "/v1/responses":
        result["store"] = False
        result = _sanitize_responses_empty_tool_descriptions(result)
        result = _ensure_encrypted_reasoning_include(result)
    if path == "/v1/messages":
        result["metadata"] = {"user_id": oid}
    else:
        result["user"] = oid
    return result


_EMPTY_TOOL_DESCRIPTION_FALLBACK = "No description provided."
_ENCRYPTED_REASONING_INCLUDE = "reasoning.encrypted_content"
# Built-in Responses tools that must not receive invented ``description`` values.
# Client-defined tools (``function``, ``custom``, named freeform tools, etc.) need a
# non-empty description for Azure OpenAI; these built-ins either omit ``description``
# from their schema or treat it as optional, so blank values are dropped instead of
# invented. Kept in sync with the Responses API tool union (built-in/hosted tools).
_BUILTIN_RESPONSES_TOOL_TYPES = frozenset(
    {
        "web_search",
        "web_search_2025_08_26",
        "web_search_preview",
        "web_search_preview_2025_03_11",
        "file_search",
        "code_interpreter",
        "computer",
        "computer_use_preview",
        "image_generation",
        "mcp",
        "apply_patch",
        "shell",
        "local_shell",
        "tool_search",
        "programmatic_tool_calling",
    }
)


def _ensure_encrypted_reasoning_include(body: Mapping[str, Any]) -> dict[str, Any]:
    """Guarantee encrypted reasoning is returned for stateless /v1/responses calls.

    The broker forces ``store: false`` (it never persists prompts upstream). Per the
    Responses API, reasoning items can only be replayed across turns when the request
    asks for ``include: ["reasoning.encrypted_content"]``. Codex sends this already;
    we add it whenever the request uses ``reasoning`` so multi-turn tool calling keeps
    working even if the client omitted it. Non-reasoning requests are left untouched.
    """
    result = dict(body)
    if "reasoning" not in result:
        return result
    include = result.get("include")
    if isinstance(include, list):
        if _ENCRYPTED_REASONING_INCLUDE not in include:
            result["include"] = [*include, _ENCRYPTED_REASONING_INCLUDE]
    elif include is None:
        result["include"] = [_ENCRYPTED_REASONING_INCLUDE]
    # A non-list, non-null ``include`` is malformed; leave it for upstream to reject.
    return result


def _sanitize_responses_empty_tool_descriptions(body: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize tool descriptions that Azure OpenAI rejects on /v1/responses.

    Codex (and similar clients) sometimes send blank or null ``description`` values
    on client-defined tools (``function``, ``custom``, freeform/named tools). Azure
    requires a non-empty description for those, so blank/missing/null values are
    filled with a fallback derived from the tool name when available.

    Built-in tools (for example ``web_search``) do not define ``description`` in
    their schema, so blank descriptions are omitted instead of inventing text.
    """
    result = dict(body)
    if "tools" in result:
        result["tools"] = _sanitize_tool_list(result["tools"])
    input_value = result.get("input")
    if isinstance(input_value, list):
        result["input"] = [
            _sanitize_input_item_tools(item) if isinstance(item, Mapping) else item
            for item in input_value
        ]
    return result


def _sanitize_input_item_tools(item: Mapping[str, Any]) -> dict[str, Any]:
    if "tools" not in item:
        return dict(item)
    sanitized = dict(item)
    sanitized["tools"] = _sanitize_tool_list(sanitized["tools"])
    return sanitized


def _sanitize_tool_list(tools: Any) -> Any:
    if not isinstance(tools, list):
        return tools
    return [_sanitize_tool(tool) if isinstance(tool, Mapping) else tool for tool in tools]


def _tool_description_fallback(tool: Mapping[str, Any]) -> str:
    name = tool.get("name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    function = tool.get("function")
    if isinstance(function, Mapping):
        function_name = function.get("name")
        if isinstance(function_name, str) and function_name.strip():
            return function_name.strip()
    return _EMPTY_TOOL_DESCRIPTION_FALLBACK


def _is_builtin_responses_tool(tool: Mapping[str, Any]) -> bool:
    tool_type = tool.get("type")
    return isinstance(tool_type, str) and tool_type in _BUILTIN_RESPONSES_TOOL_TYPES


def _is_client_defined_tool(tool: Mapping[str, Any]) -> bool:
    """True for tools Azure treats as requiring a non-empty description."""
    tool_type = tool.get("type")
    if tool_type in {"function", "custom"}:
        return True
    if isinstance(tool.get("function"), Mapping):
        return True
    if "name" in tool and "parameters" in tool:
        return True
    # Named freeform/custom-shaped tools without an explicit type still need a
    # description when the client includes the field or Azure will reject blanks.
    name = tool.get("name")
    return isinstance(name, str) and bool(name.strip()) and not _is_builtin_responses_tool(tool)


def _description_missing_or_blank(tool: Mapping[str, Any]) -> bool:
    if "description" not in tool:
        return True
    description = tool.get("description")
    if description is None:
        return True
    return isinstance(description, str) and not description.strip()


def _tool_description_action(tool: Mapping[str, Any]) -> str:
    """Decide how to normalize a tool's ``description`` for Azure /v1/responses.

    Returns one of:

    * ``"fill"`` -- a client-defined tool (or any tool that explicitly sent a
      blank/null ``description``) needs a non-empty value; Azure rejects both
      empty strings and omission for tools that require the parameter.
    * ``"omit"`` -- a built-in tool carries a blank/null ``description`` it does
      not define in its schema, so the field is dropped rather than invented.
    * ``"leave"`` -- the description is already valid, or absent on a tool that
      does not require one.
    """
    if not _description_missing_or_blank(tool):
        return "leave"
    if _is_builtin_responses_tool(tool):
        # Built-ins never receive invented text; drop only an explicit blank/null.
        return "omit" if "description" in tool else "leave"
    if _is_client_defined_tool(tool) or "description" in tool:
        return "fill"
    return "leave"


def _apply_tool_description_action(tool: Mapping[str, Any]) -> dict[str, Any]:
    normalized = dict(tool)
    action = _tool_description_action(normalized)
    if action == "fill":
        normalized["description"] = _tool_description_fallback(normalized)
    elif action == "omit":
        del normalized["description"]
    return normalized


def _sanitize_tool(tool: Mapping[str, Any]) -> dict[str, Any]:
    sanitized = _apply_tool_description_action(tool)
    function = sanitized.get("function")
    if isinstance(function, Mapping):
        sanitized["function"] = _apply_tool_description_action(function)
    return sanitized


async def _bounded_response_content(response: httpx.Response, max_response_bytes: int) -> bytes | None:
    chunks: list[bytes] = []
    received = 0
    async for chunk in response.aiter_bytes():
        received += len(chunk)
        if received > max_response_bytes:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def _safe_upstream_headers(path: str, request: Request) -> dict[str, str]:
    return {
        name: value
        for name in _SAFE_REQUEST_HEADERS | _ENDPOINT_REQUEST_HEADERS.get(path, frozenset())
        if (value := request.headers.get(name)) is not None
    }


def _safe_response_headers(response: httpx.Response) -> dict[str, str]:
    return {
        name: value
        for name in _SAFE_RESPONSE_HEADERS
        if (value := response.headers.get(name)) is not None
    }


def _error(status_code: int, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"message": message, "type": "broker_error"}},
    )
