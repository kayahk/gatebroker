# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import asyncio

import httpx
from fastapi import FastAPI
from opentelemetry import baggage, context, propagate
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind

from gatebroker.telemetry import (
    SensitiveSpanAttributeRedactingExporter,
    configure_trace_context_propagation,
    traces_enabled,
)


def test_traces_are_disabled_without_an_otlp_endpoint() -> None:
    assert traces_enabled({}) is False
    assert traces_enabled({"OTEL_EXPORTER_OTLP_ENDPOINT": "   "}) is False


def test_traces_are_enabled_with_an_otlp_endpoint() -> None:
    assert traces_enabled({"OTEL_EXPORTER_OTLP_ENDPOINT": "http://otel-collector:4317"}) is True


def test_redactor_removes_client_metadata_before_export() -> None:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(
        SimpleSpanProcessor(SensitiveSpanAttributeRedactingExporter(exporter))
    )

    with provider.get_tracer("test").start_as_current_span("broker.request") as span:
        span.set_attribute("client.address", "198.51.100.23")
        span.set_attribute("net.peer.ip", "198.51.100.23")
        span.set_attribute("user_agent.original", "private-client")
        span.set_attribute("http.user_agent", "private-client")
        span.set_attribute("http.request.method", "POST")

    attributes = exporter.get_finished_spans()[0].attributes
    assert "client.address" not in attributes
    assert "net.peer.ip" not in attributes
    assert "user_agent.original" not in attributes
    assert "http.user_agent" not in attributes
    assert attributes["http.request.method"] == "POST"


def test_fastapi_server_span_excludes_client_address_and_user_agent() -> None:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(
        SimpleSpanProcessor(SensitiveSpanAttributeRedactingExporter(exporter))
    )
    app = FastAPI()

    @app.get("/v1/models")
    async def models() -> dict[str, bool]:
        return {"ok": True}

    FastAPIInstrumentor.instrument_app(app, tracer_provider=provider)

    async def request() -> None:
        transport = httpx.ASGITransport(app=app, client=("198.51.100.23", 4242))
        async with httpx.AsyncClient(transport=transport, base_url="http://broker") as client:
            response = await client.get("/v1/models", headers={"User-Agent": "private-client"})
        assert response.status_code == 200

    asyncio.run(request())
    server_span = next(span for span in exporter.get_finished_spans() if span.kind is SpanKind.SERVER)
    assert not set(server_span.attributes).intersection(
        {"client.address", "net.peer.ip", "user_agent.original", "http.user_agent"}
    )


def test_httpx_instrumentation_propagates_trace_context_but_not_baggage() -> None:
    provider = TracerProvider()
    seen: dict[str, str | None] = {}
    original_propagator = propagate.get_global_textmap()
    configure_trace_context_propagation()

    async def send_request() -> None:
        async def upstream(request: httpx.Request) -> httpx.Response:
            seen["traceparent"] = request.headers.get("traceparent")
            seen["baggage"] = request.headers.get("baggage")
            return httpx.Response(200)

        async with httpx.AsyncClient(transport=httpx.MockTransport(upstream)) as client:
            HTTPXClientInstrumentor.instrument_client(client, tracer_provider=provider)
            baggage_token = context.attach(baggage.set_baggage("untrusted", "caller-data"))
            try:
                with provider.get_tracer("test").start_as_current_span("broker.request") as span:
                    await client.get("http://gateway.test/v1/chat/completions")
                    expected_trace_id = f"{span.get_span_context().trace_id:032x}"
            finally:
                context.detach(baggage_token)
                HTTPXClientInstrumentor.uninstrument_client(client)
        assert seen["traceparent"] is not None
        assert seen["traceparent"].split("-")[1] == expected_trace_id
        assert seen["baggage"] is None

    try:
        asyncio.run(send_request())
    finally:
        propagate.set_global_textmap(original_propagator)
