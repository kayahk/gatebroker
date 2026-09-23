# SPDX-License-Identifier: Apache-2.0
"""OpenTelemetry setup for the broker's request and upstream spans."""

from __future__ import annotations

import os

import httpx
from fastapi import FastAPI
from opentelemetry import propagate, trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

_SENSITIVE_ATTRIBUTE_KEYS = frozenset(
    {
        "client.address",
        "client.port",
        "http.client_ip",
        "http.user_agent",
        "net.peer.ip",
        "net.peer.port",
        "network.peer.address",
        "network.peer.port",
        "user_agent.original",
    }
)


class SensitiveSpanAttributeRedactingExporter(SpanExporter):
    """Remove client identity and request metadata before delegating export."""

    def __init__(self, exporter: SpanExporter) -> None:
        self._exporter = exporter

    def export(self, spans: list[ReadableSpan]) -> object:
        return self._exporter.export([_redacted_span(span) for span in spans])

    def shutdown(self) -> None:
        self._exporter.shutdown()

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        return self._exporter.force_flush(timeout_millis)


def _redacted_span(span: ReadableSpan) -> ReadableSpan:
    """Copy a completed span, omitting attributes prohibited by broker policy."""
    return ReadableSpan(
        name=span.name,
        context=span.context,
        parent=span.parent,
        resource=span.resource,
        attributes={
            key: value
            for key, value in span.attributes.items()
            if key not in _SENSITIVE_ATTRIBUTE_KEYS
        },
        events=span.events,
        links=span.links,
        kind=span.kind,
        status=span.status,
        start_time=span.start_time,
        end_time=span.end_time,
        instrumentation_scope=span.instrumentation_scope,
    )


def traces_enabled(environment: dict[str, str] | None = None) -> bool:
    """Return whether this process was configured with an OTLP endpoint."""
    values = os.environ if environment is None else environment
    return bool(values.get("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip())


def configure_trace_context_propagation() -> None:
    """Allow only W3C trace context across the broker trust boundary."""
    propagate.set_global_textmap(TraceContextTextMapPropagator())


def configure_telemetry(app: FastAPI, upstream_client: httpx.AsyncClient) -> None:
    """Instrument HTTP server/client spans when the deployment enables OTLP.

    The broker accepts and injects only W3C ``traceparent``/``tracestate``. It
    deliberately excludes W3C baggage so untrusted caller attributes cannot be
    forwarded to the upstream gateway. No bodies, credentials, headers, or
    identity claims are added as span attributes; a processor removes client
    metadata captured by framework instrumentation before export.
    """
    if not traces_enabled():
        return

    configure_trace_context_propagation()
    if not isinstance(trace.get_tracer_provider(), TracerProvider):
        provider = TracerProvider(resource=Resource.create())
        provider.add_span_processor(
            BatchSpanProcessor(SensitiveSpanAttributeRedactingExporter(OTLPSpanExporter()))
        )
        trace.set_tracer_provider(provider)

    # Probe endpoints are intentionally excluded from operational traces.
    if not getattr(app, "_is_instrumented_by_opentelemetry", False):
        FastAPIInstrumentor.instrument_app(app, excluded_urls="healthz,readyz")
    # Scope instrumentation to the upstream gateway client. This injects W3C
    # trace context without wrapping unrelated HTTP clients in the process.
    HTTPXClientInstrumentor.instrument_client(upstream_client)
