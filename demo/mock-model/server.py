# SPDX-License-Identifier: Apache-2.0
"""A stand-in model provider, so the demo needs no provider account or API key.

It answers the handful of upstream shapes LiteLLM uses when it proxies to an
OpenAI-compatible provider, echoing back enough of the request that a walkthrough
can show which model was reached and which identity was attributed to the call.

This is a demo fixture. It has no authentication of its own and must never be
exposed outside the demo network.
"""

from __future__ import annotations

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

PORT = 8081
# Matches the broker's default request bound, so the demo can actually carry the
# payload sizes the broker accepts. A provider limit below the broker's turns a
# working request into an upstream 413, which reads like a broker fault.
_MAX_BODY_BYTES = 10_485_760


def _completion(model: str, prompt: str) -> dict[str, Any]:
    return {
        "id": "chatcmpl-demo",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": f"Hello from the mock model {model}. You said: {prompt}",
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 9, "completion_tokens": 12, "total_tokens": 21},
    }


def _first_prompt(body: dict[str, Any]) -> str:
    messages = body.get("messages")
    if isinstance(messages, list):
        for message in messages:
            if isinstance(message, dict) and isinstance(message.get("content"), str):
                return message["content"]
    return ""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == "/health":
            self._respond(200, {"status": "ok"})
            return
        if self.path.rstrip("/") == "/v1/models":
            self._respond(
                200,
                {
                    "object": "list",
                    "data": [
                        {"id": "demo-small", "object": "model"},
                        {"id": "demo-large", "object": "model"},
                    ],
                },
            )
            return
        self._respond(404, {"error": {"message": "not found"}})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._respond(400, {"error": {"message": "invalid content length"}})
            return
        if length > _MAX_BODY_BYTES:
            self._respond(413, {"error": {"message": "request too large"}})
            return
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._respond(400, {"error": {"message": "invalid json"}})
            return
        if not isinstance(body, dict):
            self._respond(400, {"error": {"message": "invalid json"}})
            return

        path = self.path.split("?", 1)[0].rstrip("/")
        model = body.get("model") if isinstance(body.get("model"), str) else "unknown"

        if path in {"/v1/chat/completions", "/chat/completions"}:
            self._respond(200, _completion(model, _first_prompt(body)))
            return
        if path in {"/v1/embeddings", "/embeddings"}:
            self._respond(
                200,
                {
                    "object": "list",
                    "model": model,
                    "data": [{"object": "embedding", "index": 0, "embedding": [0.1] * 8}],
                    "usage": {"prompt_tokens": 4, "total_tokens": 4},
                },
            )
            return
        self._respond(404, {"error": {"message": "unsupported path"}})

    def _respond(self, status: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        print(f"mock-model {self.address_string()} {format % args}", flush=True)


if __name__ == "__main__":
    # Binds to every interface because it only ever runs inside the demo network.
    ThreadingHTTPServer(("", PORT), Handler).serve_forever()  # nosec B104
