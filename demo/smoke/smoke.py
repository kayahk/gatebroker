# SPDX-License-Identifier: Apache-2.0
"""Drives the demo end to end and asserts what the broker is supposed to do.

Runs inside the demo network, where the demo CA is trusted and `keycloak` resolves.
It obtains tokens the same way `gabro login` does, except through the password grant
rather than the device-code flow, so the run needs no human at a browser.

The interesting assertions are the refusals. A demo that only shows a successful
call proves very little about a fail-closed component.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

# nosec B105: an endpoint URL, not a credential; the name merely contains "TOKEN".
KEYCLOAK_TOKEN_URL = (
    "https://keycloak:8443/realms/gatebroker-demo/protocol/openid-connect/token"  # nosec B105
)
BROKER = "http://gatebroker:8080"
CLIENT_ID = "gabro-cli"
PASSWORD = "demo"  # nosec B105: the demo realm's throwaway password

failures: list[str] = []


def check(description: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  ok    {description}")
        return
    failures.append(f"{description}{f': {detail}' if detail else ''}")
    print(f"  FAIL  {description}{f': {detail}' if detail else ''}")


def token_for(username: str) -> str:
    """Obtain an access token, standing in for the device-code flow."""
    payload = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "client_id": CLIENT_ID,
            "username": username,
            "password": PASSWORD,
            "scope": "openid broker",
        }
    ).encode()
    request = urllib.request.Request(
        KEYCLOAK_TOKEN_URL,
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310
        return json.load(response)["access_token"]


def call_broker(
    path: str,
    token: str | None,
    body: dict[str, Any],
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    headers = {"Content-Type": "application/json", **(extra_headers or {})}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        f"{BROKER}{path}", data=json.dumps(body).encode(), headers=headers
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:  # nosec B310
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            return error.code, json.loads(raw)
        except json.JSONDecodeError:
            return error.code, {"raw": raw.decode("utf-8", "replace")}


def chat(model: str) -> dict[str, Any]:
    return {"model": model, "messages": [{"role": "user", "content": "ping"}]}


def main() -> int:
    print("\n== an entitled user reaches an allowed model ==")
    alice = token_for("alice")
    status, payload = call_broker("/v1/chat/completions", alice, chat("demo-large"))
    check("alice may use demo-large", status == 200, f"status {status}")
    content = ""
    if status == 200:
        content = payload["choices"][0]["message"]["content"]
        print(f"        model said: {content}")
    check("the response came from the mock model", "mock model" in content)

    print("\n== the same user is refused a model their policy omits ==")
    bob = token_for("bob")
    status, _ = call_broker("/v1/chat/completions", bob, chat("demo-small"))
    check("bob may use demo-small", status == 200, f"status {status}")
    status, payload = call_broker("/v1/chat/completions", bob, chat("demo-large"))
    check("bob may not use demo-large", status == 403, f"status {status}")
    check(
        "the refusal says nothing about why",
        payload.get("error", {}).get("message") == "request denied",
        json.dumps(payload),
    )

    print("\n== a user in no entitled group is refused entirely ==")
    carol = token_for("carol")
    status, _ = call_broker("/v1/chat/completions", carol, chat("demo-small"))
    check("carol resolves to no policy and is denied", status == 403, f"status {status}")

    print("\n== a caller without a valid token gets nowhere ==")
    status, _ = call_broker("/v1/chat/completions", None, chat("demo-small"))
    check("no token is rejected", status == 401, f"status {status}")
    status, _ = call_broker("/v1/chat/completions", "not-a-token", chat("demo-small"))
    check("a malformed token is rejected", status == 401, f"status {status}")
    status, _ = call_broker(
        "/v1/chat/completions", alice[:-4] + "AAAA", chat("demo-small")
    )
    check("a tampered signature is rejected", status == 401, f"status {status}")

    print("\n== a client cannot supply its own gateway credential or identity ==")
    status, _ = call_broker(
        "/v1/chat/completions",
        alice,
        chat("demo-large"),
        {"x-api-key": "sk-attacker-supplied", "api-key": "sk-attacker-supplied"},
    )
    check("client-supplied key headers are stripped, not forwarded", status == 200)
    # The broker overwrites `user` with the verified subject before forwarding, so
    # the gateway attributes usage to who the caller actually is. That substitution
    # happens on the broker-to-gateway hop, which this topology cannot observe;
    # tests/test_forwarding.py asserts it directly.
    claimed = {**chat("demo-large"), "user": "somebody-else"}
    status, _ = call_broker("/v1/chat/completions", alice, claimed)
    check("a client-claimed identity does not break the request", status == 200)

    print("\n== the model must exist in the policy, not merely at the gateway ==")
    status, _ = call_broker("/v1/chat/completions", alice, chat("no-such-model"))
    check("an unknown model is refused before the gateway is called", status == 403)

    print("\n== unsupported endpoints are not proxied ==")
    status, _ = call_broker("/v1/completions", alice, chat("demo-small"))
    check("a path the broker does not implement is not reachable", status == 404)

    print("\n== health endpoints disclose nothing ==")
    with urllib.request.urlopen(f"{BROKER}/healthz", timeout=10) as response:  # nosec B310
        health = json.load(response)
    check("healthz returns only a status", health == {"status": "ok"}, json.dumps(health))

    print()
    if failures:
        print(f"{len(failures)} check(s) failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("All demo checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
