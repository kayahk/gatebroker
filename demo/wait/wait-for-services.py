# SPDX-License-Identifier: Apache-2.0
"""Blocks until the identity provider and gateway are actually usable.

Keycloak's own health endpoint sits on a port that inherits TLS, and its image
carries no HTTP client, so probing it from inside that container is awkward. Waiting
here instead is both simpler and a better signal: it checks the realm's OIDC
discovery document and the gateway's liveness, which are the two things the broker
needs, rather than a generic "process is up".
"""

from __future__ import annotations

import sys
import time
import urllib.error
import urllib.request

TIMEOUT_SECONDS = 240
TARGETS = (
    (
        "identity provider",
        "https://keycloak:8443/realms/gatebroker-demo/.well-known/openid-configuration",
    ),
    ("gateway", "https://litellm:4000/health/liveliness"),
)


def reachable(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=5) as response:  # nosec B310
            return 200 <= response.status < 300
    except (urllib.error.URLError, OSError, ValueError):
        return False


def main() -> int:
    deadline = time.monotonic() + TIMEOUT_SECONDS
    for name, url in TARGETS:
        print(f"waiting for {name} ...", flush=True)
        while not reachable(url):
            if time.monotonic() > deadline:
                print(f"timed out waiting for {name} at {url}", file=sys.stderr)
                return 1
            time.sleep(2)
        print(f"  {name} is ready", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
