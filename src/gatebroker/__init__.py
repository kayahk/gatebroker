# SPDX-License-Identifier: Apache-2.0
"""GateBroker: a fail-closed authorization broker for OpenAI-compatible gateways.

``gatebroker.forwarding.create_app`` is the library boundary. It takes an injected
token verifier, entitlement policies, a key resolver, and a rate limiter, and
returns an ASGI application that forwards only allowed requests upstream.
``gatebroker.runtime`` wires that boundary into a self-contained service.
"""

__all__ = ["__version__"]

__version__ = "0.1.0"
