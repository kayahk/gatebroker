# SPDX-License-Identifier: Apache-2.0
"""A fail-closed authorization broker for model gateways.

GateBroker fronts a gateway that exposes OpenAI-compatible paths (Chat
Completions, Embeddings, Responses), Anthropic-compatible Messages, or both. It
exchanges a caller's verified identity for scoped access to that gateway and
allows only the models the caller's entitlement policy lists.

``gatebroker.forwarding.create_app`` is the library boundary. It takes an injected
token verifier, entitlement policies, a key resolver, and a rate limiter, and
returns an ASGI application that forwards only allowed requests upstream.
``gatebroker.runtime`` wires that boundary into a self-contained service.
"""

__all__ = ["__version__"]

__version__ = "0.1.0"
