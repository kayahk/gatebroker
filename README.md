# gatebroker
Fail-closed, identity-aware authorization broker for OpenAI- and Anthropic-compatible LLM gateways. Exchanges an OIDC identity for a scoped, short-lived credential and enforces per-group model entitlements, so clients never hold a provider key.
