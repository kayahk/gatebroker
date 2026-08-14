# GateBroker

**A fail-closed authorization broker for OpenAI- and Anthropic-compatible model
gateways.**

Your users sign in with the identity they already have. GateBroker exchanges that
identity for scoped access to a model gateway, decides which models they may use,
and forwards the request with a server-side key they never see.

Nobody holds an API key. Not the user, not the agent, not the laptop.

```text
agent ──Bearer(OIDC token)──▶ GateBroker ──Bearer(server-side key)──▶ your gateway ──▶ model provider
                                  │
                                  ├─ verify signature, issuer, audience, lifetime, scope
                                  ├─ resolve exactly one entitlement policy from groups/roles
                                  ├─ allow only models that policy lists
                                  ├─ rate-limit, bound request and response size
                                  └─ emit one audit event carrying no secrets
```

## Why

The usual way to give people access to models is to hand out API keys. Keys leak,
outlive their owner, carry no identity, and cannot express "this group may use
these two models." Once a key is in a `.env` file, revoking it means finding
everyone who copied it.

GateBroker replaces the key with the identity your organization already governs.
Access follows group membership, so it appears and disappears with the directory.
Every request is attributable. The gateway credential stays server-side, which
means there is nothing on a developer's machine worth stealing.

It is deliberately a small, boring component: it authenticates, authorizes,
sanitizes, and forwards. It does not translate between provider APIs, host models,
or try to be a gateway itself.

## What it does

- Accepts `POST /v1/chat/completions`, `/v1/embeddings`, `/v1/responses`
  (OpenAI Responses), and `/v1/messages` (Anthropic Messages).
- Answers `GET /v1/models` with the models the caller's own policy allows, so a
  client never has to carry its own copy of the list.
- Validates issuer, audience, lifetime, subject, groups, and a delegated scope or
  app role, after signature verification against a periodically refreshed JWKS
  snapshot.
- Resolves exactly **one** entitlement policy from the caller's groups or app
  roles. No match is denied. A tie at the highest priority is denied.
- Allows only the models that policy lists.
- Reads the upstream key server-side by reference. Clients and policy documents
  contain key *names*, never values.
- Strips client credentials, routing, and identity headers, then attributes the
  request to the verified caller for the upstream's own accounting.
- Relays bounded SSE streams, and caps request and response sizes, both configurable.
- Emits one JSON audit event per request containing no tokens, prompts, bodies,
  subject ids, IP addresses, or keys.

Anything that does not clearly pass is refused, without calling the upstream.

## Which gateways it works with

Any HTTPS endpoint that speaks the supported OpenAI and Anthropic-compatible
paths and accepts a bearer credential. [LiteLLM](https://github.com/BerriAI/litellm)
is one popular choice and a good place to start, but nothing here depends on it —
the library boundary has no gateway-specific code. A gateway with different paths
or schemas needs an adapter outside this project, because GateBroker deliberately
does not translate between provider protocols.

Both API families are first-class: Chat Completions, Embeddings and Responses on
the OpenAI side, Messages on the Anthropic side, each with its own request
sanitizing, identity attribution and bounded streaming. Which models that reaches
is a separate question, and not one GateBroker answers — a model name is just a
string in a policy's allow-list, so what it resolves to is whatever your gateway
routes it to.

## See it work first

A single command brings up a real identity provider, a real gateway, and the broker,
then proves the whole path — including the refusals:

```shell
cd demo && ./run.sh
```

No provider account, no API key, no outbound calls. See [`demo/`](demo/).

## Quick start

```shell
pip install gatebroker
```

Write a non-secret policy document. A policy maps identity groups or app roles to
allowed models, and *names* the key it needs:

```json
{
  "policies": [
    {
      "id": "engineering",
      "group_ids": ["00000000-0000-0000-0000-000000000001"],
      "allowed_models": ["gpt-4o-mini"],
      "key_ref": "ENGINEERING_GATEWAY_KEY",
      "priority": 10
    }
  ]
}
```

Then run the service. It reads its configuration from the environment and refuses
to start until everything required is present:

```shell
export GABRO_OIDC_ISSUER="https://login.microsoftonline.com/<tenant>/v2.0"
export GABRO_OIDC_AUDIENCE="<broker-application-client-id>"
export GABRO_OIDC_REQUIRED_SCOPE="Broker.Access"
export GABRO_OIDC_JWKS_URL="https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys"
export GABRO_POLICY_PATH="./policies.json"
export GABRO_UPSTREAM_BASE_URL="https://your-gateway.internal"
export GABRO_UPSTREAM_TRUSTED_HOSTS="your-gateway.internal"
export ENGINEERING_GATEWAY_KEY="<server-side-gateway-key>"

python -m gatebroker.runtime
```

Clients then use the ordinary paths, authenticating with their own identity token
rather than a gateway key:

```shell
curl http://127.0.0.1:8080/v1/chat/completions \
  -H "Authorization: Bearer <access-token>" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Hello"}]}'
```

Anthropic-compatible clients use `/v1/messages` and must send an
`anthropic-version` header, which the broker requires and forwards:

```shell
curl http://127.0.0.1:8080/v1/messages \
  -H "Authorization: Bearer <access-token>" \
  -H "anthropic-version: 2023-06-01" \
  -H "Content-Type: application/json" \
  -d '{"model": "claude-sonnet-4", "max_tokens": 256, "messages": [{"role": "user", "content": "Hello"}]}'
```

Either way the model has to be listed by the policy the caller resolves to, or the
request is denied without the gateway being called.

For Kubernetes, [`deploy/`](deploy/) has a complete reference deployment and
explains what the platform around it must provide.

## Local agents: the `gabro` CLI

The other half of the project is a credential helper for developer machines. It
signs a user in and hands a short-lived token to exactly one child process:

```shell
gabro login                  # device-code sign-in; only renewal state is stored
gabro configure claude -- claude
gabro run claude             # starts Claude Code against the gateway
gabro logout
```

The token lives in the spawned process and nowhere else — not in a shell profile,
not in the agent's config file, not in shell history. Claude Code, OpenCode,
Codex, and the GitHub Copilot CLI are handled, including the ones that ignore
`OPENAI_BASE_URL` and need their own provider variables.

`gabro` compiles in its tenant, client, scope, and gateway URL on purpose: if
those were environment-configurable, a shell profile could redirect a freshly
minted token to an endpoint of someone else's choosing. Set them in
`gatebroker/profile.py` and build your own signed release. See
[`docs/cli.md`](docs/cli.md).

## Use it as a library

`create_app` is the boundary. Inject a signature-verifying token verifier, a key
resolver, and a rate limiter, and you get an ASGI app:

```python
from gatebroker.entra import EntraTokenValidationConfig
from gatebroker.forwarding import create_app

app = create_app(
    entra_config=EntraTokenValidationConfig(
        issuer="https://login.microsoftonline.com/<tenant>/v2.0",
        audience="<broker-application-client-id>",
        required_delegated_scope="Broker.Access",
        allowed_app_roles=frozenset({"Broker.Access"}),
    ),
    token_verifier=my_verifier,          # must verify the signature
    policies_json=policies,
    upstream_base_url="https://your-gateway.internal",
    trusted_upstream_hosts=frozenset({"your-gateway.internal"}),
    key_resolver=my_key_resolver,        # resolves key_ref -> value, server-side
    rate_limiter=my_rate_limiter,
)
```

`gatebroker.runtime` is a working implementation of all four injected pieces:
JWKS verification, a file- or environment-backed key resolver, a fixed-window
limiter, and health endpoints.

## Identity providers

Any OIDC provider that issues RS256 access tokens works: Microsoft Entra ID,
Keycloak, Okta, Auth0, Authentik, Dex. The provider has to put group names or role
values in a `groups` or `roles` claim, and a stable subject identifier in the claim
named by `GABRO_OIDC_SUBJECT_CLAIM` — `oid` by default, because Entra's `sub` is
pairwise per application and therefore not a durable identity. For most other
providers, set it to `sub`.

The JWKS endpoint has to belong to the issuer: same origin, and a path below the
issuer's own. That constraint is deliberate, because signing keys decide whether a
token is genuine. If the endpoint were separately steerable, anything able to set
one environment variable could point key discovery at a key set it controls and
mint its own tokens. Entra keeps a stricter exact rule, since its discovery URL is
a known constant rather than something a deployment varies.

The [demo](demo/) runs the whole path against Keycloak, so you can see a
non-Microsoft provider working before committing to one.

## Configuration

| Variable | Required | Purpose |
| --- | --- | --- |
| `GABRO_OIDC_ISSUER` | yes | Expected token issuer |
| `GABRO_OIDC_AUDIENCE` | yes | The broker application's client id |
| `GABRO_OIDC_REQUIRED_SCOPE` | yes | Delegated scope a caller must hold |
| `GABRO_OIDC_JWKS_URL` | yes | Issuer's JWKS endpoint; must belong to the issuer |
| `GABRO_POLICY_PATH` | yes | Path to the policy document |
| `GABRO_UPSTREAM_BASE_URL` | yes | Gateway base URL |
| `GABRO_UPSTREAM_TRUSTED_HOSTS` | yes | Exact allowed gateway hostnames |
| `GABRO_OIDC_ALLOWED_APP_ROLES` | no | App roles accepted instead of a scope |
| `GABRO_OIDC_SUBJECT_CLAIM` | no | Claim holding the subject id (default `oid`; use `sub` for most providers) |
| `GABRO_KEY_DIR` | no | Read each `key_ref` from a file here instead of the environment |
| `GABRO_RATE_LIMIT_REQUESTS` | no | Requests per window (default 60) |
| `GABRO_RATE_LIMIT_WINDOW_SECONDS` | no | Window length (default 60) |
| `GABRO_RATE_LIMIT_MAX_KEYS` | no | Tracked limiter keys (default 10000) |
| `GABRO_MAX_REQUEST_BYTES` | no | Largest accepted request (default 10485760, max 104857600) |
| `GABRO_MAX_RESPONSE_BYTES` | no | Largest relayed response (default 10485760, max 104857600) |
| `GABRO_UPSTREAM_ALLOW_CLUSTER_LOCAL_PLAINTEXT` | no | Permit `http://` to in-cluster Service DNS only |

A `key_ref` is a name, never a value. Keep key material out of policy documents,
container images, and version control.

## Limits worth knowing before you deploy

**The bundled rate limiter is process-local.** It bounds one replica. Two replicas
mean twice the limit. Inject a shared limiter before scaling out.

**Policies load once at startup.** Rotating the document requires a restart.

**Group overage is refused.** When a directory returns a claim-source reference
instead of the group list, the request is denied rather than resolved through a
directory lookup the broker is not configured to make.

**Sizes are capped** at 10 MiB per request and per response, adjustable up to 100 MiB.
A request body is read into memory before parsing, so what a hostile caller can pin is
the bound times the number of concurrent requests. Raise it deliberately.

**The broker is not a network control.** It only helps if callers cannot reach the
gateway directly; enforce that with network policy.

## Security

Token failures return a generic `401`, entitlement failures `403`, rate-limit
denials `429`, and internal or limiter failures `503`. Nothing discloses why.
Tokens and keys are never logged. `GET /healthz` returns only a status, and
`GET /readyz` succeeds only while the JWKS snapshot is fresh and every
policy-referenced key resolves.

To report a vulnerability, see [`SECURITY.md`](SECURITY.md). Please do not open a
public issue.

## Documentation

- [`demo/`](demo/) — a runnable end-to-end demo against Keycloak and LiteLLM
- [`docs/cli.md`](docs/cli.md) — installing and using `gabro`, and building your own distribution
- [`docs/operations.md`](docs/operations.md) — running the service, audit events, diagnosing failures
- [`docs/releases.md`](docs/releases.md) — release and signing administration
- [`deploy/`](deploy/) — reference Kubernetes deployment

## Development

```shell
uv sync --locked --extra test
uv run pytest -q
uv run ruff check .
uv run bandit -q -r src
uv run pip-audit
```

Tests run on macOS, Linux, and Windows, and need no credentials or network. See
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
