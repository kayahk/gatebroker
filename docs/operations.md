# Operating GateBroker

## The boundary you are protecting

GateBroker is only a boundary if callers cannot go around it. Two things have to
hold, and neither is enforced by this code:

1. Client-facing `/v1/*` traffic reaches the broker, not the upstream gateway.
2. The upstream gateway accepts connections from the broker's identity and from
   nothing else.

If either is missing, a caller who learns the gateway's address bypasses every
entitlement check here. Verify both before treating the broker as a control.

## Diagnosing without disclosing

The broker is deliberately quiet, and incident work should stay that way. Do not
extract an upstream gateway key, print a device-code cache, bearer token, request
or response body, or prompt content in order to debug. An incident record should
carry only the endpoint class, HTTP status, resource condition, audit
classification, and model name.

This is not ceremony. The reason the broker is worth deploying is that no client
and no operator needs to hold the upstream credential; a debugging session that
prints one has removed the property you deployed it for.

## Audit events

Every supported `/v1/*` request emits exactly one JSON audit event. The outcome
is one of `forwarded`, `authentication_failed`, `authorization_denied`,
`rate_limit_denied`, `invalid_request`, `service_unavailable`, or
`upstream_failed`. Each event carries the route, HTTP status, duration, and —
once authorization has succeeded — the policy id and the requested model.

Events never contain tokens, prompts, request bodies, object ids, IP addresses,
group claims, or gateway keys. Client-facing error messages stay generic on
purpose, so the audit stream, not the response body, is where you look.

When the broker can classify an upstream failure safely it records an
allowlisted `detail`. The value is always drawn from a fixed set — for example
`upstream_key_rejected`, `upstream_budget_denied`, `upstream_rate_limited`,
`upstream_model_denied`, `upstream_tool_schema_rejected`,
`upstream_json_error`, `upstream_plaintext_error`, or
`upstream_error_body_unavailable`. Raw upstream text is never copied into it.

## Common failures, in the order worth checking

**The pod never becomes ready.** `GET /readyz` succeeds only while the JWKS
snapshot is fresh *and* every key referenced by the policy document resolves to a
non-empty value. So a `503` means either the identity provider's JWKS endpoint is
unreachable from the pod, or some `key_ref` has no corresponding file in
`GABRO_KEY_DIR`. A partially projected entitlement document keeps the whole
broker out of service rather than silently denying a subset of users, which is
deliberate: a policy that half-exists is not a policy.

**Every request returns 401.** The token is being rejected before entitlement
selection. Check that `GABRO_ENTRA_AUDIENCE` is the broker application's client
id — not its identifier URI, which is the *scope* prefix and is a common
mix-up — and that the issuer matches the tenant that minted the token.

**A specific user gets 403 while others succeed.** Entitlement selection found
either no matching policy or several tied at the top priority. Both fail closed.
The audit event names the policy id when one was selected, so an event with no
policy id means nothing matched.

**Requests are denied for one model only.** The selected policy's
`allowed_models` does not list it. Model access is per-policy, so a user in a
group with a narrower list is denied even if another policy allows the model.

**The broker still enforces an old policy after you changed it.** Policies are
read once at startup. Rotating the projected document requires restarting the
pod.

**Authentication succeeds but forwarding fails.** A generic `403` or `502` after
successful validation points at the hop between broker and gateway, not at
identity. Check network policy first: a broker that reaches the gateway through a
mesh or hairpin usually keeps its own pod identity, so a rule that authorizes
"ingress" in general will not authorize this source.

## Rate limiting

The bundled limiter is a process-local fixed window keyed by
`(object id, policy id, client IP)`. It bounds one replica. Two replicas mean
roughly twice the configured requests, because neither knows about the other. If
the limit is a real control rather than a courtesy, inject a shared limiter
through `create_app` before scaling out.

A limiter that raises, or that returns anything other than a boolean, fails
closed with a `503`.

## Cost and usage

The broker does not meter tokens or spend; it forwards a request and records that
it did. Take usage and cost from the upstream gateway, which sees the actual
completions. The policy id in the audit event is what lets you attribute that
usage back to an entitlement group.
