# GateBroker demo

A complete, self-contained walkthrough: a real identity provider, a real gateway,
and the broker built from this repository. No provider account, no API key, and no
outbound calls at run time.

```text
Keycloak ──token──▶ gabro/curl ──▶ GateBroker ──▶ LiteLLM ──▶ mock provider
(identity)                        (this repo)    (gateway)   (stands in for OpenAI)
```

```shell
cd demo
./run.sh
```

First run pulls images and builds the broker, so allow a few minutes. It ends by
running the checks below. `./run.sh up` leaves the stack running, `./run.sh down`
removes it, `./run.sh logs` follows output.

## What it proves

```text
== an entitled user reaches an allowed model ==
== the same user is refused a model their policy omits ==
== a user in no entitled group is refused entirely ==
== a caller without a valid token gets nowhere ==
== a client cannot supply its own gateway credential or identity ==
== the model must exist in the policy, not merely at the gateway ==
== unsupported endpoints are not proxied ==
== health endpoints disclose nothing ==
```

Most of these are refusals, which is the point. A demo that only shows a successful
call says very little about a component whose job is to say no.

## Who is who

Three users, password `demo`, all in the `gatebroker-demo` realm:

| User | Group | Policy | May use |
| --- | --- | --- | --- |
| `alice` | `engineering` | `engineering` | `demo-small`, `demo-large` |
| `bob` | `contractors` | `contractors` | `demo-small` only |
| `carol` | none | none resolves | nothing — denied |

Carol is the interesting one. She authenticates perfectly well: her token is valid,
signed, and in date. She is refused because no entitlement policy matches her
groups, and no match means denial rather than a default.

## Trying it by hand

With the stack up, get a token and call the broker:

```shell
token=$(docker compose exec -T gatebroker python - <<'PY'
import json, urllib.parse, urllib.request
data = urllib.parse.urlencode({
    "grant_type": "password", "client_id": "gabro-cli",
    "username": "alice", "password": "demo", "scope": "openid broker",
}).encode()
request = urllib.request.Request(
    "https://keycloak:8443/realms/gatebroker-demo/protocol/openid-connect/token",
    data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
print(json.load(urllib.request.urlopen(request))["access_token"])
PY
)

curl -s http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer ${token}" \
  -H 'Content-Type: application/json' \
  -d '{"model":"demo-large","messages":[{"role":"user","content":"hello"}]}' | jq .
```

Swap `demo-large` for `demo-small` as `bob`, or try `carol`, to watch entitlement
resolution refuse the call.

To browse the identity provider, see the one-line hosts entry below.

## One name for Keycloak

Everything addresses Keycloak as `keycloak:8443`. Containers resolve it through
Compose DNS. To reach it from your own machine — for the admin console or the `gabro`
CLI — map the name once:

```shell
echo '127.0.0.1 keycloak' | sudo tee -a /etc/hosts
```

Then the console is at <https://keycloak:8443> (`admin`/`admin`). Your browser will
warn about the demo's own certificate; accept it and continue.

**The end-to-end checks need none of this.** They run inside the network, where the
name already resolves, so `./run.sh` works on a clean machine. The script tells you
which situation you are in.

Using one name is not incidental. Tokens carry the issuer that minted them, the broker
validates it, and the JWKS endpoint must share its origin — so every party has to agree
on a single name. Two earlier attempts to avoid the hosts entry both failed, and the
second failed in an especially unhelpful way:

- Pinning the server to `keycloak` while serving the console under `localhost` looks
  right, but the console is a browser application that authenticates against the
  *master* realm, and that realm still pointed at `keycloak`. The page loaded and then
  died with "Something went wrong" and nothing in the server log, because the failing
  request never left the browser.
- Letting the issuer follow the request host fixes the console and breaks the broker:
  tokens fetched through `localhost` carry an issuer it rejects.

If you ever change the hostname here, check `authServerUrl` in the console's embedded
`environment` block, not just whether the page loads. That is the value the browser
authenticates against, and it is where both attempts went wrong.

## Using the `gabro` CLI against the demo

The automated checks use the password grant so they need no human at a browser. To
drive the real device-code flow instead, point a local build at the demo realm. This
needs the hosts entry from above, since the CLI acquires real tokens.

Set the distribution profile in `src/gatebroker/profile.py`:

```python
TENANT_ID = ""
OIDC_AUTHORITY = "https://keycloak:8443/realms/gatebroker-demo"
CLIENT_ID = "gabro-cli"
SCOPE = "openid broker"
BASE_URL = "http://localhost:8080/v1"
MODELS = (("demo-small", "Demo small"), ("demo-large", "Demo large"))
CONFIGURED = True
```

```shell
export SSL_CERT_FILE="$PWD/demo/tls/ca.pem"   # trust the demo CA
uv run gabro login
uv run gabro exec -- your-openai-compatible-client
```

This is also the shortest way to see that `gabro` is not Entra-specific: MSAL
reaches Keycloak through OIDC discovery, taking the device authorization endpoint
from the realm's own metadata.

## How the pieces are configured, and why

**Keycloak stands in for Entra, Okta, or Auth0.** The realm import is deliberately
minimal and shows the smallest claim set the broker needs: a subject (`sub`, via
Keycloak's `basic` client scope), the audience of the broker's own API client, group
names in a `groups` claim, and realm roles in a `roles` claim. Declaring client
scopes in a realm import replaces Keycloak's defaults, which is why `basic` is
listed explicitly — without it there is no `sub` and every request is a 401.

Keycloak spells granted scopes `scope` and the subject `sub`. Entra uses `scp` and
`oid`, which are the defaults, so the demo sets `GABRO_OIDC_SCOPE_CLAIM` and
`GABRO_OIDC_SUBJECT_CLAIM` to the Keycloak spellings.

**Everything runs over real TLS with a throwaway CA.** The broker refuses a
plaintext identity provider or gateway, and that is not a rule worth bending for a
demo: a plaintext JWKS fetch would let anything on the path substitute signing keys,
which is a complete bypass. `tls/generate-certs.sh` issues a CA and two server
certificates, and the broker is pointed at that CA with `GABRO_TLS_CA_BUNDLE`. Its
HTTP clients run with `trust_env=False` so nothing ambient can redirect them, which
is exactly why the CA has to be named rather than inherited.

**LiteLLM runs as the single unified image** with no database and no UI login. That
is enough to exercise the broker's upstream contract. One consequence: a real
deployment issues a separate LiteLLM virtual key per entitlement policy, so usage is
attributable per group, and virtual keys need LiteLLM's database. Here all three
policies reference the same master key, and the three separate `key_ref` files exist
to show the shape rather than a genuine separation.

**The mock provider replaces OpenAI.** Point `api_base` in `litellm/config.yaml` at
a real provider and the rest of the demo is unchanged.

## Where identity stops

The broker overwrites whatever identity a client claimed with the verified subject
before forwarding, so the gateway attributes usage to who the caller actually is
rather than to who they said they were. That substitution is a security property and
`tests/test_forwarding.py` asserts it directly.

What the gateway then does with that identity is the gateway's decision, and
stopping there is the sensible default: the gateway holds the provider credentials
and calls the provider as itself, so internal user identifiers need not be handed to
a third party. That is why the mock provider in this demo never sees a user id, and
why the checks do not look for one. The observable hop for attribution is
broker-to-gateway, which this topology does not expose.

## Not production

Passwords are `demo`, the CA is throwaway, Keycloak runs `start-dev` with an
in-memory database, LiteLLM has no persistence, and the entitlement keys in
`entitlements/` are placeholders committed to Git. Nothing here should be copied
into a real deployment; [`deploy/`](../deploy/) is the reference for that.
