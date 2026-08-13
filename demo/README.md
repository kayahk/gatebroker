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

With the stack up, everything is reachable from your machine directly. Get a token
and call the broker:

```shell
token=$(curl -sk https://localhost:8443/realms/gatebroker-demo/protocol/openid-connect/token \
  -d grant_type=password -d client_id=gabro-cli \
  -d username=alice -d password=demo -d 'scope=openid broker' | jq -r .access_token)

curl -s http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer ${token}" \
  -H 'Content-Type: application/json' \
  -d '{"model":"demo-large","messages":[{"role":"user","content":"hello"}]}' | jq .
```

`curl -sk` skips verification of the demo's own certificate, which is fine for poking
around; the broker itself verifies it properly against the demo CA.

Swap `demo-large` for `demo-small` as `bob`, or try `carol`, to watch entitlement
resolution refuse the call.

The Keycloak admin console is at <https://localhost:8443/admin> (`admin`/`admin`).
Your browser will warn about the demo's own certificate; accept it and continue.

## Everything on localhost, and why

There is nothing to configure: no hosts file, no DNS, no sudo. Every service shares a
single network namespace, so `localhost` means the same thing to your browser and to
every container, the same way it does inside a Kubernetes pod.

That is worth the slightly unusual arrangement because tokens carry the issuer that
minted them, the broker validates it, and the JWKS endpoint must share its origin. With
separate namespaces there is simply no address that both a browser on the host and the
broker in a container can use for the same Keycloak, and two attempts to work around
that both failed — the second in a particularly unhelpful way:

- Pinning the server to a container-only name while serving the console under
  `localhost` looks right, but the console is a browser application that authenticates
  against the *master* realm, and that realm still pointed at the container-only name.
  The page loaded and then died with "Something went wrong" and nothing in the server
  log, because the failing request never left the browser.
- Letting the issuer follow the request host fixes the console and breaks the broker:
  tokens fetched through one name carry an issuer it rejects.

The cost is that this demo does not model production networking, where services address
each other by distinct names. [`deploy/`](../deploy/) is the reference for that.

If you change the addressing here, check `authServerUrl` in the console's embedded
`environment` block rather than whether the page loads. That is the value the browser
authenticates against, and it is where both attempts went wrong.

## Using the `gabro` CLI against the demo

The automated checks use the password grant so they need no human at a browser. To
drive the real device-code flow instead, point a local build at the demo realm. From the
repository root:

```shell
export GABRO_DEV_PROFILE="$PWD/demo/gabro-dev-profile.json"
uv run gabro login
```

`login` prints a URL and a code. Open it and sign in as **`alice`** with password
**`demo`** — one of the realm users from the table above, not the `admin` account, which
belongs to the admin console in a different realm. Sign in as `bob` or `carol` instead to
watch the broker refuse a model or an identity that resolves to no policy.

Then start something through the gateway. If you do not have an OpenAI-compatible agent
to hand, a shell is enough to see it working: `exec` puts the endpoint and a short-lived
token in the child process, and nowhere else.

```shell
uv run gabro exec -- sh -c 'curl -s "$OPENAI_BASE_URL/chat/completions" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"demo-small\",\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}]}"'
```

```shell
uv run gabro exec -- your-openai-compatible-client
```

That is all: no source edits, no other variables. The shipped profile carries the demo
realm's coordinates and points at the demo CA, and `gabro` prints which profile it is
using on every invocation so you can never be unsure whether a token came from a
reviewed distribution or from a local file.

If it refuses with "This build has no distribution profile", ask the CLI what it is:

```shell
uv run gabro --version
```

That reports the version, which profile is in use, and the directory the code was
loaded from. A `profile: none set` line with the variable exported almost always means
the checkout predates this feature, so `git pull` first.

Signing in more than once used to leave a stale account behind and every later command
failed with "Multiple cached accounts were found" — recreating the demo is enough to
cause it, since a rebuilt Keycloak issues new subject identifiers for the same username.
`login` now keeps only the account that just signed in. To clear an older cache:

```shell
uv run gabro logout
```

Note the `uv run` prefix: from a source checkout `gabro` is not on your PATH. The CLI's
own messages take that into account and name whichever form will work.

`GABRO_DEV_PROFILE` is read **only** by a build whose `profile.py` is still
unconfigured, which is what makes it safe. A configured distribution has its
coordinates compiled in and ignores the variable entirely, so it cannot be used to
redirect a signed release's token — and an unconfigured build refuses to mint a token
at all, so there is nothing there to subvert. The release workflow additionally refuses
to bundle a build configured this way.

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

## One stack at a time

Compose pins a single project name, so two checkouts of this repository — a second clone,
or a git worktree — address the same stack. Whichever ran last owns the containers, and
they keep the paths of the directory that created them, which surfaces as certificates
that inexplicably fail to verify against the files sitting right next to you. `run.sh`
detects this and tells you which directory owns the running stack; take it over with
`./run.sh down && ./run.sh`.

## If something does not come up

`./run.sh` bounds how long it waits and then prints the last health check output for
every container, so a service that never becomes healthy says why instead of sitting at
"Waiting".

The most likely cause after an upgrade is stale TLS material. `tls/generate-certs.sh`
validates what is on disk rather than reusing it blindly — it checks the key-identifier
extensions, that `localhost` is present as a subject alternative name, that nothing is
close to expiry, and that each certificate really was signed by the CA next to it — and
reissues everything if any of that fails. To force a clean slate:

```shell
rm -f tls/*.pem tls/*.key
./run.sh down && ./run.sh
```

## Not production

Passwords are `demo`, the CA is throwaway, Keycloak runs `start-dev` with an
in-memory database, LiteLLM has no persistence, and the entitlement keys in
`entitlements/` are placeholders committed to Git. Nothing here should be copied
into a real deployment; [`deploy/`](../deploy/) is the reference for that.
