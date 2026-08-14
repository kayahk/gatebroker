# The `gabro` CLI

`gabro` signs a user in with their organization's identity provider and hands a
short-lived gateway token to one child process. It never gives the user, or the
agent, the upstream gateway key.

Its whole job is that boundary. Everything below is in service of one property:
the credential exists in the spawned process and nowhere else — not in a shell
profile, not in an agent's configuration file, not in your shell history.

## Install

Each `v*` release publishes self-contained archives with a SHA-256 checksum and
GitHub build provenance. They need neither Python nor a virtual environment.

**A release is only useful if it was built from a configured distribution.** The
shipped `gatebroker/profile.py` is a placeholder, and the CLI refuses to acquire a
token until a distributor replaces it with their own tenant, client, scope,
gateway URL, and model list. See [Building your own distribution](#building-your-own-distribution).

### macOS (Apple Silicon)

When the project's release workflow has Apple signing configured, download
`gabro-macos-arm64.pkg` and its `.sha256`:

```sh
shasum -a 256 -c gabro-macos-arm64.pkg.sha256
sudo installer -pkg gabro-macos-arm64.pkg -target /
gabro --help
```

If signing is not configured, the release publishes
`gabro-macos-arm64-unsigned.tar.gz` instead, named so you cannot mistake it for a
signed build. Verify the checksum and the build provenance attestation before you
clear the quarantine attribute, and prefer a signed build when one exists.

### Linux

```sh
sha256sum -c gabro-linux-x64.tar.gz.sha256
mkdir gabro-release && tar -xzf gabro-linux-x64.tar.gz -C gabro-release
gabro-release/gabro-linux-x64/install.sh
```

### Windows

Verify `gabro-windows-x64.zip` with `Get-FileHash -Algorithm SHA256`, extract
`gabro.exe` into a user-controlled directory such as
`%LOCALAPPDATA%\Programs\gabro`, and add it to the user `PATH`.

### From source

For development against a checkout:

```sh
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[test]"
gabro --help
```

## Sign in and launch an agent

```sh
# Device-code sign-in. Copies the code and opens the verification page when it
# can, and keeps both visible when it cannot. Only renewal state is persisted,
# in the OS credential store.
gabro login

# Sign in, save a launcher profile, and start the agent in one step. Equivalent
# to `gabro login` then `gabro configure opencode -- opencode` then
# `gabro run opencode`.
gabro login opencode

# Save a reusable, non-secret launcher profile. Stores the command and its fixed
# arguments; never a token.
gabro configure claude -- claude

# Start that profile. Arguments after -- are passed through to the agent.
gabro run claude -- --model your-allowed-model

# One-off launch without saving a profile.
gabro exec -- your-compatible-client

# Remove local renewal state. Reports whether state existed.
gabro logout
```

`exec` and `run` set `OPENAI_BASE_URL` and `OPENAI_API_KEY` for
OpenAI-compatible clients, and `ANTHROPIC_BASE_URL` and `ANTHROPIC_AUTH_TOKEN`
for Anthropic Messages-compatible clients, in the child process only. Never
export those variables yourself or paste the token into a file.

## Two configurations, easily confused

**The entitlement policy is owned by whoever runs the broker.** It maps identity
groups or app roles to allowed models and to a server-side gateway key. A user
neither deploys nor edits it, and never receives the key. To get access, ask for
membership in an entitled group.

**The local setup is yours.** You install the agent, configure its non-secret
provider settings, sign in, and launch through `gabro`.

## Launcher profiles

```sh
gabro configure [--reset] <name> -- <command> [fixed-arguments...]
```

The syntax is positional, which trips people up: the first word is the profile
name, and the command comes after `--`. For OpenCode both happen to be
`opencode`:

```sh
gabro configure --reset opencode -- opencode
gabro login
gabro run opencode
```

`--reset` discards **every** saved profile before writing this one, so use it
only when you mean to start over. Running `configure` again with the same name
and without `--reset` replaces just that profile.

Profiles live in a per-user config directory:

- macOS: `~/Library/Application Support/gabro/agents.json`
- Linux: `$XDG_CONFIG_HOME/gabro/agents.json`, or `~/.config/gabro/agents.json`
- Windows: `%APPDATA%\gabro\agents.json`

They are written atomically and authenticated with an HMAC key held in the OS
credential store, so an edited profile is rejected before any token is acquired.
That matters because a profile names an executable: without the check, anything
able to write the file could get a fresh gateway token handed to a command of its
choosing.

`configure` does not touch an agent's own provider configuration and never writes
credential material into it.

## Claude Code

Launching Claude through `gabro` needs nothing extra:

```shell
gabro configure claude -- claude
gabro login
gabro run claude
```

Claude Code reads the gateway address and credential from `ANTHROPIC_BASE_URL` and
`ANTHROPIC_AUTH_TOKEN`, which `gabro` supplies to the child process. Its model ids are the
part that needs help: Claude Code defaults to Anthropic's own names, which an entitlement
policy is unlikely to list, so the broker refuses every request with a generic `403` and
nothing points at the model as the cause. `gabro` therefore asks the broker which models
*this* user may use — `GET /v1/models`, answered from the caller's resolved policy — and
sets both of the variables Claude Code reads:

- `ANTHROPIC_MODEL` — the session model.
- `ANTHROPIC_SMALL_FAST_MODEL` — the cheaper model used for background work such as
  summarising and titling.

Both matter. With only the session model set, the session looks healthy while background
requests fail on their own.

Because the list comes from the policy rather than from `gabro`, a policy that grows a
model grants it without a new release, and nobody is pinned to a subset of what they are
entitled to. Export either variable to pin a different allowed model and `gabro` keeps
your value. If the lookup fails, `gabro` falls back to the profile's models and still
starts the agent.

## Clients that ignore `OPENAI_BASE_URL`

Some agents do not treat `OPENAI_BASE_URL` as a provider switch, so `gabro`
injects the equivalent non-secret settings for them:

**Codex** uses the OpenAI Responses path. `gabro` passes `-c` overrides that point
a custom provider at the gateway and install a local model catalog, so the
`/model` picker lists the models the caller's own policy allows instead of the built-in
presets. The catalog is non-secret; the token still only reaches the process environment.

**GitHub Copilot CLI** selects a custom endpoint through its own
`COPILOT_PROVIDER_*` "bring your own key" variables, which `gabro` sets for the
child process. Copilot picks one model per launch rather than enumerating a
catalog, so use `--model` or `COPILOT_MODEL` to choose another allowed model.

In both cases the gateway remains the authority. The picker is a convenience;
entitlement, the model allow-list, and rate limits are enforced by the broker
regardless of what a client offers to select.

## Claude Code and `--dangerously-skip-permissions`

`--dangerously-skip-permissions` gives Claude Code unrestricted local tool and
shell execution. It changes nothing about gateway access — the broker still
applies authentication, entitlement, model, and rate-limit checks — but it does
remove local guardrails. Use it only in a repository and branch you trust, and
prefer a disposable worktree:

```sh
git worktree add ../review-worktree <branch>
cd ../review-worktree
gabro exec -- claude --dangerously-skip-permissions
```

The launched process inherits `gabro`'s working directory, and the configured
argument vector is passed directly rather than through a shell.

## Building your own distribution

`gabro` deliberately accepts no environment override for its tenant, client,
scope, or gateway URL. If it did, a shell profile or CI variable could redirect a
freshly minted gateway token to an endpoint of the attacker's choosing.

So the coordinates are compiled in. Set them in `src/gatebroker/profile.py`:

```python
TENANT_ID = "your-tenant-id"
CLIENT_ID = "your-device-code-public-client-id"
SCOPE = "api://your-broker-application/access_as_user"
BASE_URL = "https://your-gateway.internal/v1"
GATEWAY_NAME = "Your Gateway"
MODELS = (("gpt-4o-mini", "GPT-4o mini"),)
CONFIGURED = True
```

Then tag a release. The release workflow refuses to bundle while `CONFIGURED` is
`False`, so an unconfigured build cannot reach users.

For development, an *unconfigured* build can be pointed at a profile file instead of
editing source:

```shell
export GABRO_DEV_PROFILE=/path/to/profile.json
```

```json
{
  "oidc_authority": "https://idp.example/realms/yours",
  "client_id": "your-device-code-client",
  "scope": "openid your-scope",
  "base_url": "https://your-gateway.internal/v1",
  "ca_bundle": "ca.pem",
  "models": [["gpt-4o-mini", "GPT-4o mini"]]
}
```

Use `tenant_id` instead of `oidc_authority` for Microsoft Entra. A relative `ca_bundle`
is resolved against the profile file's own directory. The CLI announces on every run
that it is using a development profile, and a configured distribution ignores the
variable completely, so this cannot redirect a released build. The
[demo](../demo/) ships a working example.

The client you register for this flow must be a **public** client with device-code
flow enabled and no secret, and it must be separate from the broker's own resource
application. It should request only the broker's delegated scope.
