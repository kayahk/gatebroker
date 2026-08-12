# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use the repository's
GitHub **Security** tab to open a private vulnerability report, including affected
versions, reproduction steps, and impact.

Never include access tokens, gateway keys, directory data, or prompt content in a
report. If a reproduction seems to need a real credential, describe the shape of the
input instead and we will work it out.

Expect an acknowledgement of a complete report within five business days. A
disclosure date is agreed once impact and remediation are understood.

## Supported versions

Security fixes land on the latest release line. Pin deployments to an immutable
image digest or commit-SHA tag and upgrade after a security release.

## Scope notes

Some properties this project depends on are outside its control, and reports about
them belong with the deployment rather than here:

- **Network isolation.** GateBroker only constrains traffic that reaches it. A
  deployment that lets clients call the upstream gateway directly has bypassed it by
  configuration, not by defect.
- **Rate limiting across replicas.** The bundled limiter is documented as
  process-local. Running several replicas without injecting a shared limiter
  multiplies the limit, as documented.
- **Key projection.** How key material arrives at `GABRO_KEY_DIR`, and who can read
  it, belongs to the deployment's secret management.

A way to make the broker forward without a valid token, select a policy the caller is
not entitled to, reach a model outside the selected policy, disclose a token or key
in a response or log, or bypass the size and depth bounds is in scope and we want to
hear about it.
