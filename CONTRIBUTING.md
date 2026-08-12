# Contributing

Thanks for helping. This is a security component, so a few things matter more here
than in a typical project.

## Development setup

Python 3.11 or newer:

```shell
uv sync --locked --extra test
```

Before opening a pull request:

```shell
uv run pytest -q
uv run ruff check .
uv run bandit -q -r src
uv run pip-audit
```

Tests need no credentials and make no network calls. They run on macOS, Linux, and
Windows in CI; if your change touches paths, file permissions, or process launching,
please think about all three.

## What review will look for

**Fail closed.** Anything ambiguous must be refused. No entitlement match, several
matches tied at the top priority, an unparseable token, a limiter that misbehaves —
all of these deny. If your change introduces a new decision point, the default has
to be "no".

**Cover the refusal, not just the success.** A test that proves a valid request is
forwarded is half a test. Add the case that proves the invalid one is rejected
*without reaching the upstream*.

**Nothing sensitive in an error, log, or audit event.** Tokens, keys, prompts,
request and response bodies, subject identifiers, group claims, and IP addresses stay
out. Client-facing errors are generic on purpose; if you find yourself wanting to
return a more helpful message, add an allowlisted audit classification instead.

**Keys are named, never carried.** A policy document, container image, or commit must
never contain key material.

## Commit sign-off

This project uses the [Developer Certificate of Origin](https://developercertificate.org/).
Sign off each commit to certify you have the right to submit it under Apache-2.0:

```shell
git commit -s -m "your message"
```

That adds a `Signed-off-by` line. There is no CLA.

## Licensing of contributions

Contributions are licensed under Apache-2.0, the license of this repository, per
section 5 of that license. New source files should carry:

```python
# SPDX-License-Identifier: Apache-2.0
```

## Reporting a vulnerability

Do not open a public issue or send a pull request that reveals an exploitable
weakness. Follow [`SECURITY.md`](SECURITY.md).
