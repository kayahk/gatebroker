# Release administration

For repository maintainers. See [`cli.md`](cli.md) for installation.

## Before the first release

Pushing a `v*` tag runs two workflows: one publishes a container image, the other
bundles and publishes CLI artifacts. The CLI workflow has access to code-signing
material, so configure these first:

1. **Protect the `v*` tag namespace** with a repository ruleset, so only trusted
   maintainers can create, delete, or move a release tag. This is the control
   that matters most: the tag is what authorizes a signed artifact.
2. **Store signing values as Actions secrets**, never in workflow files, repository
   files, or release notes. Scope them to a release environment if you use one.
3. **Review every workflow change** before merge, and keep third-party actions
   pinned to commit SHAs. A test asserts the pinning; it cannot assert that a
   pinned SHA is one you meant to trust.
4. **Configure the distribution profile.** The workflow refuses to bundle while
   `gatebroker/profile.py` is still the placeholder, which prevents shipping a
   build that points users at the example endpoint — but it cannot tell whether the
   values you set are the right ones.

## macOS signing

Signing is optional, because a fork will not have an Apple Developer account.
When all seven inputs below are present the workflow produces a signed, notarized,
stapled `.pkg`. When any is missing it publishes
`gabro-macos-arm64-unsigned.tar.gz` instead and annotates the run, so a release
never silently passes off an unsigned build as a signed one.

- `APPLE_SIGNING_CERTIFICATE_BASE64` — base64 Developer ID certificate (PKCS#12)
- `APPLE_SIGNING_CERTIFICATE_PASSWORD` — password for that PKCS#12 file
- `APPLE_DEVELOPER_ID_APPLICATION` — Developer ID Application identity
- `APPLE_DEVELOPER_ID_INSTALLER` — Developer ID Installer identity
- `APPLE_NOTARY_ISSUER` — App Store Connect issuer id
- `APPLE_NOTARY_KEY_ID` — App Store Connect API key id
- `APPLE_NOTARY_PRIVATE_KEY_BASE64` — base64 App Store Connect API private key

Set the repository variable `MACOS_BUNDLE_IDENTIFIER` to your own reverse-DNS
identifier; it defaults to `org.gatebroker.gabro`.

If you distribute to users who are not you, sign. An unsigned build is
appropriate for evaluation and for forks, not for a fleet.

## Accepting a release

After the tag runs, confirm that:

- all three bundle jobs ran from the intended tag;
- the macOS job either completed codesign verification, notarization, stapling and
  `spctl --assess`, or clearly published the unsigned archive;
- the release contains only the expected assets and their `.sha256` files;
- every asset has build provenance;
- the container image was published under its commit SHA, and nothing published
  `latest`;
- a clean host can install and run `gabro --help` by following `cli.md`.

## Versioning

The tag drives the CLI version and the container tag. Keep `version` in
`pyproject.toml` and `__version__` in `gatebroker/__init__.py` in step with it.

A deployment should pin an image digest or a commit-SHA tag, never a moving tag.
The image workflow publishes the commit SHA for exactly this reason.
