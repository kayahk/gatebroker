# SPDX-License-Identifier: Apache-2.0
"""Distribution profile: the one place a distributor pins its own deployment.

These values are deliberately **not** environment-configurable. ``gabro`` mints a
short-lived access token for one specific gateway audience, so a shell profile,
wrapper script, or CI variable must not be able to redirect that token to another
endpoint. A distributor sets the constants below when it builds and signs its own
CLI; the rest of this package is deployment-neutral.

The shipped values are placeholders. ``CONFIGURED`` stays ``False`` until they are
replaced, and the CLI refuses to acquire a token while it is ``False`` so an
unconfigured build can never send a credential to the example endpoint.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

# Identity provider and gateway coordinates.
#
# For Microsoft Entra, set TENANT_ID and leave OIDC_AUTHORITY empty. For any other
# OIDC provider, leave TENANT_ID empty and set OIDC_AUTHORITY to the issuer URL
# whose /.well-known/openid-configuration advertises a device authorization
# endpoint; the device-code flow needs one.
TENANT_ID = "00000000-0000-0000-0000-000000000000"
OIDC_AUTHORITY = ""
CLIENT_ID = "00000000-0000-0000-0000-000000000000"
SCOPE = "api://gatebroker.invalid/access_as_user"
BASE_URL = "https://gateway.gatebroker.invalid/v1"

# Shown to users when a local agent lists its provider.
GATEWAY_NAME = "GateBroker"

# Optional path to a CA bundle for reaching the identity provider, for a deployment
# behind a private CA. Empty means the system trust store. This is needed separately
# from any SSL_CERT_FILE in the environment because the identity library used here
# goes through `requests`, which reads neither that variable nor the system store.
CA_BUNDLE = ""

# Model ids the gateway accepts, paired with the label a local agent displays.
# Keep aligned with the ``allowed_models`` of the entitlement policy that serves
# these users; a model missing from that policy is denied by the broker.
MODELS: tuple[tuple[str, str], ...] = (
    ("gpt-4o-mini", "GPT-4o mini"),
    ("gpt-4o", "GPT-4o"),
)

# Set to True in your distribution once every value above is your own.
CONFIGURED = False

# True when the values above came from a development profile file rather than from
# source. A release must never be built this way; the release workflow checks it.
DEVELOPMENT = False

_DEVELOPMENT_PROFILE_VARIABLE = "GABRO_DEV_PROFILE"
_REQUIRED_KEYS = frozenset({"client_id", "scope", "base_url"})


def default_model() -> str:
    """Return the model a local agent selects when the user names none."""
    if not MODELS:
        raise RuntimeError("profile.MODELS must list at least one gateway model")
    return MODELS[0][0]


def _apply_development_profile() -> None:
    """Point an unconfigured build at a profile file, for demos and development.

    This is only ever consulted when ``CONFIGURED`` is False, which is what makes it
    safe. A configured distribution has its coordinates compiled in and never reads
    this, so the variable cannot redirect a signed release's token to another endpoint
    -- the property the whole module exists to protect. An unconfigured build refuses to
    mint a token at all, so there is nothing here to subvert either.

    It exists because the alternative was asking people to edit tracked source to try
    the demo, which is easy to forget and leaves demo values in a working tree.
    """
    global CONFIGURED, DEVELOPMENT, TENANT_ID, OIDC_AUTHORITY, CLIENT_ID
    global SCOPE, BASE_URL, GATEWAY_NAME, MODELS, CA_BUNDLE

    # The refusal lives here rather than only at the call site below, so that a
    # configured build is protected however this is reached.
    if CONFIGURED:
        return

    location = os.environ.get(_DEVELOPMENT_PROFILE_VARIABLE, "").strip()
    if not location:
        return

    try:
        document = json.loads(Path(location).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"{_DEVELOPMENT_PROFILE_VARIABLE} is unreadable") from error
    if not isinstance(document, dict):
        raise RuntimeError(f"{_DEVELOPMENT_PROFILE_VARIABLE} must contain a JSON object")

    missing = sorted(_REQUIRED_KEYS - document.keys())
    if missing:
        raise RuntimeError(
            f"{_DEVELOPMENT_PROFILE_VARIABLE} is missing: {', '.join(missing)}"
        )
    if bool(document.get("tenant_id")) == bool(document.get("oidc_authority")):
        raise RuntimeError(
            f"{_DEVELOPMENT_PROFILE_VARIABLE} must set exactly one of "
            "tenant_id or oidc_authority"
        )

    models = document.get("models") or []
    if not isinstance(models, list) or not models:
        raise RuntimeError(f"{_DEVELOPMENT_PROFILE_VARIABLE} must list models")
    try:
        parsed = tuple((str(slug), str(label)) for slug, label in models)
    except (TypeError, ValueError) as error:
        raise RuntimeError(
            f"{_DEVELOPMENT_PROFILE_VARIABLE} models must be [id, label] pairs"
        ) from error

    TENANT_ID = str(document.get("tenant_id") or "")
    OIDC_AUTHORITY = str(document.get("oidc_authority") or "")
    CLIENT_ID = str(document["client_id"])
    SCOPE = str(document["scope"])
    BASE_URL = str(document["base_url"])
    GATEWAY_NAME = str(document.get("gateway_name") or "GateBroker")
    MODELS = parsed
    # Resolved against the profile's own directory, so a profile can name a CA
    # sitting next to it without depending on the working directory.
    bundle = str(document.get("ca_bundle") or "")
    if bundle:
        resolved = Path(bundle)
        if not resolved.is_absolute():
            resolved = Path(location).parent / resolved
        if not resolved.is_file():
            raise RuntimeError(f"{_DEVELOPMENT_PROFILE_VARIABLE} ca_bundle is unreadable")
        CA_BUNDLE = str(resolved)
    DEVELOPMENT = True
    CONFIGURED = True


if not CONFIGURED:
    _apply_development_profile()
