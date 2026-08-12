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

# Identity provider and gateway coordinates.
TENANT_ID = "00000000-0000-0000-0000-000000000000"
CLIENT_ID = "00000000-0000-0000-0000-000000000000"
SCOPE = "api://gatebroker.invalid/access_as_user"
BASE_URL = "https://gateway.gatebroker.invalid/v1"

# Shown to users when a local agent lists its provider.
GATEWAY_NAME = "GateBroker"

# Model ids the gateway accepts, paired with the label a local agent displays.
# Keep aligned with the ``allowed_models`` of the entitlement policy that serves
# these users; a model missing from that policy is denied by the broker.
MODELS: tuple[tuple[str, str], ...] = (
    ("gpt-4o-mini", "GPT-4o mini"),
    ("gpt-4o", "GPT-4o"),
)

# Set to True in your distribution once every value above is your own.
CONFIGURED = False


def default_model() -> str:
    """Return the model a local agent selects when the user names none."""
    if not MODELS:
        raise RuntimeError("profile.MODELS must list at least one gateway model")
    return MODELS[0][0]
