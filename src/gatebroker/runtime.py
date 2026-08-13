# SPDX-License-Identifier: Apache-2.0
"""Production runtime wiring for the GateBroker service."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import ssl
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from threading import Condition, Lock
from typing import Any
from urllib.parse import SplitResult, urlsplit

import httpx
import jwt
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from .forwarding import KeyResolver, RateLimiter, RateLimitKey, create_app
from .oidc import TokenValidationConfig, TokenVerifier
from .policy import load_policies

_JWKS_REFRESH_SECONDS = 300
_JWKS_STALE_SECONDS = 900
_JWKS_KEY_MISS_REFRESH_COOLDOWN_SECONDS = 60
_JWKS_REFRESH_WAIT_SECONDS = 6
_LOGGER = logging.getLogger("uvicorn.error")


@dataclass(frozen=True)
class RuntimeSettings:
    """Non-secret broker runtime configuration supplied by the deployment."""

    oidc: TokenValidationConfig
    jwks_url: str
    policies_json: str
    upstream_base_url: str
    trusted_upstream_hosts: frozenset[str]
    rate_limit_requests: int
    rate_limit_window_seconds: int
    rate_limit_max_keys: int
    allow_cluster_local_plaintext_upstream: bool = False
    key_directory: str = ""
    tls_ca_bundle: str = ""


def load_runtime_settings(environment: Mapping[str, str] | None = None) -> RuntimeSettings:
    """Load and validate all configuration required before accepting traffic."""
    values = os.environ if environment is None else environment
    issuer = _required(values, "GABRO_OIDC_ISSUER")
    audience = _required(values, "GABRO_OIDC_AUDIENCE")
    required_scope = _required(values, "GABRO_OIDC_REQUIRED_SCOPE")
    jwks_url = _required(values, "GABRO_OIDC_JWKS_URL")
    _validate_jwks_url(issuer, jwks_url)
    policy_path = Path(_required(values, "GABRO_POLICY_PATH"))
    upstream_base_url = _required(values, "GABRO_UPSTREAM_BASE_URL")
    trusted_hosts = frozenset(
        host.strip()
        for host in _required(values, "GABRO_UPSTREAM_TRUSTED_HOSTS").split(",")
        if host.strip()
    )
    if not trusted_hosts:
        raise RuntimeError("GABRO_UPSTREAM_TRUSTED_HOSTS must include a hostname")
    try:
        policies_json = policy_path.read_text(encoding="utf-8")
    except OSError as error:
        raise RuntimeError("GABRO_POLICY_PATH is unreadable") from error
    return RuntimeSettings(
        oidc=TokenValidationConfig(
            issuer=issuer,
            audience=audience,
            required_delegated_scope=required_scope,
            allowed_app_roles=frozenset(_csv(values.get("GABRO_OIDC_ALLOWED_APP_ROLES", ""))),
            subject_claim=_claim_name(
                values.get("GABRO_OIDC_SUBJECT_CLAIM", "oid"), "GABRO_OIDC_SUBJECT_CLAIM"
            ),
            scope_claim=_claim_name(
                values.get("GABRO_OIDC_SCOPE_CLAIM", "scp"), "GABRO_OIDC_SCOPE_CLAIM"
            ),
        ),
        jwks_url=jwks_url,
        policies_json=policies_json,
        upstream_base_url=upstream_base_url,
        trusted_upstream_hosts=trusted_hosts,
        rate_limit_requests=_positive_integer(values.get("GABRO_RATE_LIMIT_REQUESTS", "60"), "GABRO_RATE_LIMIT_REQUESTS"),
        rate_limit_window_seconds=_positive_integer(values.get("GABRO_RATE_LIMIT_WINDOW_SECONDS", "60"), "GABRO_RATE_LIMIT_WINDOW_SECONDS"),
        rate_limit_max_keys=_positive_integer(
            values.get("GABRO_RATE_LIMIT_MAX_KEYS", "10000"), "GABRO_RATE_LIMIT_MAX_KEYS"
        ),
        allow_cluster_local_plaintext_upstream=_boolean(
            values.get("GABRO_UPSTREAM_ALLOW_CLUSTER_LOCAL_PLAINTEXT", "false"),
            "GABRO_UPSTREAM_ALLOW_CLUSTER_LOCAL_PLAINTEXT",
        ),
        key_directory=values.get("GABRO_KEY_DIR", "").strip(),
        tls_ca_bundle=_readable_ca_bundle(values.get("GABRO_TLS_CA_BUNDLE", "").strip()),
    )


def _readable_ca_bundle(path: str) -> str:
    """Fail at startup rather than on the first request if the CA is unusable."""
    if not path:
        return ""
    try:
        if not Path(path).is_file():
            raise OSError("not a file")
        Path(path).read_bytes()
    except OSError as error:
        raise RuntimeError("GABRO_TLS_CA_BUNDLE is unreadable") from error
    return path


def build_ssl_context(settings: RuntimeSettings) -> ssl.SSLContext | None:
    """Return the verification context, or None to use the default trust store.

    An internal identity provider or gateway is often fronted by a private CA. The
    HTTP clients here run with ``trust_env=False`` so that no ambient environment
    variable can redirect them through a proxy, which also means they will not pick
    a CA up from the environment. Naming the bundle explicitly keeps the operator's
    decision deliberate and visible.
    """
    if not settings.tls_ca_bundle:
        return None
    context = ssl.create_default_context(cafile=settings.tls_ca_bundle)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def build_key_resolver(settings: RuntimeSettings) -> KeyResolver:
    """Return the key source this deployment configured.

    The broker resolves a policy's key by reference and stays indifferent to
    where that key comes from. With `GABRO_KEY_DIR` set it reads one
    file per reference from that directory, which works for any projection that
    presents files -- a Secret or ConfigMap volume, a CSI driver, a tmpfs
    written by a sidecar. Without it, the reference is a process environment
    variable, as it has always been.
    """
    if not settings.key_directory:
        return lambda key_ref: os.environ[key_ref]

    directory = Path(settings.key_directory).resolve()

    def resolve(key_ref: str) -> str:
        # Policy loading already constrains a reference to [A-Z_][A-Z0-9_]*, so
        # it cannot traverse. Canonicalize and re-check anyway: a key source
        # must never reach outside its own directory, including through a
        # symlink planted inside it.
        #
        # Containment is checked against the whole subtree rather than the
        # immediate parent, because a Kubernetes Secret or ConfigMap volume
        # projects each key as a symlink into a timestamped `..data` directory
        # inside the mount. Requiring the parent to be the mount itself would
        # reject every real projected key.
        path = (directory / key_ref).resolve()
        if not path.is_relative_to(directory):
            raise KeyError(key_ref)
        return path.read_text(encoding="utf-8").strip()

    return resolve


class JwksVerifier:
    """Verify JWTs against a JWKS snapshot refreshed outside request handling."""

    def __init__(self, settings: RuntimeSettings) -> None:
        self._config = settings.oidc
        self._jwks = jwt.PyJWKClient(
            settings.jwks_url,
            cache_keys=False,
            timeout=5,
            ssl_context=build_ssl_context(settings),
        )
        self._condition = Condition()
        self._keys: dict[str, jwt.PyJWK] = {}
        self._last_refresh = 0.0
        self._last_key_miss_refresh = float("-inf")
        self._refresh_in_progress = False

    def __call__(self, token: str) -> Mapping[str, object]:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "RS256":
            raise jwt.InvalidAlgorithmError("unsupported signing algorithm")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise jwt.InvalidTokenError("missing signing key id")
        signing_key = self._signing_key(kid)
        if signing_key is None:
            raise jwt.InvalidTokenError("unknown signing key id")
        claims: dict[str, Any] = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=self._config.audience,
            issuer=self._config.issuer,
            # `nbf` is deliberately absent: it is optional in RFC 7519 and many
            # providers omit it. PyJWT still enforces it whenever it is present.
            options={"require": ["exp", "iss", "aud", self._config.subject_claim]},
        )
        return claims

    def _fetch_keys(self) -> dict[str, jwt.PyJWK]:
        try:
            signing_keys = self._jwks.get_signing_keys(refresh=True)
            keys = {
                key.key_id: key
                for key in signing_keys
                if isinstance(key.key_id, str) and key.key_id
            }
            if not keys:
                raise RuntimeError("empty JWKS")
        except Exception as error:
            raise RuntimeError("JWKS unavailable") from error
        return keys

    def _complete_refresh(self, keys: dict[str, jwt.PyJWK] | None) -> None:
        with self._condition:
            if keys is not None:
                self._keys = keys
                self._last_refresh = time.monotonic()
            self._refresh_in_progress = False
            self._condition.notify_all()

    def _signing_key(self, kid: str) -> jwt.PyJWK | None:
        with self._condition:
            signing_key = self._keys.get(kid)
            if signing_key is not None:
                return signing_key
            if self._refresh_in_progress:
                self._condition.wait_for(
                    lambda: not self._refresh_in_progress,
                    timeout=_JWKS_REFRESH_WAIT_SECONDS,
                )
                return self._keys.get(kid)
            now = time.monotonic()
            if (
                now - self._last_key_miss_refresh
                < _JWKS_KEY_MISS_REFRESH_COOLDOWN_SECONDS
            ):
                return None
            self._last_key_miss_refresh = now
            self._refresh_in_progress = True

        keys: dict[str, jwt.PyJWK] | None = None
        try:
            keys = self._fetch_keys()
        except RuntimeError:
            _LOGGER.warning("JWKS key-miss refresh failed")
        finally:
            self._complete_refresh(keys)

        with self._condition:
            return self._keys.get(kid)

    def refresh(self) -> None:
        """Replace the local key snapshot after one serialized successful fetch."""
        with self._condition:
            if self._refresh_in_progress:
                completed = self._condition.wait_for(
                    lambda: not self._refresh_in_progress,
                    timeout=_JWKS_REFRESH_WAIT_SECONDS,
                )
                if not completed:
                    raise RuntimeError("JWKS refresh timed out")
                return
            self._refresh_in_progress = True

        keys: dict[str, jwt.PyJWK] | None = None
        try:
            keys = self._fetch_keys()
        finally:
            self._complete_refresh(keys)

    async def ensure_ready(self) -> None:
        """Fetch and validate the configured JWKS before serving traffic."""
        await asyncio.to_thread(self.refresh)

    async def refresh_forever(self) -> None:
        """Refresh signing keys periodically without putting network I/O on requests."""
        while True:
            await asyncio.sleep(_JWKS_REFRESH_SECONDS)
            try:
                await asyncio.to_thread(self.refresh)
            except RuntimeError:
                _LOGGER.exception("JWKS refresh failed")

    def is_ready(self) -> bool:
        with self._condition:
            return bool(self._keys) and (
                time.monotonic() - self._last_refresh <= _JWKS_STALE_SECONDS
            )


class FixedWindowRateLimiter:
    """Bound requests per identity, policy, and client IP in a process-local window."""

    def __init__(self, *, requests: int, window_seconds: int, max_keys: int) -> None:
        self._requests = requests
        self._window_seconds = window_seconds
        self._max_keys = max_keys
        self._lock = Lock()
        self._window: int | None = None
        self._counts: dict[RateLimitKey, int] = {}

    def __call__(self, key: RateLimitKey) -> bool:
        window = int(time.time() // self._window_seconds)
        with self._lock:
            if self._window != window:
                self._window = window
                self._counts.clear()
            count = self._counts.get(key, 0)
            if count >= self._requests:
                return False
            if count == 0 and len(self._counts) >= self._max_keys:
                return False
            self._counts[key] = count + 1
            return True


def create_runtime_app(
    settings: RuntimeSettings,
    *,
    token_verifier: TokenVerifier | None = None,
    rate_limiter: RateLimiter | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    key_resolver: KeyResolver | None = None,
) -> FastAPI:
    """Build the production ASGI app and non-sensitive liveness/readiness endpoints."""
    verifier = token_verifier or JwksVerifier(settings)
    policies = load_policies(settings.policies_json)
    required_keys = frozenset(policy.key_ref for policy in policies)
    resolve_key = key_resolver or build_key_resolver(settings)
    app = create_app(
        oidc_config=settings.oidc,
        token_verifier=verifier,
        policies_json=settings.policies_json,
        upstream_base_url=settings.upstream_base_url,
        trusted_upstream_hosts=settings.trusted_upstream_hosts,
        allow_cluster_local_plaintext_upstream=settings.allow_cluster_local_plaintext_upstream,
        key_resolver=resolve_key,
        rate_limiter=rate_limiter
        or FixedWindowRateLimiter(
            requests=settings.rate_limit_requests,
            window_seconds=settings.rate_limit_window_seconds,
            max_keys=settings.rate_limit_max_keys,
        ),
        transport=transport,
        ssl_context=build_ssl_context(settings),
    )

    if isinstance(verifier, JwksVerifier):
        refresh_task: asyncio.Task[None] | None = None

        async def start_jwks_refresh() -> None:
            nonlocal refresh_task
            await verifier.ensure_ready()
            refresh_task = asyncio.create_task(verifier.refresh_forever())

        async def stop_jwks_refresh() -> None:
            if refresh_task is not None:
                refresh_task.cancel()
                with suppress(asyncio.CancelledError):
                    await refresh_task

        app.router.on_startup.append(start_jwks_refresh)
        app.router.on_shutdown.append(stop_jwks_refresh)

    @app.get("/healthz")
    async def health() -> JSONResponse:
        return JSONResponse({"status": "ok"})

    def keys_are_resolvable() -> bool:
        """Every policy must have a usable key before the broker accepts traffic."""
        for name in required_keys:
            try:
                key = resolve_key(name)
            except Exception:
                return False
            if not isinstance(key, str) or not key:
                return False
        return True

    @app.get("/readyz")
    async def readiness() -> JSONResponse:
        verifier_ready = not isinstance(verifier, JwksVerifier) or verifier.is_ready()
        if not verifier_ready or not keys_are_resolvable():
            return JSONResponse({"status": "unavailable"}, status_code=503)
        return JSONResponse({"status": "ok"})

    return app


def _required(values: Mapping[str, str], name: str) -> str:
    value = values.get(name)
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"{name} must be configured")
    return value.strip()


def _csv(value: str) -> set[str]:
    return {item.strip() for item in value.split(",") if item.strip()}


def _claim_name(value: str, name: str) -> str:
    """Accept only a plain claim name, so it cannot smuggle in JWT decode options."""
    claim = value.strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", claim):
        raise RuntimeError(f"{name} must be a plain claim name")
    return claim


_ENTRA_HOST = "login.microsoftonline.com"


def _validate_jwks_url(issuer: str, jwks_url: str) -> None:
    """Require the JWKS endpoint to belong to the configured issuer.

    Signing keys decide whether a token is genuine, so the endpoint they come from
    must not be separately steerable. If it were, anything able to set one
    environment variable could point key discovery at a key set it controls and
    mint its own tokens. Tying the JWKS URL to the issuer removes that lever.

    Microsoft Entra keeps its stricter, exact rule because its discovery URL is a
    known constant rather than something a deployment may vary.
    """
    parsed_issuer = urlsplit(issuer)
    if (
        parsed_issuer.scheme != "https"
        or not parsed_issuer.netloc
        or parsed_issuer.query
        or parsed_issuer.fragment
    ):
        raise RuntimeError("GABRO_OIDC_ISSUER must be an https URL without query or fragment")

    if parsed_issuer.netloc == _ENTRA_HOST:
        _validate_entra_jwks_url(parsed_issuer, jwks_url)
        return

    parsed_jwks = urlsplit(jwks_url)
    if parsed_jwks.scheme != "https" or parsed_jwks.query or parsed_jwks.fragment:
        raise RuntimeError("GABRO_OIDC_JWKS_URL must be an https URL without query or fragment")
    if parsed_jwks.netloc != parsed_issuer.netloc:
        raise RuntimeError("GABRO_OIDC_JWKS_URL must have the same origin as GABRO_OIDC_ISSUER")
    issuer_path = parsed_issuer.path.rstrip("/")
    if issuer_path and not parsed_jwks.path.startswith(f"{issuer_path}/"):
        raise RuntimeError("GABRO_OIDC_JWKS_URL must be a path below GABRO_OIDC_ISSUER")


def _validate_entra_jwks_url(parsed_issuer: SplitResult, jwks_url: str) -> None:
    """Allow only the issuer tenant's canonical Entra v2 JWKS discovery URL."""
    issuer_parts = parsed_issuer.path.split("/")
    if len(issuer_parts) != 3 or not issuer_parts[1] or issuer_parts[2] != "v2.0":
        raise RuntimeError("GABRO_OIDC_ISSUER must be an Entra v2 issuer URL")
    expected = f"https://{_ENTRA_HOST}/{issuer_parts[1]}/discovery/v2.0/keys"
    if jwks_url != expected:
        raise RuntimeError(
            "GABRO_OIDC_JWKS_URL must be the configured issuer tenant's Entra discovery endpoint"
        )


def _boolean(value: str, name: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise RuntimeError(f"{name} must be exactly 'true' or 'false'")


def _positive_integer(value: str, name: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise RuntimeError(f"{name} must be a positive integer") from error
    if parsed <= 0:
        raise RuntimeError(f"{name} must be a positive integer")
    return parsed


def main() -> None:
    """Run the broker with the deployment-supplied configuration."""
    import uvicorn

    # The container network boundary controls service exposure.
    uvicorn.run(
        create_runtime_app(load_runtime_settings()), host="0.0.0.0", port=8080  # nosec B104
    )


if __name__ == "__main__":
    main()
