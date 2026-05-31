"""ArgoCD bearer-token provider via the auth.romaine.life k8s exchange.

The pod has a projected SA token at SA_TOKEN_PATH with audience
``https://auth.romaine.life``. We POST it to auth.romaine.life's
``/api/auth/exchange/k8s`` endpoint, which validates the token against the AKS
OIDC issuer's JWKS and the (namespace, serviceAccount) allowlist, then mints a
``role=service`` auth.romaine.life JWT with a stable
``sub=svc:mcp-argocd:mcp-argocd``.

That JWT is presented directly to the ArgoCD API. argocd-server's
sessionmanager verifies any bearer whose ``iss`` isn't ``"argocd"`` against the
configured OIDC provider's JWKS (oidc.config → auth.romaine.life), and
argocd-rbac-cm maps the stable ``sub`` to ``role:mcp-argocd``. No Dex, no
token-exchange, no static API token — the same auth.romaine.life identity every
other romaine.life service uses.

Bearers are cached in-memory until within REFRESH_LEEWAY_SECONDS of expiry.
This avoids an exchange round-trip per tool call while keeping the credential
window short — the cache lives only while the pod is alive.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import threading
import time
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)


SA_TOKEN_PATH = os.environ.get(
    "AUTH_SA_TOKEN_PATH",
    "/var/run/secrets/auth-romaine/token",
)
AUTH_EXCHANGE_URL = os.environ.get(
    "AUTH_EXCHANGE_URL",
    "https://auth.romaine.life/api/auth/exchange/k8s",
)
ARGOCD_SERVER_URL = os.environ.get(
    "ARGOCD_SERVER_URL",
    "http://argocd-server.argocd",
)

# Re-fetch when within this many seconds of expiry. auth.romaine.life service
# tokens are short-lived (~15 min); refreshing at 5 minutes left keeps
# long-running tool calls from tripping over an expiry mid-flight.
REFRESH_LEEWAY_SECONDS = 300


@dataclass
class _CachedToken:
    bearer: str
    expires_at: float  # epoch seconds


def _read_sa_token() -> str:
    with open(SA_TOKEN_PATH, "r") as f:
        return f.read().strip()


def _decode_jwt_exp(token: str) -> float:
    """Pull ``exp`` (epoch seconds) out of a JWT payload without verifying.

    Only used as a fallback when the exchange response omits ``expires_at``.
    Verification isn't our job — auth.romaine.life signed it, and ArgoCD
    re-verifies it against the JWKS on every call.
    """
    payload_b64 = token.split(".")[1]
    payload_b64 += "=" * (-len(payload_b64) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    return float(payload["exp"])


class AuthExchangeTokenProvider:
    """Thread-safe bearer cache.

    Multiple FastMCP tool invocations can land concurrently; the lock keeps
    them from stampeding on the exchange when the cache is cold or stale.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cached: _CachedToken | None = None

    def get(self) -> str:
        with self._lock:
            now = time.time()
            if self._cached and self._cached.expires_at - now > REFRESH_LEEWAY_SECONDS:
                return self._cached.bearer
            self._cached = self._exchange()
            return self._cached.bearer

    def invalidate(self, bearer: str | None = None) -> None:
        """Clear the cached bearer.

        If ``bearer`` is provided, only clear when the cached token is still
        that exact value. That avoids one request invalidating a newer token
        another request already exchanged after seeing the same 401.
        """
        with self._lock:
            if self._cached is None:
                return
            if bearer is not None and self._cached.bearer != bearer:
                return
            self._cached = None

    def _exchange(self) -> _CachedToken:
        sa_token = _read_sa_token()
        resp = httpx.post(
            AUTH_EXCHANGE_URL,
            headers={"Authorization": f"Bearer {sa_token}"},
            timeout=10.0,
        )
        if resp.status_code != 200:
            raise RuntimeError(
                f"auth.romaine.life k8s exchange failed: "
                f"HTTP {resp.status_code} {resp.text}"
            )
        body = resp.json()
        bearer = body.get("token")
        if not bearer:
            raise RuntimeError(
                f"auth.romaine.life k8s exchange returned no token: {body}"
            )
        expires_at = body.get("expires_at")
        expires_at = float(expires_at) if expires_at is not None else _decode_jwt_exp(bearer)
        logger.info(
            "exchanged SA token for auth.romaine.life service token; expires in %ds",
            int(expires_at - time.time()),
        )
        return _CachedToken(bearer=bearer, expires_at=expires_at)


_provider = AuthExchangeTokenProvider()


def get_bearer() -> str:
    return _provider.get()


def invalidate_bearer(bearer: str | None = None) -> None:
    _provider.invalidate(bearer)
