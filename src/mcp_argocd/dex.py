"""ArgoCD bearer-token provider using Dex token-exchange.

The pod has a projected SA token at SA_TOKEN_PATH with audience matching the
`argocd-mcp` Dex static client. We POST that to ArgoCD's Dex
/api/dex/token endpoint with grant_type=token-exchange and connector_id=aks-sa
(see infra-bootstrap k8s/argocd/values.yaml). Dex validates the token's
signature against the AKS OIDC issuer's JWKS and issues an ArgoCD bearer
whose `sub` resolves to the SA's RBAC subject in argocd-rbac-cm.

Bearers are cached in-memory until they are within REFRESH_LEEWAY_SECONDS of
expiry. This avoids a token-exchange round-trip per tool call but still keeps
the credential window short — the cache survives only while the pod is alive,
and an exec into the pod can't lift a long-lived token from disk.
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
    "ARGOCD_DEX_SA_TOKEN_PATH",
    "/var/run/secrets/argocd-dex/token",
)
ARGOCD_SERVER_URL = os.environ.get(
    "ARGOCD_SERVER_URL",
    "http://argocd-server.argocd",
)
DEX_CONNECTOR_ID = os.environ.get("ARGOCD_DEX_CONNECTOR_ID", "aks-sa")
DEX_CLIENT_ID = os.environ.get("ARGOCD_DEX_CLIENT_ID", "argo-cd-cli")

# Re-fetch when within this many seconds of expiry. Dex hands out 24-hour
# tokens; refreshing at 5 minutes left keeps long-running tool calls from
# tripping over an expiry mid-flight.
REFRESH_LEEWAY_SECONDS = 300


@dataclass
class _CachedToken:
    bearer: str
    expires_at: float  # epoch seconds


def _read_sa_token() -> str:
    with open(SA_TOKEN_PATH, "r") as f:
        return f.read().strip()


def _decode_jwt_exp(token: str) -> float:
    """Pull `exp` (epoch seconds) out of a JWT payload without verifying.

    Verification isn't our job — Dex did it before issuing the bearer. We
    only need `exp` to drive the cache.
    """
    payload_b64 = token.split(".")[1]
    payload_b64 += "=" * (-len(payload_b64) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    return float(payload["exp"])


class DexTokenProvider:
    """Thread-safe bearer cache.

    Multiple FastMCP tool invocations can land concurrently; the lock keeps
    them from stampeding on token-exchange when the cache is cold or stale.
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

    def _exchange(self) -> _CachedToken:
        sa_token = _read_sa_token()
        resp = httpx.post(
            f"{ARGOCD_SERVER_URL}/api/dex/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_id": DEX_CLIENT_ID,
                "subject_token": sa_token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                "connector_id": DEX_CONNECTOR_ID,
                "scope": "openid",
            },
            timeout=10.0,
        )
        if resp.status_code != 200:
            raise RuntimeError(
                f"Dex token-exchange failed: HTTP {resp.status_code} {resp.text}"
            )
        body = resp.json()
        bearer = body.get("access_token")
        if not bearer:
            raise RuntimeError(f"Dex token-exchange returned no access_token: {body}")
        expires_at = _decode_jwt_exp(bearer)
        logger.info(
            "exchanged SA token for ArgoCD bearer; expires in %ds",
            int(expires_at - time.time()),
        )
        return _CachedToken(bearer=bearer, expires_at=expires_at)


_provider = DexTokenProvider()


def get_bearer() -> str:
    return _provider.get()
