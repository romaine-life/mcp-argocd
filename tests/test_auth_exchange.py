from __future__ import annotations

import base64
import json

import pytest

from mcp_argocd import auth_exchange
from mcp_argocd.auth_exchange import AuthExchangeTokenProvider, REFRESH_LEEWAY_SECONDS


class _Response:
    def __init__(self, status_code: int, body: dict | None = None, text: str = ""):
        self.status_code = status_code
        self._body = body if body is not None else {}
        self.text = text

    def json(self):
        return self._body


def _wire(monkeypatch, responses: list[_Response], *, sa_token: str = "sa-token"):
    """Stub the SA-token read and httpx.post; record exchange calls."""
    calls: list[dict] = []

    def fake_post(url, headers=None, timeout=None):
        calls.append({"url": url, "headers": headers})
        return responses.pop(0)

    monkeypatch.setattr(auth_exchange, "_read_sa_token", lambda: sa_token)
    monkeypatch.setattr(auth_exchange.httpx, "post", fake_post)
    return calls


def _jwt_with_exp(exp: int) -> str:
    payload = base64.urlsafe_b64encode(json.dumps({"exp": exp}).encode()).rstrip(b"=").decode()
    return f"header.{payload}.sig"


def test_exchange_posts_sa_token_and_returns_service_jwt(monkeypatch):
    calls = _wire(
        monkeypatch,
        [_Response(200, {"token": "svc-jwt", "expires_at": 9_999_999_999})],
        sa_token="projected-sa",
    )
    provider = AuthExchangeTokenProvider()
    assert provider.get() == "svc-jwt"
    assert len(calls) == 1
    assert calls[0]["url"] == auth_exchange.AUTH_EXCHANGE_URL
    assert calls[0]["headers"]["Authorization"] == "Bearer projected-sa"


def test_caches_within_refresh_leeway(monkeypatch):
    calls = _wire(
        monkeypatch,
        [_Response(200, {"token": "svc-jwt", "expires_at": 9_999_999_999})],
    )
    provider = AuthExchangeTokenProvider()
    assert provider.get() == "svc-jwt"
    assert provider.get() == "svc-jwt"  # served from cache, no second exchange
    assert len(calls) == 1


def test_reexchanges_when_near_expiry(monkeypatch):
    import time

    soon = int(time.time()) + REFRESH_LEEWAY_SECONDS - 10  # inside the leeway window
    calls = _wire(
        monkeypatch,
        [
            _Response(200, {"token": "first", "expires_at": soon}),
            _Response(200, {"token": "second", "expires_at": 9_999_999_999}),
        ],
    )
    provider = AuthExchangeTokenProvider()
    assert provider.get() == "first"
    assert provider.get() == "second"  # near-expiry → re-exchanged
    assert len(calls) == 2


def test_invalidate_only_clears_matching_bearer(monkeypatch):
    calls = _wire(
        monkeypatch,
        [
            _Response(200, {"token": "current", "expires_at": 9_999_999_999}),
            _Response(200, {"token": "next", "expires_at": 9_999_999_999}),
        ],
    )
    provider = AuthExchangeTokenProvider()
    assert provider.get() == "current"
    provider.invalidate("some-other-stale-token")  # no-op: doesn't match cache
    assert provider.get() == "current"
    assert len(calls) == 1
    provider.invalidate("current")  # clears the cache
    assert provider.get() == "next"
    assert len(calls) == 2


def test_non_200_raises(monkeypatch):
    _wire(monkeypatch, [_Response(403, text="namespace/sa not allowlisted")])
    provider = AuthExchangeTokenProvider()
    with pytest.raises(RuntimeError, match="k8s exchange failed: HTTP 403"):
        provider.get()


def test_missing_token_in_body_raises(monkeypatch):
    _wire(monkeypatch, [_Response(200, {"expires_at": 9_999_999_999})])
    provider = AuthExchangeTokenProvider()
    with pytest.raises(RuntimeError, match="returned no token"):
        provider.get()


def test_falls_back_to_jwt_exp_when_expires_at_absent(monkeypatch):
    import time

    exp = int(time.time()) + 3600
    _wire(monkeypatch, [_Response(200, {"token": _jwt_with_exp(exp)})])
    provider = AuthExchangeTokenProvider()
    # Should not raise — exp is decoded from the JWT payload as the fallback.
    assert provider.get() == _jwt_with_exp(exp)
