from __future__ import annotations

import pytest

from mcp_argocd import tools


class _Response:
    def __init__(self, status_code: int, text: str, body=None):
        self.status_code = status_code
        self.text = text
        self._body = body if body is not None else {}

    def json(self):
        return self._body


class _Client:
    def __init__(self, bearer: str, responses: list[_Response], calls: list[dict]):
        self._bearer = bearer
        self._responses = responses
        self._calls = calls

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def request(self, method: str, path: str, params=None, json=None):
        self._calls.append({
            "bearer": self._bearer,
            "method": method,
            "path": path,
            "params": params,
            "json": json,
        })
        return self._responses.pop(0)


def _wire(monkeypatch, responses: list[_Response]):
    bearers = iter(["stale-token", "fresh-token"])
    calls: list[dict] = []
    invalidated: list[str | None] = []

    monkeypatch.setattr(tools, "get_bearer", lambda: next(bearers))
    monkeypatch.setattr(tools, "invalidate_bearer", invalidated.append)
    monkeypatch.setattr(
        tools,
        "_client",
        lambda bearer: _Client(bearer, responses, calls),
    )
    return calls, invalidated


def test_get_invalidates_cached_bearer_and_retries_once_on_401(monkeypatch):
    calls, invalidated = _wire(
        monkeypatch,
        [
            _Response(401, "invalid session"),
            _Response(200, '{"items":[]}', {"items": []}),
        ],
    )

    assert tools._get("/api/v1/applications", params={"projects": "default"}) == {
        "items": []
    }
    assert invalidated == ["stale-token"]
    assert [call["bearer"] for call in calls] == ["stale-token", "fresh-token"]
    assert all(call["method"] == "GET" for call in calls)


def test_post_invalidates_cached_bearer_and_retries_once_on_401(monkeypatch):
    calls, invalidated = _wire(
        monkeypatch,
        [
            _Response(401, "invalid session"),
            _Response(201, '{"ok":true}', {"ok": True}),
        ],
    )

    assert tools._post("/api/v1/applications/demo/sync", {"dryRun": False}) == {
        "ok": True
    }
    assert invalidated == ["stale-token"]
    assert [call["bearer"] for call in calls] == ["stale-token", "fresh-token"]
    assert [call["method"] for call in calls] == ["POST", "POST"]


def test_auth_failure_after_retry_surfaces_error(monkeypatch):
    _calls, invalidated = _wire(
        monkeypatch,
        [
            _Response(401, "invalid session"),
            _Response(401, "still invalid"),
        ],
    )

    with pytest.raises(RuntimeError, match="ArgoCD GET /api/v1/applications -> 401"):
        tools._get("/api/v1/applications")

    assert invalidated == ["stale-token"]
