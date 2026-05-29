"""Read-only ArgoCD REST tools.

Defense in depth: tool surface is constrained to GET endpoints + the
`/sync` action. argocd-rbac-cm grants the MCP's SA exactly those verbs
(applications get/sync, projects get, repositories get, clusters get) — so
even if a tool wrapper were bypassed, the bearer can't write anything else.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

from .dex import ARGOCD_SERVER_URL, get_bearer, invalidate_bearer


_TIMEOUT_SECONDS = 30
_RETRYABLE_AUTH_STATUS = 401
logger = logging.getLogger(__name__)


def _clamp_limit(limit: int | None, *, default: int, maximum: int = 500) -> int:
    if limit is None:
        return default
    return max(1, min(int(limit), maximum))


def _app_summary(app: dict[str, Any]) -> dict[str, Any]:
    md = app.get("metadata", {})
    sp = app.get("spec", {})
    st = app.get("status", {})
    return {
        "name": md.get("name"),
        "namespace": md.get("namespace"),
        "project": sp.get("project"),
        "destination": sp.get("destination"),
        "source": sp.get("source"),
        "syncStatus": st.get("sync", {}).get("status"),
        "healthStatus": st.get("health", {}).get("status"),
        "revision": st.get("sync", {}).get("revision"),
        "conditions": st.get("conditions") or [],
        "operationState": st.get("operationState"),
    }


def _client(bearer: str) -> httpx.Client:
    return httpx.Client(
        base_url=ARGOCD_SERVER_URL,
        headers={"Authorization": f"Bearer {bearer}"},
        timeout=_TIMEOUT_SECONDS,
    )


def _request(
    method: str,
    path: str,
    *,
    ok: set[int],
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
) -> httpx.Response:
    bearer = get_bearer()
    for attempt in range(2):
        with _client(bearer) as c:
            resp = c.request(method, path, params=params, json=json_body)
        if resp.status_code != _RETRYABLE_AUTH_STATUS or attempt == 1:
            break
        logger.info(
            "ArgoCD %s %s returned 401; invalidating cached bearer and retrying once",
            method,
            path,
        )
        invalidate_bearer(bearer)
        bearer = get_bearer()

    if resp.status_code not in ok:
        raise RuntimeError(f"ArgoCD {method} {path} -> {resp.status_code} {resp.text}")
    return resp


def _get(path: str, params: dict[str, Any] | None = None) -> Any:
    return _request("GET", path, ok={200}, params=params).json()


def _post(path: str, json_body: dict[str, Any] | None = None) -> Any:
    resp = _request("POST", path, ok={200, 201}, json_body=json_body)
    return resp.json() if resp.text else {}


def register_tools(mcp: FastMCP) -> None:
    @mcp.tool()
    def list_applications(
        project: str | None = None,
        selector: str | None = None,
        name_contains: str | None = None,
        health_status: str | None = None,
        sync_status: str | None = None,
        limit: int | None = 100,
    ) -> list[dict[str, Any]]:
        """List ArgoCD Applications with sync status, health status, source, and revision.

        Use to find an app before checking resource trees, diffs, events, or
        triggering sync. `project` filters by AppProject;
        `selector` is a label selector ('app=foo,role=bar'). `name_contains`,
        `health_status`, `sync_status`, and `limit` further narrow output."""
        params: dict[str, Any] = {}
        if project:
            params["projects"] = project
        if selector:
            params["selector"] = selector
        body = _get("/api/v1/applications", params=params)
        out = []
        needle = name_contains.lower() if name_contains else None
        cap = _clamp_limit(limit, default=100)
        for app in body.get("items") or []:
            md = app.get("metadata", {})
            st = app.get("status", {})
            name = md.get("name")
            app_sync_status = st.get("sync", {}).get("status")
            app_health_status = st.get("health", {}).get("status")
            if needle and (not name or needle not in name.lower()):
                continue
            if health_status and app_health_status != health_status:
                continue
            if sync_status and app_sync_status != sync_status:
                continue
            out.append(_app_summary(app))
            if len(out) >= cap:
                break
        return out

    @mcp.tool()
    def get_application(name: str, include_raw: bool = False) -> dict[str, Any]:
        """Get one ArgoCD Application object including spec, status, health, sync, and operationState.

        Returns a compact summary by default. Set `include_raw=True` when you
        need the full Application object."""
        app = _get(f"/api/v1/applications/{name}")
        if include_raw:
            return app
        return _app_summary(app)

    @mcp.tool()
    def get_application_resource_tree(
        name: str,
        kind: str | None = None,
        name_contains: str | None = None,
        health_status: str | None = None,
        sync_status: str | None = None,
        include_raw: bool = False,
        limit: int | None = 100,
    ) -> dict[str, Any]:
        """Get the ArgoCD live Kubernetes resource tree for an Application.

        Returns compact nodes by default. Use filters to focus a large app,
        or set `include_raw=True` for ArgoCD's full response."""
        body = _get(f"/api/v1/applications/{name}/resource-tree")
        if include_raw:
            return body
        kind_needle = kind.lower() if kind else None
        name_needle = name_contains.lower() if name_contains else None
        cap = _clamp_limit(limit, default=100)
        rows: list[dict[str, Any]] = []
        for node in body.get("nodes") or []:
            node_kind = node.get("kind")
            node_name = node.get("name")
            node_health = node.get("health", {}).get("status")
            node_sync = node.get("status")
            if kind_needle and (not node_kind or kind_needle not in node_kind.lower()):
                continue
            if name_needle and (not node_name or name_needle not in node_name.lower()):
                continue
            if health_status and node_health != health_status:
                continue
            if sync_status and node_sync != sync_status:
                continue
            rows.append(
                {
                    "group": node.get("group"),
                    "kind": node_kind,
                    "namespace": node.get("namespace"),
                    "name": node_name,
                    "version": node.get("version"),
                    "healthStatus": node_health,
                    "syncStatus": node_sync,
                    "message": node.get("health", {}).get("message"),
                }
            )
            if len(rows) >= cap:
                break
        return {"application": name, "node_count": len(body.get("nodes") or []), "returned": len(rows), "nodes": rows}

    @mcp.tool()
    def get_application_managed_resources(
        name: str,
        kind: str | None = None,
        name_contains: str | None = None,
        include_raw: bool = False,
        limit: int | None = 100,
    ) -> dict[str, Any]:
        """Get ArgoCD managed resources and live-vs-target diffs for an Application.

        Returns compact resource metadata by default. Set `include_raw=True`
        when you need full live/target manifests or diff payloads."""
        body = _get(f"/api/v1/applications/{name}/managed-resources")
        if include_raw:
            return body
        kind_needle = kind.lower() if kind else None
        name_needle = name_contains.lower() if name_contains else None
        cap = _clamp_limit(limit, default=100)
        rows: list[dict[str, Any]] = []
        resources = body.get("items") or body.get("managedResources") or []
        for resource in resources:
            resource_kind = resource.get("kind")
            resource_name = resource.get("name")
            if kind_needle and (not resource_kind or kind_needle not in resource_kind.lower()):
                continue
            if name_needle and (not resource_name or name_needle not in resource_name.lower()):
                continue
            rows.append(
                {
                    "group": resource.get("group"),
                    "kind": resource_kind,
                    "namespace": resource.get("namespace"),
                    "name": resource_name,
                    "version": resource.get("version"),
                    "hook": resource.get("hook"),
                    "requiresPruning": resource.get("requiresPruning"),
                }
            )
            if len(rows) >= cap:
                break
        return {"application": name, "resource_count": len(resources), "returned": len(rows), "resources": rows}

    @mcp.tool()
    def get_application_events(name: str, reason_contains: str | None = None, message_contains: str | None = None, limit: int | None = 50) -> dict[str, Any]:
        """Get ArgoCD Application events for sync operations, health changes, and hooks.

        Return compact events ArgoCD has recorded for the Application. Use
        filters and `limit` to focus large event streams."""
        body = _get(f"/api/v1/applications/{name}/events")
        reason_needle = reason_contains.lower() if reason_contains else None
        message_needle = message_contains.lower() if message_contains else None
        cap = _clamp_limit(limit, default=50)
        rows: list[dict[str, Any]] = []
        events = body.get("items") or []
        for event in events:
            reason = event.get("reason")
            message = event.get("message")
            if reason_needle and (not reason or reason_needle not in reason.lower()):
                continue
            if message_needle and (not message or message_needle not in message.lower()):
                continue
            rows.append(
                {
                    "namespace": event.get("metadata", {}).get("namespace"),
                    "name": event.get("metadata", {}).get("name"),
                    "type": event.get("type"),
                    "reason": reason,
                    "message": message,
                    "count": event.get("count"),
                    "firstTimestamp": event.get("firstTimestamp"),
                    "lastTimestamp": event.get("lastTimestamp"),
                    "involvedObject": event.get("involvedObject"),
                }
            )
            if len(rows) >= cap:
                break
        return {"application": name, "event_count": len(events), "returned": len(rows), "events": rows}

    @mcp.tool()
    def sync_application(
        name: str,
        revision: str | None = None,
        prune: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Sync an ArgoCD Application to its target revision, optionally dry-run or prune.

        Trigger an ArgoCD sync. revision defaults to the Application's
        configured targetRevision. dry_run=True returns the diff without
        applying. prune=True deletes resources removed from git — leave
        False unless you specifically want a destructive sync."""
        body: dict[str, Any] = {"prune": prune, "dryRun": dry_run}
        if revision:
            body["revision"] = revision
        return _post(f"/api/v1/applications/{name}/sync", json_body=body)

    @mcp.tool()
    def list_projects(name_contains: str | None = None, limit: int | None = 100) -> list[dict[str, Any]]:
        """List ArgoCD AppProjects with source repository and destination permissions.

        `name_contains` filters project names client-side and `limit` caps
        returned rows.
        """
        body = _get("/api/v1/projects")
        rows: list[dict[str, Any]] = []
        needle = name_contains.lower() if name_contains else None
        cap = _clamp_limit(limit, default=100)
        for p in body.get("items") or []:
            name = p.get("metadata", {}).get("name")
            if needle and (not name or needle not in name.lower()):
                continue
            rows.append(
                {
                    "name": name,
                    "description": p.get("spec", {}).get("description"),
                    "sourceRepos": p.get("spec", {}).get("sourceRepos"),
                    "destinations": p.get("spec", {}).get("destinations"),
                }
            )
            if len(rows) >= cap:
                break
        return rows

    @mcp.tool()
    def list_repositories(
        repo_contains: str | None = None,
        name_contains: str | None = None,
        type: str | None = None,
        connection_status: str | None = None,
        limit: int | None = 100,
    ) -> list[dict[str, Any]]:
        """List Git repositories and Helm repositories configured in ArgoCD, optionally filtered.

        Connection state included so you
        can spot a repo whose creds rotted. `repo_contains`, `name_contains`,
        `type`, `connection_status`, and `limit` narrow large installations."""
        body = _get("/api/v1/repositories")
        rows: list[dict[str, Any]] = []
        repo_needle = repo_contains.lower() if repo_contains else None
        name_needle = name_contains.lower() if name_contains else None
        cap = _clamp_limit(limit, default=100)
        for r in body.get("items") or []:
            repo = r.get("repo")
            name = r.get("name")
            status = r.get("connectionState", {}).get("status")
            if repo_needle and (not repo or repo_needle not in repo.lower()):
                continue
            if name_needle and (not name or name_needle not in name.lower()):
                continue
            if type and r.get("type") != type:
                continue
            if connection_status and status != connection_status:
                continue
            rows.append(
                {
                    "repo": repo,
                    "type": r.get("type"),
                    "name": name,
                    "connectionState": status,
                    "connectionMessage": r.get("connectionState", {}).get("message"),
                }
            )
            if len(rows) >= cap:
                break
        return rows

    @mcp.tool()
    def list_clusters(
        name_contains: str | None = None,
        server_contains: str | None = None,
        connection_status: str | None = None,
        limit: int | None = 100,
    ) -> list[dict[str, Any]]:
        """List Kubernetes clusters registered in ArgoCD, optionally filtered.

        In-cluster (kubernetes.default.svc)
        is always present; remote clusters appear here once registered.
        `name_contains`, `server_contains`, `connection_status`, and `limit`
        narrow large cluster lists."""
        body = _get("/api/v1/clusters")
        rows: list[dict[str, Any]] = []
        name_needle = name_contains.lower() if name_contains else None
        server_needle = server_contains.lower() if server_contains else None
        cap = _clamp_limit(limit, default=100)
        for c in body.get("items") or []:
            name = c.get("name")
            server = c.get("server")
            status = c.get("connectionState", {}).get("status")
            if name_needle and (not name or name_needle not in name.lower()):
                continue
            if server_needle and (not server or server_needle not in server.lower()):
                continue
            if connection_status and status != connection_status:
                continue
            rows.append(
                {
                    "name": name,
                    "server": server,
                    "connectionState": status,
                    "serverVersion": c.get("serverVersion"),
                }
            )
            if len(rows) >= cap:
                break
        return rows

    @mcp.tool()
    def server_version() -> dict[str, Any]:
        """Get ArgoCD server version information.

        Handy when comparing API
        behaviour across upgrades."""
        return _get("/api/version")
