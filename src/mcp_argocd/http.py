"""HTTP entrypoint — streamable-http transport, no incoming auth.

Auth is handled by kube-rbac-proxy in front of this process: clients present
a K8s SA token, the proxy validates it via TokenReview + SubjectAccessReview
(see ../../../k8s-mcp-argocd/templates/proxy-config.yaml). Only authorized
requests reach this server, so it binds loopback to keep direct pod-IP:8080
access from bypassing the gate.

Outbound auth (to ArgoCD) is the inverse: we mint a fresh ArgoCD bearer per
session via Dex token-exchange against our projected SA token. See dex.py.
"""

import logging
import os
from contextlib import asynccontextmanager

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Mount, Route

from .tools import register_tools


def build_app() -> Starlette:
    # Same DNS-rebinding-protection workaround as the other MCPs in this
    # repo: the streamable_http transport ships a middleware that 421s any
    # Host header not in `allowed_hosts`. The default whitelist only covers
    # localhost, so in-cluster requests to mcp-argocd.mcp-argocd.svc would
    # be rejected. kube-rbac-proxy in front already gates auth, so DNS
    # rebinding can't reach an unauthorized caller anyway.
    mcp = FastMCP(
        "argocd-mcp",
        stateless_http=True,
        streamable_http_path="/",
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=False,
        ),
    )
    register_tools(mcp)

    async def healthz(_: Request) -> Response:
        return Response("ok", media_type="text/plain")

    @asynccontextmanager
    async def lifespan(_app: Starlette):
        async with mcp.session_manager.run():
            yield

    return Starlette(
        routes=[
            Route("/healthz", healthz),
            Mount("/", app=mcp.streamable_http_app()),
        ],
        lifespan=lifespan,
    )


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    import uvicorn

    port = int(os.environ.get("PORT", "8080"))
    uvicorn.run(build_app(), host="127.0.0.1", port=port)


if __name__ == "__main__":
    main()
