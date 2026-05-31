# mcp-argocd

ArgoCD MCP server for Tank sessions.

## Layout

- `src/` - Python MCP server package.
- `Dockerfile` - image build for `romainecr.azurecr.io/mcp-argocd`.
- `chart/` - Helm chart synced by ArgoCD.

Images are SHA-tagged from `main`; `.github/workflows/build.yml` pushes the image and commits the matching chart tag.

## Auth

- **Inbound** (callers → this server): kube-rbac-proxy validates the caller's K8s SA token via TokenReview/SubjectAccessReview; when an `Authorization` JWT is present it is additionally verified as an auth.romaine.life token (`romaine-auth`), binding the resolved `Caller` for audit.
- **Outbound** (this server → ArgoCD): the pod's projected SA token (audience `https://auth.romaine.life`) is exchanged at `auth.romaine.life/api/auth/exchange/k8s` for a `role=service` JWT (`sub=svc:mcp-argocd:mcp-argocd`), which is presented directly to the ArgoCD API. argocd-server verifies it against the auth.romaine.life JWKS (its `oidc.config` provider) and maps the subject to `role:mcp-argocd` in `argocd-rbac-cm`. No Dex, no token-exchange, no static API token. See `src/mcp_argocd/auth_exchange.py`.
