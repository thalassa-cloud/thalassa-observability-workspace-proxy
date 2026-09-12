# Observability Workspace Proxy

HTTP reverse proxy that authenticates to [Thalassa Cloud Observability](https://docs.thalassa.cloud/docs/observability/) workspaces from Kubernetes **without long-lived client secrets**.

It reads a projected Kubernetes service account JWT, exchanges it for a Thalassa bearer token via [Workload Identity Federation](https://docs.thalassa.cloud/docs/iam/oidc/), and injects that token on egress to workspace gateways (Prometheus remote write/query, Loki push/query, OTLP, etc.). The proxy is protocol-agnostic: request paths and bodies are forwarded unchanged.

## Architecture

```text
Collector / Grafana  -->  Proxy (this binary)  -->  Workspace gateway
                              |
                              +--> POST /oidc/token (K8s JWT -> Thalassa bearer)
```

| Mode | Listen | Inbound auth | Typical use |
|------|--------|--------------|-------------|
| Sidecar | `127.0.0.1:8080` | `none` | Co-located with Prometheus/Alloy/Promtail |
| Shared | `:8080` (+ TLS recommended) | `tokenreview` or `rbac` | Central proxy Service for many clients |

Outbound WIF auth is always enabled. Inbound auth is optional and kube-rbac-proxy–style when set to `rbac` (TokenReview + SubjectAccessReview).

## Quick start (local binary)

```bash
make build

./bin/thalassa-observability-workspace-proxy \
  --listen-address=127.0.0.1:8080 \
  --upstream=https://prometheus.nl-01.thalassa.cloud \
  --organisation-id="$THALASSA_ORGANISATION_ID" \
  --service-account-id="$THALASSA_SERVICE_ACCOUNT_ID" \
  --subject-token-file=/var/run/secrets/thalassa/token \
  --inbound-auth=none
```

Point remote write at the proxy (no oauth2 client secret):

```yaml
remote_write:
  - url: http://127.0.0.1:8080/workspace/obsw-<id>/api/v1/push
```

Loki / PromQL / OTLP work the same way: use the proxy as the host and keep the workspace path from the console or API.

## WIF bootstrap

Register the Kubernetes service account that mounts the projected token:

```bash
tcloud iam workload-identity-federation bootstrap kubernetes \
  --cluster "$CLUSTER_ID" \
  --namespace <kube-namespace> \
  --service-account <kube-sa-name> \
  --role <observability-role>
```

Use the resulting Thalassa service account ID for `--service-account-id`. Project the token with audience `https://api.thalassa.cloud` (see [examples/sidecar-pod.yaml](examples/sidecar-pod.yaml)).

## Configuration

Flags and matching environment variables:

| Flag | Env | Description |
|------|-----|-------------|
| `--listen-address` | `LISTEN_ADDRESS` | Proxy listen address (default `127.0.0.1:8080`) |
| `--upstream` | `UPSTREAM` | Gateway base URL only (no path), e.g. `https://prometheus.nl-01.thalassa.cloud` |
| `--thalassa-api-url` | `THALASSA_API_URL` | Default `https://api.thalassa.cloud` |
| `--organisation-id` | `THALASSA_ORGANISATION_ID` | Required |
| `--service-account-id` | `THALASSA_SERVICE_ACCOUNT_ID` | Required Thalassa SA to impersonate |
| `--subject-token-file` | `THALASSA_SUBJECT_TOKEN_FILE` | Projected K8s JWT path |
| `--inbound-auth` | `INBOUND_AUTH` | `none` \| `tokenreview` \| `rbac` |
| `--auth-audience` | `AUTH_AUDIENCE` | Required when inbound auth ≠ `none` |
| `--rbac-resource` / `--rbac-verb` / … | `RBAC_*` | SAR attributes when `inbound-auth=rbac` |
| `--tls-cert-file` / `--tls-key-file` | `TLS_*` | Optional serve TLS |
| `--metrics-address` | `METRICS_ADDRESS` | Prometheus metrics (default `127.0.0.1:9090`) |

Security behaviour:

- Client `Authorization` headers are stripped before upstream; only the Thalassa bearer is sent.
- Tokens and Authorization values are never logged.
- Missing token file, exchange failure, or inbound auth failure fails closed (401/403/502).
- Upstream is a single configured host (not an open proxy).

Probes: `GET /healthz` (liveness), `GET /readyz` (ready when a cached Thalassa token is available). Metrics: `GET /metrics` on `--metrics-address`.

## Helm (shared proxy)

From a release tag (OCI):

```bash
helm upgrade --install observability-workspace-proxy \
  oci://ghcr.io/thalassa-cloud/charts/observability-workspace-proxy --version v0.1.0 \
  --namespace observability --create-namespace \
  --set proxy.upstream=https://prometheus.nl-01.thalassa.cloud \
  --set proxy.organisationId="$THALASSA_ORGANISATION_ID" \
  --set proxy.serviceAccountId="$THALASSA_SERVICE_ACCOUNT_ID" \
  --set proxy.authAudience=https://observability-workspace-proxy.observability.svc \
  --set clientAccess.subjects[0].kind=ServiceAccount \
  --set clientAccess.subjects[0].name=prometheus \
  --set clientAccess.subjects[0].namespace=monitoring \
  --set networkPolicy.allowFromNamespaces[0]=monitoring
```

From this repository:

```bash
helm upgrade --install observability-workspace-proxy ./chart/observability-workspace-proxy \
  --namespace observability --create-namespace \
  --set proxy.upstream=https://prometheus.nl-01.thalassa.cloud \
  --set proxy.organisationId="$THALASSA_ORGANISATION_ID" \
  --set proxy.serviceAccountId="$THALASSA_SERVICE_ACCOUNT_ID"
```

Sidecar-oriented defaults: [`values-sidecar.yaml`](chart/observability-workspace-proxy/values-sidecar.yaml). Full sidecar Pod example: [`examples/sidecar-pod.yaml`](examples/sidecar-pod.yaml).

For shared + `rbac`, clients must send a Kubernetes Bearer token (audience = `--auth-audience`) and hold the client Role that matches `--rbac-resource` / `--rbac-verb`.

## Development

```bash
make test
make lint
make build
```

Local image (dev only; releases use GoReleaser + `Dockerfile.goreleaser`):

```bash
make docker-build
```

## Release

Push a semver tag (`v*`). GitHub Actions runs GoReleaser (multi-arch image to `ghcr.io/thalassa-cloud/thalassa-observability-workspace-proxy`, cosign, SBOMs) and publishes the Helm chart to `oci://ghcr.io/thalassa-cloud/charts/observability-workspace-proxy`.
