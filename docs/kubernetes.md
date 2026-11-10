# Kubernetes

dbgateway has a Helm chart in [deploy/helm/dbgateway](../deploy/helm/dbgateway/). It runs the release image (`ghcr.io/kyosu-1/dbgateway`) with a hardened pod, renders the configuration from your values, and refuses value combinations that would fail at startup or lose data. The full list of values is in the [chart's README](../deploy/helm/dbgateway/README.md).

The chart is not published to a chart repository yet; install it from a checkout of the repository:

```sh
git clone https://github.com/kyosu-1/dbgateway.git
helm install dbgateway dbgateway/deploy/helm/dbgateway \
  --namespace dbgateway --create-namespace -f my-values.yaml
```

## How the chart is put together

- **Configuration.** The `config:` value is the [configuration file](./configuration), written as YAML. The chart renders it into a ConfigMap mounted at `/etc/dbgateway/dbgateway.yaml`, and changing it rolls the pods. You can instead keep the file in your own ConfigMap (`existingConfigMap`).
- **Secrets.** The configuration only names environment variables (`*_env` keys). Put the values in Kubernetes Secrets you manage (or with External Secrets, Sealed Secrets, a CSI driver...) and load them with `envFrom` or `env`. Nothing secret is ever rendered into the ConfigMap.
- **HTTPS.** dbgateway serves plain HTTP on port 8443. TLS is terminated by the Ingress or a load balancer, and `server.public_url` must be the URL people and agents use. With the Ingress enabled, `public_url` defaults to `https://<first host>`, and the chart refuses a `public_url` whose host is not one of the Ingress hosts.
- **Pod security.** Non-root user, read-only root file system, all capabilities dropped, `RuntimeDefault` seccomp profile, no Kubernetes API token. Probes use `GET /healthz`.

## Single instance

The default: the SQLite management database and the audit log files live on a PersistentVolumeClaim mounted at `/var/lib/dbgateway`. The Deployment always runs one pod with the `Recreate` strategy, so an upgrade has a short gap while the new pod starts.

Create the Secret with the database passwords:

```sh
kubectl create namespace dbgateway
kubectl -n dbgateway create secret generic dbgateway-secrets \
  --from-literal=DBGW_APP_READER_PASSWORD=... \
  --from-literal=DBGW_APP_WRITER_PASSWORD=...
```

`my-values.yaml`:

```yaml
config:
  server:
    public_url: https://dbgateway.example.com
  auth:
    passkeys: true                  # or auth.oidc with your IdP
  databases:
    - name: app
      labels: { env: prod }
      primary:
        host: postgres.databases.svc.cluster.local
        dbname: app
        read_user: dbgw_reader
        password_env: DBGW_APP_READER_PASSWORD
        write_user: dbgw_writer
        write_password_env: DBGW_APP_WRITER_PASSWORD
  groups:
    - { name: sre, members: [sre@example.com] }
  role_bindings:
    - { group: sre, databases: "*", roles: [querier, writer, approver] }
  approvals:
    enabled: true
  approval_rules:
    - { name: default, when: "true", steps: [{ role: approver }] }

envFrom:
  - secretRef:
      name: dbgateway-secrets

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt
  hosts:
    - host: dbgateway.example.com
      paths: [{ path: /, pathType: Prefix }]
  tls:
    - secretName: dbgateway-tls
      hosts: [dbgateway.example.com]
```

Check the configuration, then install:

```sh
helm template dbgateway deploy/helm/dbgateway -f my-values.yaml --show-only templates/configmap.yaml
dbgw config validate --config dbgateway.yaml   # the dbgateway.yaml from the ConfigMap
helm install dbgateway deploy/helm/dbgateway -n dbgateway -f my-values.yaml
```

Without an IdP, create the first passkey enrollment link inside the pod:

```sh
kubectl -n dbgateway exec deployment/dbgateway -- \
  dbgw passkey enroll --config /etc/dbgateway/dbgateway.yaml --email sre@example.com
```

## Multiple instances

For several replicas, use a PostgreSQL management database and audit log ([High availability](./ha)): tokens, sessions and approvals are shared, approved writes run exactly once, and all pods write one audit hash chain. The chart refuses `replicaCount > 1` with the SQLite store, with `audit.output: file`, or with the persistent volume.

```yaml
replicaCount: 3

config:
  auth:
    oidc:
      issuer: https://idp.example.com
      client_id_env: DBGW_OIDC_CLIENT_ID
      client_secret_env: DBGW_OIDC_CLIENT_SECRET
  store:
    driver: postgres
    path: null                       # drop the SQLite default
    dsn_env: DBGW_STORE_DSN
  audit:
    output: postgres
    dir: null
  # databases, groups, role_bindings, policies...

persistence:
  enabled: false

envFrom:
  - secretRef:
      name: dbgateway-secrets        # DBGW_OIDC_CLIENT_*, DBGW_STORE_DSN, database passwords

topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: ScheduleAnyway
    labelSelector:
      matchLabels: { app.kubernetes.io/name: dbgateway, app.kubernetes.io/instance: dbgateway }
```

The Deployment then uses a rolling update (one new pod at a time, none removed before it is ready) and a PodDisruptionBudget allows one pod down at a time. During a rollout, pods run different configuration versions for a moment, as described in [High availability](./ha#_1-1-configuration).

## Audit log storage

| `audit.output` | Where the chart keeps it |
| --- | --- |
| `file` (default) | Files under `/var/lib/dbgateway/audit` on the PersistentVolumeClaim. Single instance only. Archive and verify them as described in [Operations](./operations#_3-audit-log-retention-and-verification) |
| `postgres` | The management database; nothing on the pod's disk. Required for several replicas |
| `stdout` | The container log; collect it with your log pipeline |

With `persistence.enabled: false` the directory is an `emptyDir`, so audit files would be lost with the pod; the chart only allows that for a single instance, and its notes warn about it.

## Metrics

```yaml
metrics:
  enabled: true
  serviceMonitor:
    enabled: true                   # needs the Prometheus Operator CRDs
    labels: { release: prometheus }
networkPolicy:
  enabled: true
  ingressFrom:
    - namespaceSelector:
        matchLabels: { kubernetes.io/metadata.name: ingress-nginx }
  metricsFrom:
    - namespaceSelector:
        matchLabels: { kubernetes.io/metadata.name: monitoring }
```

`metrics.enabled` sets `server.metrics_listen` to `0.0.0.0:9090` and adds a separate `<release>-metrics` ClusterIP Service. The Ingress only routes to the main Service, so `/metrics` (which has no authentication) is never exposed through it; use the NetworkPolicy to limit who inside the cluster can scrape it. dbgateway logs a warning that the metrics listener is not on loopback; that is expected here. See [Operations](./operations#_6-metrics) for the metrics and example alerts.

## IAM database authentication

`auth: aws_iam` and `auth: gcp_iam` use the pod's cloud identity. Annotate the ServiceAccount:

```yaml
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::<account>:role/dbgateway       # EKS (IRSA)
    # iam.gke.io/gcp-service-account: dbgateway@<project>.iam.gserviceaccount.com  # GKE Workload Identity
```

The Kubernetes API token stays unmounted (`automountServiceAccountToken: false`); IRSA and EKS Pod Identity inject their own token volume, and GKE Workload Identity uses the metadata server.

## Other settings

- **CA certificates.** Use `sslrootcert_env` with a variable from a Secret, or mount a ConfigMap or Secret with `extraVolumes` / `extraVolumeMounts` and point `sslrootcert` at the file.
- **Streaming responses.** MCP over Streamable HTTP can keep responses open; raise the Ingress controller's read timeout (for example `nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"`).
- **Egress.** `networkPolicy.egress` restricts outgoing traffic when set. Include DNS, the target databases, the management database, the IdP and notification endpoints (Slack, webhooks).
- **Keeping the volume.** `helm uninstall` deletes the PersistentVolumeClaim created by the chart. To keep the SQLite store and audit files, set `persistence.annotations: { helm.sh/resource-policy: keep }` or use `persistence.existingClaim`.
