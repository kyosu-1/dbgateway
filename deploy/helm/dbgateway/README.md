# dbgateway Helm chart

Deploys [dbgateway](https://github.com/kyosu-1/dbgateway), an SQL-aware gateway that lets AI agents and people use production PostgreSQL and MySQL databases safely, on Kubernetes.

The chart is not published to a chart repository yet. Install it from a checkout of the repository:

```sh
helm install dbgateway deploy/helm/dbgateway --namespace dbgateway --create-namespace -f my-values.yaml
```

The [Kubernetes guide](https://kyosu-1.github.io/dbgateway/kubernetes) walks through a single-instance and a multi-instance installation. This page is the reference for the chart's values.

## What the chart creates

| Resource | When |
| --- | --- |
| Deployment (`dbgw serve --config /etc/dbgateway/dbgateway.yaml`) | always |
| ConfigMap with `dbgateway.yaml` | unless `existingConfigMap` |
| Service (port 8443, plain HTTP) | always |
| PersistentVolumeClaim mounted at `/var/lib/dbgateway` | `persistence.enabled` without `existingClaim` |
| ServiceAccount (no API token mounted) | `serviceAccount.create` |
| Ingress | `ingress.enabled` |
| Service `<fullname>-metrics` | `metrics.enabled` |
| ServiceMonitor | `metrics.serviceMonitor.enabled` |
| PodDisruptionBudget | `podDisruptionBudget.enabled` and more than one replica |
| NetworkPolicy | `networkPolicy.enabled` |
| Secret `<fullname>-env` | `secret.create` (quickstarts only) |

## Configuration and secrets

`config` is the dbgateway configuration ([reference](https://kyosu-1.github.io/dbgateway/configuration)) written as YAML under the `config:` key. The chart renders it into a ConfigMap, mounts it at `/etc/dbgateway/dbgateway.yaml`, and rolls the pods whenever it changes (`checksum/config` annotation). Alternatively, point `existingConfigMap` at a ConfigMap you manage; then add an annotation to `podAnnotations` (or use a reloader) to roll the pods on changes.

The defaults only set what the container needs: `server.listen: 0.0.0.0:8443`, the SQLite store and audit files under `/var/lib/dbgateway`. You add `auth`, `databases`, `groups`, `role_bindings`, `policies` and the rest. Values files are merged key by key and lists are replaced; set a default key to `null` to remove it (for example `store.path: null` when switching to PostgreSQL).

**Secrets never go into `config`.** dbgateway reads them from environment variables named by the `*_env` keys (`password_env`, `dsn_env`, `client_secret_env`...). Provide those variables from Secrets you manage, with `envFrom` or `env`:

```yaml
envFrom:
  - secretRef:
      name: dbgateway-secrets   # DBGW_OIDC_CLIENT_SECRET, DBGW_STORE_DSN, ...
```

`secret.create` creates a Secret from `secret.stringData` for quickstarts. Its values end up in the Helm release and usually in a values file, so do not use it in production.

The chart checks what it can before installing and fails with a message when:

- `config.auth` is missing;
- `config.server.listen` is a loopback address, or its port differs from `ports.http`;
- `config.server.public_url` is missing (it defaults to `https://<first ingress host>` when the Ingress is enabled), is not `https`, or names a host that is not in `ingress.hosts`;
- `config.server.metrics_listen` does not match `ports.metrics` with `metrics.enabled`;
- `replicaCount` is greater than 1 with the SQLite store, with `audit.output: file`, or with `persistence.enabled`.

It cannot check an `existingConfigMap`. Run `dbgw config validate --config dbgateway.yaml` on any configuration before installing it.

## Single instance and multiple instances

| | Single instance (default) | Multiple instances |
| --- | --- | --- |
| `config.store` | `driver: sqlite` (on the volume) | `driver: postgres`, `dsn_env: ...` |
| `config.audit` | `output: file` (on the volume) | `output: postgres` (or `stdout`) |
| `persistence.enabled` | `true` | `false` |
| `replicaCount` | always 1 | 2 or more |
| Deployment strategy | `Recreate` | `updateStrategy` (RollingUpdate) |
| PodDisruptionBudget | none | `maxUnavailable: 1` |

With SQLite or a persistent volume, the Deployment always runs one pod and uses the `Recreate` strategy, so two pods never open the store or the audit files at the same time. During an upgrade there is a short outage while the new pod starts. For several replicas, see [High availability](https://kyosu-1.github.io/dbgateway/ha): the PostgreSQL management database shares tokens, sessions and approvals between pods and keeps one audit hash chain.

The volume mounted at `/var/lib/dbgateway` is the PVC with `persistence.enabled`, an `emptyDir` otherwise. With an `emptyDir`, the SQLite store and audit files are lost whenever the pod is replaced, which is only acceptable for a trial. Audit files on one pod's volume are not supported with several replicas; use `audit.output: postgres`.

## Values

| Key | Default | Description |
| --- | --- | --- |
| `image.repository` | `ghcr.io/kyosu-1/dbgateway` | Image repository |
| `image.tag` | `""` (the chart's `appVersion`) | Image tag |
| `image.digest` | `""` | Image digest (`sha256:...`); used instead of the tag when set |
| `image.pullPolicy` | `IfNotPresent` | |
| `imagePullSecrets` | `[]` | |
| `nameOverride`, `fullnameOverride` | `""` | |
| `config` | server, store and audit defaults | dbgateway configuration, rendered into a ConfigMap |
| `existingConfigMap` | `""` | Use this ConfigMap instead of `config` |
| `existingConfigMapKey` | `dbgateway.yaml` | Key of the configuration in `existingConfigMap` |
| `env` | `[]` | Container environment variables (secrets named by `*_env` keys) |
| `envFrom` | `[]` | Environment variables from Secrets or ConfigMaps |
| `secret.create` | `false` | Create a Secret from `secret.stringData` (quickstarts only) |
| `secret.stringData` | `{}` | Environment variable name to value |
| `ports.http` | `8443` | Container port; must match `config.server.listen` |
| `ports.metrics` | `9090` | Metrics container port; must match `config.server.metrics_listen` |
| `replicaCount` | `1` | Pods; more than 1 needs the PostgreSQL store and audit log |
| `updateStrategy` | RollingUpdate, `maxUnavailable: 0`, `maxSurge: 1` | Used when several replicas are possible; otherwise `Recreate` |
| `revisionHistoryLimit` | `10` | |
| `persistence.enabled` | `true` | PVC at `/var/lib/dbgateway` (SQLite store, audit files); `emptyDir` when false |
| `persistence.existingClaim` | `""` | Use an existing PVC |
| `persistence.storageClass` | `""` | `""`: cluster default; `"-"`: `storageClassName: ""` |
| `persistence.accessModes` | `[ReadWriteOnce]` | |
| `persistence.size` | `2Gi` | |
| `persistence.annotations`, `persistence.labels` | `{}` | For example `helm.sh/resource-policy: keep` |
| `serviceAccount.create` | `true` | |
| `serviceAccount.name` | `""` (the full name) | |
| `serviceAccount.annotations` | `{}` | IRSA (`eks.amazonaws.com/role-arn`) or GKE Workload Identity (`iam.gke.io/gcp-service-account`) for IAM database authentication |
| `serviceAccount.labels` | `{}` | |
| `automountServiceAccountToken` | `false` | dbgateway does not use the Kubernetes API |
| `deploymentAnnotations`, `podAnnotations`, `podLabels` | `{}` | |
| `podSecurityContext` | non-root (65532), `fsGroup` 65532, seccomp `RuntimeDefault` | |
| `securityContext` | read-only root file system, no privilege escalation, all capabilities dropped | |
| `resources` | requests `100m` / `128Mi`, memory limit `512Mi` | |
| `startupProbe`, `livenessProbe`, `readinessProbe` | `GET /healthz` | Set to `null` to remove one |
| `terminationGracePeriodSeconds` | `30` | dbgateway drains requests for up to 15 seconds |
| `lifecycle` | `{}` | For example `preStop: { sleep: { seconds: 5 } }` |
| `priorityClassName` | `""` | |
| `nodeSelector`, `tolerations`, `affinity`, `topologySpreadConstraints` | empty | |
| `service.type` | `ClusterIP` | |
| `service.port` | `8443` | |
| `service.annotations`, `service.labels` | `{}` | |
| `ingress.enabled` | `false` | |
| `ingress.className` | `""` | |
| `ingress.annotations` | `{}` | |
| `ingress.hosts` | `dbgateway.example.com`, path `/` | The first host provides the default `public_url` |
| `ingress.tls` | `[]` | TLS secrets; leave empty only when TLS is terminated in front of the Ingress |
| `metrics.enabled` | `false` | Expose Prometheus metrics; sets `metrics_listen` to `0.0.0.0:<ports.metrics>` unless set |
| `metrics.service.annotations`, `metrics.service.labels` | `{}` | The `<fullname>-metrics` Service |
| `metrics.serviceMonitor.enabled` | `false` | Requires the Prometheus Operator CRDs |
| `metrics.serviceMonitor.labels` | `{}` | For example the label your Prometheus selects on |
| `metrics.serviceMonitor.interval` / `scrapeTimeout` | `30s` / `10s` | |
| `metrics.serviceMonitor.relabelings`, `metricRelabelings` | `[]` | |
| `podDisruptionBudget.enabled` | `true` | Only rendered with more than one replica |
| `podDisruptionBudget.maxUnavailable` | `1` | |
| `podDisruptionBudget.minAvailable` | unset | Used instead of `maxUnavailable` when set |
| `networkPolicy.enabled` | `false` | |
| `networkPolicy.ingressFrom` | `[]` | Peers allowed to reach the HTTP port; empty: everyone |
| `networkPolicy.metricsFrom` | `[]` | Peers allowed to reach the metrics port; empty: nobody |
| `networkPolicy.egress` | `[]` | Egress rules; empty: egress not restricted |
| `extraVolumes`, `extraVolumeMounts` | `[]` | For example CA certificates for `sslrootcert` |
| `sidecars`, `initContainers` | `[]` | |
| `enableServiceLinks` | `false` | |

## Security defaults

- The container runs as the image's non-root user (65532) with a read-only root file system, no privilege escalation, all capabilities dropped and the `RuntimeDefault` seccomp profile. `/tmp` is a small `emptyDir` (CA certificates from `sslrootcert_env` are written there).
- No Kubernetes API token is mounted.
- dbgateway serves plain HTTP. Terminate TLS at the Ingress (`ingress.tls`) or a load balancer in front of it, and keep `server.public_url` equal to the URL clients use: sign-in redirects, OAuth metadata for agents and passkeys depend on it.
- `/metrics` is never served on the main port, and the metrics Service is separate from the one the Ingress routes to. It has no authentication: with `networkPolicy.enabled`, only `networkPolicy.metricsFrom` can reach it.

## Development

`make helm-check` (or `deploy/helm/check.sh`) lints and renders the chart with each value set in `ci/`, validates the manifests with [kubeconform](https://github.com/yannh/kubeconform) (when installed), validates the rendered configuration with `dbgw config validate` (`make build` first), and checks that invalid combinations are refused. CI runs it on every pull request.
