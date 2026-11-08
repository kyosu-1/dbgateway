# Cloud Run test environment (dbgateway + Cloud SQL for PostgreSQL)

A disposable test environment that runs dbgateway on Cloud Run and connects it to a private-IP Cloud SQL for PostgreSQL 17 instance with IAM database authentication (`auth: gcp_iam`). It verifies the MCP server, the web UI, OAuth, the approval flow, the management database (PostgreSQL) and the audit log (`audit.output: postgres`) end to end. **It is not a production deployment.**

Nothing account-specific is stored in this directory. All values are passed as variables, and the state is kept locally (it is git-ignored).

## 1. What it creates

```
  Tester ──HTTPS (X-Serverless-Authorization: tester's ID token)──► Cloud Run: dbgateway (min 1, max 2 instances, CPU always allocated)
                                                                     │ Direct VPC egress (10.43.0.0/24, private ranges only)
                                                                     ▼
  setup.sh / verify-env.sh ──public IP (allowed_cidr only, TLS)──► Cloud SQL (PostgreSQL 17, private IP: PSA 10.44.0.0/20)
                                                                       ├ app       … target database (sample schema)
                                                                       └ dbgateway … management database, audit log
```

| Resource | Details |
| --- | --- |
| APIs | run, sqladmin, artifactregistry, secretmanager, servicenetworking, compute (not disabled on destroy) |
| VPC | A dedicated network (custom subnets), the Cloud Run subnet `10.43.0.0/24`, and the private services access (PSA) range `10.44.0.0/20` with its connection |
| Cloud SQL | PostgreSQL 17, ENTERPRISE, db-f1-micro, ZONAL, 10 GB, no backups, no deletion protection. A private IP (in the VPC above) and a public IP open only to `allowed_cidr`. TLS required (`ENCRYPTED_ONLY`), a per-instance CA (`GOOGLE_MANAGED_INTERNAL_CA`), `cloudsql.iam_authentication=on` |
| Databases | `app` (target database), `dbgateway` (management database and audit log) |
| Database users | `dbgw_admin` (built-in, only for `setup.sh`), `dbgw_store` (built-in, owner of `dbgateway`), the IAM user of the Cloud Run service account |
| Service account | For Cloud Run. `roles/cloudsql.instanceUser` (IAM login) and `roles/cloudsql.client` on the project, and `roles/secretmanager.secretAccessor` on the management database DSN secret only |
| Secret Manager | The management database DSN (private IP, `sslmode=verify-ca`) → the Cloud Run environment variable `DBGW_STORE_DSN` |
| Artifact Registry | Docker repository `<region>-docker.pkg.dev/<project>/<name>` |
| Cloud Run | `dbgw serve`. Created only when `image` is set. Only `invoker` can call it (`allUsers` is never granted) |

Cloud Run receives the following environment variables. The configuration file (`templates/dbgateway.yaml.tftpl` rendered by Terraform) contains no secrets.

| Environment variable | Contents |
| --- | --- |
| `DBGW_CONFIG_YAML` | The configuration file. `dbgw serve` reads it when `--config` is not given |
| `DBGW_DB_CA` | The Cloud SQL instance's server CA (PEM). Used for both the target database (`sslrootcert_env`) and the management database (`store.sslrootcert_env`) |
| `DBGW_STORE_DSN` | The management database DSN (from Secret Manager) |

The image's `ENTRYPOINT` is `/usr/local/bin/dbgw` and its `CMD` is `serve --config /etc/dbgateway/dbgateway.yaml`. Cloud Run's `args = ["serve"]` replaces only `CMD`, so the configuration is read from `DBGW_CONFIG_YAML` (Cloud Run's `command` would replace `ENTRYPOINT`, so it is not used).

### 1.1 Why CPU is always allocated with at least one instance

dbgateway keeps working in the background while it is not serving requests:

- running approved requests (finding approved requests, moving them from `approved` to `running`, and executing them)
- expiring approval requests, tokens and sessions
- deleting audit log rows past their retention period

With Cloud Run's defaults (`cpu_idle = true`, request-based billing), CPU is nearly stopped outside requests and the service scales to zero. Approved requests would then never run, and expired items would never change state. Therefore the service uses `cpu_idle = false` (CPU always allocated, instance-based billing) and `min_instance_count = 1`. The maximum of two instances is there to verify multi-instance behavior as well (a shared management database, and exactly-once execution through conditional updates; see [high availability](../../docs/ha.md)).

### 1.2 Why reads and writes use the same IAM user

A Cloud Run service has only one service account, so `read_user` and `write_user` are the same IAM user (`setup.sh` grants SELECT/INSERT/UPDATE/DELETE on all tables in `app`). Reads still run in READ ONLY transactions, and read connections also set `default_transaction_read_only = on`, so the read path cannot write. However, this does not meet the production recommendation that database grants are the last line of defense (a separate read-only user). To separate them in production, use a password-authenticated user for writes, or run separate services for reads and writes.

## 2. Cost estimate

Destroy the environment the same day you finish testing. Cloud Run with CPU always allocated keeps at least one instance running, so it is billed even when idle.

- Cloud Run: one instance with 1 vCPU and 512 MiB, always on (instance-based billing): a few tens of dollars per month (roughly 1–2 dollars per day)
- Cloud SQL: db-f1-micro with a 10 GB SSD: about 10 dollars per month
- Artifact Registry storage, Secret Manager and networking: small amounts

These are rough estimates. Actual prices vary by region and over time; check the pricing pages.

## 3. Steps

Requirements: Terraform 1.6 or later, gcloud, docker, Go (for `go run` at the repository root), and a machine on a network inside `allowed_cidr`.

```sh
cd deploy/gcp-cloudrun
gcloud auth login                          # gcloud (push in deploy.sh, ID tokens)
gcloud auth application-default login      # credentials for Terraform

# The same variables are passed every time; keep them in a shell variable (not in a file)
TFVARS=(
  -var "project=<your-project-id>"
  -var "allowed_cidr=$(curl -fsSL https://checkip.amazonaws.com)/32"
  -var "invoker=user:$(gcloud config get account)"
  -var "requester_email=<requester@example.com>"
  -var "approver_email=<approver@example.com>"
)

# 1. Initialize and create everything except Cloud Run (an empty image skips Cloud Run)
terraform init
terraform plan -out=tfplan "${TFVARS[@]}"
#    → review the plan (resources, allowed_cidr, invoker)
terraform apply tfplan

# 2. Prepare the databases (sample schema, IAM user grants, management database owner)
./setup.sh

# 3. Build the image for linux/amd64 and push it to Artifact Registry
(cd ../.. && docker build --platform linux/amd64 -t dbgateway:cloudrun-test .)
./deploy.sh dbgateway:cloudrun-test        # prints the next plan/apply commands at the end (does not apply)

# 4. Create Cloud Run (with the image printed by deploy.sh)
terraform plan -out=tfplan "${TFVARS[@]}" -var "image=<image printed by deploy.sh>"
#    → review the plan
terraform apply tfplan
terraform output public_url service_uri service_urls   # check that public_url is in service_urls

# 5. Test environment variables and passkey enrollment links
./verify-env.sh                            # prints DBGW_CLOUD_*

# 6. End-to-end tests (at the repository root, with the printed variables set)
cd ../..
export DBGW_CLOUD_URL=... DBGW_CLOUD_HEADER=... DBGW_CLOUD_DB=... \
       DBGW_CLOUD_ENROLL_REQUESTER=... DBGW_CLOUD_ENROLL_APPROVER=...
go test -tags cloud -count=1 ./test/cloud/
cd deploy/gcp-cloudrun

# 7. Destroy (pass the same image as at creation)
terraform plan -destroy -out=tfplan "${TFVARS[@]}" -var "image=<same image>"
#    → review what will be destroyed
terraform apply tfplan
```

- Run `setup.sh` **before** creating Cloud Run. dbgateway creates its tables in the management database at startup, but it cannot do so until `dbgw_store` owns (or has privileges on) the `dbgateway` database; startup would fail, and so would creating Cloud Run (`terraform apply`). It is safe to run repeatedly
- `deploy.sh` pushes with a new tag each time and prints the image name pinned by digest. Repeating step 4 with a new image switches to a new revision
- Changes to the configuration (`templates/dbgateway.yaml.tftpl`, user email addresses) are also applied with the plan/apply of step 4

### 3.1 What `verify-env.sh` prints

```
DBGW_CLOUD_URL=https://<name>-<project number>.<region>.run.app
DBGW_CLOUD_HEADER="X-Serverless-Authorization: Bearer $(gcloud auth print-identity-token)"
DBGW_CLOUD_DB=cloud-main
DBGW_CLOUD_ENROLL_REQUESTER=https://.../passkeys/enroll/...
DBGW_CLOUD_ENROLL_APPROVER=https://.../passkeys/enroll/...
```

- `DBGW_CLOUD_URL` is `server.public_url` from the configuration (Cloud Run's deterministic URL). The OAuth issuer, redirect URIs and the passkey (WebAuthn) origin are derived from this URL, so the other URL (`service_uri`, `https://<name>-<hash>.a.run.app`) does not work. A warning is printed if Cloud Run has not assigned this URL
- The enrollment links are created by connecting to the management database over the public IP from your machine and running `dbgw passkey enroll --config env:DBGW_CONFIG_YAML` (using `store_dsn_public` and `cloudsql-server-ca.pem`). Link URLs are built from `public_url` in the configuration. They are valid for 24 hours and can be used once
- The `$(...)` in `DBGW_CLOUD_HEADER` is printed unexpanded. Expand it in the shell that runs the tests (ID tokens are valid for one hour)

### 3.2 Cloud Run authentication and dbgateway authentication

Cloud Run passes only requests from principals with `roles/run.invoker` (`allUsers` is never granted). dbgateway itself receives OAuth tokens in `Authorization: Bearer`, so the ID token for Cloud Run is sent in the `X-Serverless-Authorization` header. According to the Cloud Run documentation, when both headers are present, only `X-Serverless-Authorization` is checked and its signature is removed before the request reaches the container. `Authorization` reaches the container (dbgateway) unchanged.

- A user's ID token from `gcloud auth print-identity-token` has no audience naming the Cloud Run URL. Cloud Run accepts it as a developer invocation, but the documentation describes this as "for development, susceptible to replay attacks". `--audiences` cannot be used with user accounts (only when impersonating a service account). For automation, issue a service account's ID token with the URL as its audience
- Browsers cannot add arbitrary headers, so the web UI and passkey enrollment links cannot be opened directly (they return 403). To try them in a browser, use something like a header-injecting extension. `gcloud run services proxy` relays on `http://localhost:8080`, but the origin differs from `public_url`, so sign-in and passkeys do not work

## 4. Notes on destroying

- Databases and database users use `deletion_policy = "ABANDON"` and are removed with the instance (deleting them first fails because of objects and grants created by `setup.sh`)
- The PSA connection (`google_service_networking_connection`) also uses `deletion_policy = "ABANDON"`. Right after Cloud SQL is deleted, the service-side cleanup is often not finished, and deleting the connection frequently fails with "Producer services ... are still using this connection". The connection is only removed from the state, and disappears with the VPC network
- **Deleting the subnet keeps failing for a while after Cloud Run is gone.** Cloud Run releases the IP addresses used by Direct VPC egress (`serverless-ipv4-...`) automatically, but it takes time after the service is deleted (tens of minutes or more in testing). If it fails with "`subnetwork ... is already being used by ... addresses/serverless-ipv4-...`", only the network and subnet remain (they cost nothing); confirm the addresses are released with `gcloud compute addresses list --project <project> --filter="name~^serverless-ipv4"`, then repeat the same `plan -destroy` / `apply`
- If deleting the network or the PSA range still fails with "in use", wait a while (minutes to tens of minutes) and repeat the same `plan -destroy` / `apply`. If you are in a hurry, delete the peering with `gcloud compute networks peerings delete servicenetworking-googleapis-com --network=<name>` and retry
- The Cloud SQL instance name has a random suffix (deleted names cannot be reused for a while)
- The Artifact Registry repository is deleted together with its images
- Enabled APIs are not disabled

## 5. Security notes

- The Cloud SQL public IP is open only to `allowed_cidr` (`0.0.0.0/0` is rejected by variable validation). It is used only by `setup.sh` and `verify-env.sh`; dbgateway connects over the private IP
- TLS verifies the server CA (`verify-ca`). A server certificate from a per-instance CA has no IP SAN, so `verify-full` cannot be used, but because the CA is dedicated to the instance, CA verification also establishes the server's identity. `dbgw config validate` warns when a database with `env: prod` uses anything other than `verify-full`; in this setup that is expected
- dbgateway's database connections use no passwords but IAM authentication as the Cloud Run service account. Only the management database DSN (with the `dbgw_store` password) is stored in Secret Manager, and only that secret is readable
- `roles/cloudsql.instanceUser` and `roles/cloudsql.client` are granted at the project level. Use a project dedicated to testing (`cloudsql.client` is not needed for dbgateway's direct connections; it is for investigating through the Auth Proxy)
- The Terraform state contains the database passwords and DSN in plain text. The state, `tfplan` and `cloudsql-server-ca.pem` are git-ignored. Do not share them
- `setup.sh` prevents `dbgw_reader` (created by the sample schema with a well-known development password) from logging in
- Having the target database and the management database on the same instance is a simplification for testing. Separate them in production ([high availability](../../docs/ha.md))
- Always destroy the environment when you are done

## 6. Variables and outputs

Variables: `project` (required), `region` (default `asia-northeast1`), `name` (default `dbgw-run-test`; the Cloud Run service name and the prefix for other resource names), `allowed_cidr` (required; `0.0.0.0/0` is not allowed), `invoker` (required, in the form `user:someone@example.com`; `allUsers` and similar are not allowed), `image` (empty by default; when empty, Cloud Run is not created), `requester_email` and `approver_email` (required; the only members of the fixed groups `developers` and `approvers` in the configuration).

Outputs: `public_url`, `service_uri`, `service_urls`, `artifact_repository`, `service_account_email`, `iam_db_user`, `sql_instance_name`, `sql_public_ip`, `sql_private_ip`, `server_ca_cert` (sensitive), `admin_password` (sensitive), `store_password` (sensitive), `store_dsn_public` (sensitive), `dbgateway_config`, `requester_email`, `approver_email`.
