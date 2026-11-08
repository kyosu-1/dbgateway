# Cloud Run 検証環境（dbgateway 本体 + Cloud SQL for PostgreSQL）

dbgateway 本体を Cloud Run で動かし、プライベートIPの Cloud SQL for PostgreSQL 17 に IAM データベース認証（`auth: gcp_iam`）でつなぐ、使い捨ての検証環境です。MCP サーバー、Web 画面、OAuth、承認フロー、管理用DB（PostgreSQL）と監査ログ（`audit.output: postgres`）までを、エンドツーエンドで確かめるためのものです。**本番用の構成ではありません。**

このディレクトリには、アカウント固有の値を一切置きません。値はすべて変数で渡し、state は手元に置きます（git の管理外です）。

## 1. 作るもの

```
  テスト担当者 ──HTTPS（X-Serverless-Authorization: 担当者の ID トークン）──► Cloud Run: dbgateway（最小1台・最大2台、CPU常時割り当て）
                                                                         │ Direct VPC egress（10.43.0.0/24、プライベート宛てのみ）
                                                                         ▼
  setup.sh / verify-env.sh ──パブリックIP（allowed_cidr のみ、TLS）──► Cloud SQL（PostgreSQL 17、プライベートIP: PSA 10.44.0.0/20）
                                                                           ├ app       … 接続先（サンプルスキーマ）
                                                                           └ dbgateway … 管理用DB・監査ログ
```

| リソース | 内容 |
| --- | --- |
| API | run、sqladmin、artifactregistry、secretmanager、servicenetworking、compute（destroy しても無効化しない） |
| VPC | 専用ネットワーク（カスタムサブネット）、Cloud Run 用サブネット `10.43.0.0/24`、プライベートサービスアクセス（PSA）用の範囲 `10.44.0.0/20` と接続 |
| Cloud SQL | PostgreSQL 17、ENTERPRISE、db-f1-micro、ZONAL、10GB、バックアップなし、削除保護なし。プライベートIP（上の VPC）と、`allowed_cidr` だけに開いたパブリックIP。TLS 必須（`ENCRYPTED_ONLY`）、インスタンスごとの CA（`GOOGLE_MANAGED_INTERNAL_CA`）、`cloudsql.iam_authentication=on` |
| データベース | `app`（接続先）、`dbgateway`（管理用DB と監査ログ） |
| DB ユーザー | `dbgw_admin`（組み込み、`setup.sh` 専用）、`dbgw_store`（組み込み、`dbgateway` の所有者）、Cloud Run のサービスアカウントの IAM ユーザー |
| サービスアカウント | Cloud Run 用。プロジェクトに `roles/cloudsql.instanceUser`（IAM ログイン）と `roles/cloudsql.client`、管理用DB の DSN のシークレットだけに `roles/secretmanager.secretAccessor` |
| Secret Manager | 管理用DB の DSN（プライベートIP、`sslmode=verify-ca`）→ Cloud Run の環境変数 `DBGW_STORE_DSN` |
| Artifact Registry | Docker リポジトリ `<region>-docker.pkg.dev/<project>/<name>` |
| Cloud Run | `dbgw serve`。`image` を指定したときだけ作る。呼び出せるのは `invoker` だけ（`allUsers` は付けない） |

Cloud Run には次の環境変数を渡します。設定ファイル（`templates/dbgateway.yaml.tftpl` を Terraform が展開したもの）に秘密は入っていません。

| 環境変数 | 中身 |
| --- | --- |
| `DBGW_CONFIG_YAML` | 設定ファイルの内容。`dbgw serve` は `--config` がなければこれを読みます |
| `DBGW_DB_CA` | Cloud SQL インスタンスのサーバー CA（PEM）。接続先（`sslrootcert_env`）と管理用DB（`store.sslrootcert_env`）の両方で使います |
| `DBGW_STORE_DSN` | 管理用DB の DSN（Secret Manager から） |

イメージの `ENTRYPOINT` は `/usr/local/bin/dbgw`、`CMD` は `serve --config /etc/dbgateway/dbgateway.yaml` です。Cloud Run の `args = ["serve"]` で `CMD` だけを置き換え、設定は `DBGW_CONFIG_YAML` から読ませます（Cloud Run の `command` は `ENTRYPOINT` を置き換えるため使いません）。

### 1.1 CPU を常時割り当て、最小1台にする理由

dbgateway は、リクエストを処理していない間もバックグラウンドで動き続けます。

- 承認されたリクエストの実行（承認済みを探して `approved → running` にし、実行する）
- 承認リクエスト、トークン、セッションの期限切れの処理
- 監査ログの保存期間を過ぎた行の削除

Cloud Run の既定（`cpu_idle = true`、リクエスト単位の課金）では、リクエストの外では CPU がほぼ止められ、台数も 0 まで減ります。そうなると、承認しても実行されない、期限が切れても状態が変わらない、といったことが起きます。そのため `cpu_idle = false`（CPU 常時割り当て、インスタンス単位の課金）と `min_instance_count = 1` にしています。最大2台は、複数台のときの動き（管理用DB の共有、条件付き更新による1回だけの実行）も確かめるためです（[冗長構成](../../docs/ha.md)）。

### 1.2 pgproxy を Cloud Run で動かせない理由

pgproxy（`psql` などから PostgreSQL のプロトコルで接続する入口）は生の TCP で待ち受けます。Cloud Run が外から受け付けるのは HTTP(S)（HTTP/1.1、HTTP/2、gRPC、WebSocket）だけで、任意の TCP ポートは公開できません。この環境では MCP、Web 画面、API だけを確かめます。pgproxy を試すなら GCE や GKE（TCP のロードバランサ）を使います。

### 1.3 読み取りと書き込みが同じ IAM ユーザーである理由

Cloud Run のサービスはサービスアカウントを1つしか持てないため、`read_user` と `write_user` は同じ IAM ユーザーです（`setup.sh` が `app` の全テーブルに SELECT/INSERT/UPDATE/DELETE を付けます）。読み取りは引き続き READ ONLY トランザクションで実行し、読み取り用の接続には `default_transaction_read_only = on` も設定するので、読み取りの経路から書き込みはできません。ただし「最後の防衛線は GRANT」という本番の推奨（読み取り専用ユーザーを分ける）は満たしていません。本番で分けたい場合は、書き込み用にパスワード認証のユーザーを使うか、読み取りと書き込みで別のサービスを立てる構成を検討します。

## 2. 費用の目安

検証が終わったらその日のうちに削除してください。CPU 常時割り当ての Cloud Run が最小1台で動き続けるため、使っていなくても課金されます。

- Cloud Run: 1 vCPU・512MiB を常時1台（インスタンス単位の課金）で、月に数十ドル程度（1日あたり1〜2ドル程度）
- Cloud SQL: db-f1-micro と 10GB の SSD で、月に10ドル程度
- そのほか Artifact Registry の保存容量、Secret Manager、ネットワークは小額

金額はおおよその目安です。実際の単価はリージョンと時期で変わるので、料金表で確認してください。

## 3. 手順

必要なもの: Terraform 1.6 以上、gcloud、docker、Go（リポジトリのルートで `go run` するため）、`allowed_cidr` に入るネットワークにある端末。

```sh
cd deploy/gcp-cloudrun
gcloud auth login                          # gcloud（deploy.sh の push、ID トークン）
gcloud auth application-default login      # Terraform の資格情報

# 毎回同じ変数を渡すので、シェル変数にまとめておく（ファイルには保存しない）
TFVARS=(
  -var "project=<your-project-id>"
  -var "allowed_cidr=$(curl -fsSL https://checkip.amazonaws.com)/32"
  -var "invoker=user:$(gcloud config get account)"
  -var "requester_email=<requester@example.com>"
  -var "approver_email=<approver@example.com>"
)

# 1. 初期化と、Cloud Run 以外の作成（image を空にすると Cloud Run は作らない）
terraform init
terraform plan -out=tfplan "${TFVARS[@]}"
#    → 計画を確認する（作られるもの、allowed_cidr、invoker）
terraform apply tfplan

# 2. データベースの準備（サンプルスキーマ、IAM ユーザーの権限、管理用DB の所有者）
./setup.sh

# 3. イメージを linux/amd64 でビルドし、Artifact Registry に push する
(cd ../.. && docker build --platform linux/amd64 -t dbgateway:cloudrun-test .)
./deploy.sh dbgateway:cloudrun-test        # 最後に次の plan/apply のコマンドを表示する（適用はしない）

# 4. Cloud Run の作成（deploy.sh が表示した image を使う）
terraform plan -out=tfplan "${TFVARS[@]}" -var "image=<deploy.sh が表示したイメージ>"
#    → 計画を確認する
terraform apply tfplan
terraform output public_url service_uri service_urls   # public_url が service_urls に含まれることを確認

# 5. テスト用の環境変数とパスキーの登録リンク
./verify-env.sh                            # DBGW_CLOUD_* を表示する

# 6. エンドツーエンドのテスト（リポジトリのルートで、表示された環境変数を設定して）
cd ../..
export DBGW_CLOUD_URL=... DBGW_CLOUD_HEADER=... DBGW_CLOUD_DB=... \
       DBGW_CLOUD_ENROLL_REQUESTER=... DBGW_CLOUD_ENROLL_APPROVER=...
go test -tags cloud -count=1 ./test/cloud/
cd deploy/gcp-cloudrun

# 7. 削除（image は作成時と同じ値を渡す）
terraform plan -destroy -out=tfplan "${TFVARS[@]}" -var "image=<同じイメージ>"
#    → 削除するものを確認する
terraform apply tfplan
```

- `setup.sh` は Cloud Run を作る**前に**実行します。dbgateway は起動時に管理用DB にテーブルを作りますが、`dbgw_store` が `dbgateway` データベースを所有する（または権限を持つ）までは作れず、起動に失敗して Cloud Run の作成（`terraform apply`）も失敗するためです。何度実行しても問題ありません
- `deploy.sh` は毎回違うタグで push し、ダイジェストで固定したイメージ名を表示します。イメージを変えて 4 をやり直すと、新しいリビジョンに切り替わります
- 設定（`templates/dbgateway.yaml.tftpl`、利用者のメールアドレス）を変えたときも 4 の plan/apply で反映します

### 3.1 `verify-env.sh` が表示するもの

```
DBGW_CLOUD_URL=https://<name>-<project number>.<region>.run.app
DBGW_CLOUD_HEADER="X-Serverless-Authorization: Bearer $(gcloud auth print-identity-token)"
DBGW_CLOUD_DB=cloud-main
DBGW_CLOUD_ENROLL_REQUESTER=https://.../passkeys/enroll/...
DBGW_CLOUD_ENROLL_APPROVER=https://.../passkeys/enroll/...
```

- `DBGW_CLOUD_URL` は設定の `server.public_url`（Cloud Run の決定的 URL）です。OAuth の issuer やリダイレクト先、パスキー（WebAuthn）のオリジンはこの URL から作るため、もう一方の URL（`service_uri`、`https://<name>-<ハッシュ>.a.run.app`）では動きません。Cloud Run がこの URL を割り当てていない場合は警告を出します
- 登録リンクは、手元から管理用DB にパブリックIP で接続し、`dbgw passkey enroll --config env:DBGW_CONFIG_YAML` で作ります（`store_dsn_public` と `cloudsql-server-ca.pem` を使います）。リンクの URL は設定の `public_url` から作られます。有効期限は24時間で、1回だけ使えます
- `DBGW_CLOUD_HEADER` の `$(...)` は展開せずに表示します。テストを実行するシェルで展開してください（ID トークンの有効期限は1時間です）

### 3.2 Cloud Run の認証と dbgateway の認証

Cloud Run は `roles/run.invoker` を持つ人のリクエストだけを通します（`allUsers` には付けません）。dbgateway 自身も `Authorization: Bearer` で OAuth のトークンを受け取るため、Cloud Run 用の ID トークンは `X-Serverless-Authorization` ヘッダーで送ります。Cloud Run のドキュメントでは、両方のヘッダーがあると `X-Serverless-Authorization` だけを検査し、その署名を取り除いてからコンテナに渡すとされています。`Authorization` はそのままコンテナ（dbgateway）に届きます。

- `gcloud auth print-identity-token` で取る人の ID トークンには、Cloud Run の URL を示す audience が入っていません。Cloud Run は開発者の呼び出しとしてこれを受け付けますが、ドキュメントでは「リプレイ攻撃を受けやすいので開発用」とされています。人のアカウントでは `--audiences` は指定できません（サービスアカウントの権限借用のときだけ使えます）。自動化するときは、サービスアカウントの ID トークンを audience に URL を指定して発行します
- ブラウザは任意のヘッダーを付けられないため、そのままでは Web 画面やパスキーの登録リンクを開けません（403 になります）。ブラウザで試すなら、ヘッダーを付ける拡張機能などを使います。`gcloud run services proxy` は `http://localhost:8080` で中継しますが、オリジンが `public_url` と違うため、ログインやパスキーは動きません

## 4. 削除について

- データベースと DB ユーザーは `deletion_policy = "ABANDON"` で、インスタンスと一緒に消えます（先に消そうとすると、`setup.sh` が作ったオブジェクトや権限のために失敗するため）
- PSA の接続（`google_service_networking_connection`）も `deletion_policy = "ABANDON"` です。Cloud SQL を削除した直後は、サービス側の後片付けが終わっておらず、接続の削除が「Producer services ... are still using this connection」で失敗することがよくあるためです。接続は state から外れるだけで、VPC ネットワークの削除とともに消えます
- **サブネットの削除は、Cloud Run を消した後もしばらく失敗します。** Direct VPC egress が使った IP アドレス（`serverless-ipv4-...`）は Cloud Run が自動で解放しますが、サービスの削除から解放まで時間がかかります（検証では数十分以上）。「`subnetwork ... is already being used by ... addresses/serverless-ipv4-...`」で失敗したら、残るのはネットワークとサブネット（料金はかかりません）だけなので、次で解放を確かめてから同じ `plan -destroy` / `apply` をやり直します: `gcloud compute addresses list --project <project> --filter="name~^serverless-ipv4"`
- それでもネットワークや PSA の範囲の削除が「使用中」で失敗した場合は、しばらく（数分〜数十分）待ってから同じ `plan -destroy` / `apply` をやり直します。急ぐ場合は `gcloud compute networks peerings delete servicenetworking-googleapis-com --network=<name>` でピアリングを消してからやり直します
- Cloud SQL のインスタンス名には乱数の接尾辞を付けています（削除した名前はしばらく再利用できないため）
- Artifact Registry のリポジトリは中のイメージごと削除されます
- 有効にした API は無効にしません

## 5. セキュリティ上の注意

- Cloud SQL のパブリックIP は `allowed_cidr` だけに開いています（`0.0.0.0/0` は変数の検証で拒否します）。`setup.sh` と `verify-env.sh` 以外では使いません。dbgateway はプライベートIP で接続します
- TLS はサーバー CA の検証つき（`verify-ca`）です。インスタンスごとの CA のサーバー証明書には IP の SAN がないため `verify-full` は使えませんが、CA がそのインスタンス専用なので、CA の検証でサーバーの身元も確かめられます。`dbgw config validate` は `env: prod` の DB で `verify-full` 以外を使うと警告を出しますが、この構成では想定どおりです
- dbgateway の DB 接続はパスワードを使わず、Cloud Run のサービスアカウントの IAM 認証です。管理用DB の DSN（`dbgw_store` のパスワード）だけを Secret Manager に置き、そのシークレットだけを読めるようにしています
- `roles/cloudsql.instanceUser` と `roles/cloudsql.client` はプロジェクト単位で付けています。検証専用のプロジェクトで使ってください（`cloudsql.client` は dbgateway の直接接続には不要で、Auth Proxy での調査用です）
- Terraform の state には、DB のパスワードと DSN が平文で入ります。state と `tfplan`、`cloudsql-server-ca.pem` は git の管理外です。共有しないでください
- サンプルスキーマが作る `dbgw_reader`（開発用の既知のパスワード）は、`setup.sh` がログインできないようにします
- 接続先と管理用DB が同じインスタンスにあるのは検証用の簡略化です。本番では分けます（[冗長構成](../../docs/ha.md)）
- 使い終わったら必ず削除します

## 6. 変数と出力

変数: `project`（必須）、`region`（既定 `asia-northeast1`）、`name`（既定 `dbgw-run-test`。Cloud Run のサービス名で、ほかのリソース名の接頭辞）、`allowed_cidr`（必須、`0.0.0.0/0` は不可）、`invoker`（必須、`user:someone@example.com` の形式。`allUsers` などは不可）、`image`（既定は空。空なら Cloud Run を作らない）、`requester_email`・`approver_email`（必須、設定の固定グループ `developers`・`approvers` の唯一のメンバー）。

出力: `public_url`、`service_uri`、`service_urls`、`artifact_repository`、`service_account_email`、`iam_db_user`、`sql_instance_name`、`sql_public_ip`、`sql_private_ip`、`server_ca_cert`（sensitive）、`admin_password`（sensitive）、`store_password`（sensitive）、`store_dsn_public`（sensitive）、`dbgateway_config`、`requester_email`、`approver_email`。
