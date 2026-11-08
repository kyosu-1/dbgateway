# AWS 検証環境（ECS Fargate + RDS for PostgreSQL）

dbgateway を Amazon ECS（Fargate）で2台動かし、クラウド上での動作を端から端まで確かめるための使い捨ての環境です。**本番用の構成ではありません。** 検証が終わったらすぐに削除してください。

このディレクトリには、アカウント ID、IP アドレス、メールアドレス、プロファイル名などの個人の値を置きません。値は変数で渡し、Terraform の状態ファイルは手元に置きます（`terraform.tfvars`、状態ファイル、`tfplan`、`*.pem` は Git の管理外です）。

## 作るもの

```
  検証する端末（allowed_cidr）
      │ HTTPS 443（自己署名証明書, hostname）          │ PostgreSQL 5432（setup.sh, verify-env.sh）
      ▼                                               ▼
  ALB（インターネット向け, public サブネット） ──►  dbgateway タスク ×2  ──►  RDS for PostgreSQL 17（public サブネット）
                                   HTTP 8443     （Fargate ARM64,           ・app       接続先DB（IAM認証）
                                                  private サブネット）       ・dbgateway 管理用DB + 監査ログ
                                                        │
                                                        └─ NAT ゲートウェイ経由で ECR、Secrets Manager、CloudWatch Logs
```

- VPC `10.42.0.0/16`（2つの AZ に public / private サブネット、インターネットゲートウェイ、NAT ゲートウェイ1つ）
- RDS for PostgreSQL 17（`db.t4g.micro`、暗号化、`rds.force_ssl=1`、IAM データベース認証を有効化）。`allowed_cidr` から `setup.sh` を実行できるようにパブリックアクセスを有効にしていますが、セキュリティグループで許可しているのは `allowed_cidr` と dbgateway のタスクだけです。バックアップなし、削除時のスナップショットなし、削除保護なし
  - データベース `app`: 接続先DB。サンプルスキーマ（`examples/dev/initdb/01-schema.sql`）と、IAM 認証のユーザー `dbgw_iam`（読み取り）・`dbgw_iam_writer`（書き込み）
  - データベース `dbgateway`: 管理用DBと監査ログ（所有者 `dbgw_store`、パスワードは Terraform が生成）。本番では管理用DBを接続先とは別のインスタンスにします（[冗長構成](../../docs/ha.md)）。ここでは費用を抑えるために1台にまとめています
- ECR リポジトリ（削除時にイメージごと消えます）、ECS クラスタ、Fargate サービス（ARM64、0.5 vCPU / 1 GB、2台）、CloudWatch Logs のロググループ（保存1日）
- ALB（HTTPS 443 を `allowed_cidr` からだけ受け付け、`hostname` の自己署名証明書を ACM に取り込んで使用）。ターゲットグループは IP 指定、ポート 8443、ヘルスチェック `GET /healthz`
- IAM
  - タスクロール: `dbgw_iam` と `dbgw_iam_writer` への `rds-db:connect` だけ
  - タスク実行ロール: この ECR リポジトリからのイメージの取得、このロググループへの書き込み、管理用DBの DSN を入れたシークレットの読み取りだけ
- Secrets Manager: 管理用DBの DSN（タスクの環境変数 `DBGW_STORE_DSN`）。削除時は復旧期間なしで消えます

dbgateway の設定は `templates/dbgateway.yaml.tftpl` から作り、環境変数 `DBGW_CONFIG_YAML` で渡します（秘密は含みません。`terraform output -raw dbgateway_config` で確認できます）。パスキーでログインし（IdP なし）、書き込みは承認制、管理用DBと監査ログは PostgreSQL です。`requester_email` は `developers`（querier, writer）、`approver_email` は `approvers`（querier, writer, approver）のメンバーです。

### RDS の CA 証明書

タスクには、このリージョンの RDS の CA 証明書（`https://truststore.pki.rds.amazonaws.com/<region>/<region>-bundle.pem`、3枚）を環境変数 `DBGW_DB_CA` で渡し、設定の `sslrootcert_env` で使います。全リージョン分のバンドル（約 170 KB）は、ECS のタスク定義の上限（環境変数を含めて 64 KiB）に収まらないためです。インスタンスの証明書は `rds-ca-rsa2048-g1` で発行し、リージョンのバンドルに含まれます。手元（`setup.sh`、`verify-env.sh`）では全リージョン分のバンドル `rds-global-bundle.pem` を使います。

## 費用

東京リージョンでおおよそ 1時間 0.2 USD（1日 5 USD 程度）です。主な内訳は NAT ゲートウェイ、ALB、RDS、Fargate 2台、パブリック IPv4 アドレスです（目安です。最新の料金を確認してください）。使い終わったらすぐに削除します。

## 変数

| 変数 | 既定値 | 説明 |
| --- | --- | --- |
| `allowed_cidr` | （必須） | ALB と RDS に接続できる CIDR。検証する端末のグローバル IP（`x.x.x.x/32`）。`0.0.0.0/0` は拒否します |
| `requester_email` | （必須） | 申請者のメールアドレス（グループ `developers`） |
| `approver_email` | （必須） | 承認者のメールアドレス（グループ `approvers`。`requester_email` と別のアドレス） |
| `image` | `""` | dbgateway のイメージ（linux/arm64、この ECR リポジトリ）。空のときはタスクを0台にします（先に ECR を作ってイメージを push するため） |
| `desired_count` | `2` | `image` を指定したときのタスク数。2台で管理用DBの共有を確かめます |
| `hostname` | `dbgw.test` | dbgateway のホスト名（`server.public_url` と証明書）。DNS には登録しません。検証する端末で ALB に向けます |
| `region` | `ap-northeast-1` | リージョン |
| `name` | `dbgw-ecs-test` | リソース名の接頭辞 |
| `vpc_cidr` | `10.42.0.0/16` | VPC の CIDR |
| `engine_version` / `instance_class` | `17` / `db.t4g.micro` | RDS |

主な出力: `alb_dns_name`、`ecr_repository_url`、`rds_host`、`hostname`、`public_url`、`tls_cert_pem`（自己署名証明書。クライアントで信頼する）、`dbgateway_config`、`cluster_name`、`service_name`、`log_group`、`region`、`requester_email`、`approver_email`、機密扱いの `admin_password`、`store_password`、`store_dsn`（手元からも同じホストで使える管理用DBの DSN）。

## 手順

必要なもの: Terraform 1.9 以降、AWS CLI と認証情報、Docker、Go、curl。コマンドは特に書かない限り `deploy/aws-ecs` で実行します。

**1. 変数を用意する**

```sh
cd deploy/aws-ecs
export AWS_PROFILE=<your-profile>          # または任意の認証情報
cat > terraform.tfvars <<EOF
allowed_cidr    = "$(curl -fsSL https://checkip.amazonaws.com)/32"
requester_email = "<requester@example.com>"
approver_email  = "<approver@example.com>"
EOF
```

**2. 初期化と計画の確認**

```sh
terraform init
terraform plan -out tfplan                 # 作られるリソースを確認する
```

**3. 作成（イメージなし、タスク0台）**

```sh
terraform apply tfplan
```

RDS の作成に10分ほどかかります。

**4. データベースの準備**

```sh
./setup.sh
```

`docker run postgres:17 psql`（`sslmode=verify-full`）で、`app` にサンプルスキーマ（まだなければ）と IAM ユーザー `dbgw_iam`・`dbgw_iam_writer` を、`dbgw_store` ロールとデータベース `dbgateway` を作ります。何度実行しても同じ結果になります。サンプルスキーマが作るパスワードユーザー `dbgw_reader` は、この環境では使わないためログインできないようにします。

タスクを起動する前に実行してください。タスクは管理用DBに接続できないと起動に失敗します（後から実行した場合も、ECS がタスクを起動し直すうちに動き始めます）。

**5. イメージを作って push する**

リポジトリのルートで linux/arm64 のイメージを作り、`deploy.sh` で ECR に push します。`deploy.sh` はビルドも `terraform apply` もしません。

```sh
cd ../..
docker buildx build --platform linux/arm64 -t dbgateway:$(git rev-parse --short HEAD)-arm64 --load .
deploy/aws-ecs/deploy.sh dbgateway:$(git rev-parse --short HEAD)-arm64
```

**6. タスクを起動する**

`deploy.sh` が表示したコマンド（イメージはダイジェストで指定）を実行します。

```sh
cd deploy/aws-ecs
terraform plan -var 'image=<ecr_repository_url>@sha256:...' -out tfplan   # タスク定義とサービスの変更を確認する
terraform apply tfplan
aws ecs wait services-stable --cluster "$(terraform output -raw cluster_name)" --services "$(terraform output -raw service_name)"
```

以後 `terraform apply` するときも同じ `-var image=...` を付けます（付けないとタスクが0台になります）。ログは `aws logs tail "$(terraform output -raw log_group)" --follow` で見られます。

**7. 検証用の環境変数を作る**

リポジトリのルートで実行します。

```sh
cd ../..
set -a; eval "$(deploy/aws-ecs/verify-env.sh)"; set +a
```

`verify-env.sh` は次の変数を出力します。

| 変数 | 値 |
| --- | --- |
| `DBGW_CLOUD_URL` | `https://<hostname>` |
| `DBGW_CLOUD_CONNECT_ADDR` | `<alb_dns_name>:443`（`hostname` の代わりに接続する先） |
| `DBGW_CLOUD_CA_FILE` | ALB の自己署名証明書を書き出したファイル（`deploy/aws-ecs/alb-cert.pem`）の絶対パス |
| `DBGW_CLOUD_DB` | `cloud-main` |
| `DBGW_CLOUD_ENROLL_REQUESTER` / `DBGW_CLOUD_ENROLL_APPROVER` | 申請者・承認者のパスキー登録リンク（1回限り、24時間有効） |

登録リンクは、手元から管理用DBに接続して次のコマンドで作ります（`dbgw passkey enroll` は設定を読み込むため、`sslrootcert_env` 用に `DBGW_DB_CA` が必要です。IAM 認証の接続先には秘密は不要です）。

```sh
DBGW_CONFIG_YAML="$(terraform -chdir=deploy/aws-ecs output -raw dbgateway_config)" \
DBGW_STORE_DSN="$(terraform -chdir=deploy/aws-ecs output -raw store_dsn)" \
DBGW_DB_CA="$(cat deploy/aws-ecs/rds-global-bundle.pem)" \
  go run ./cmd/dbgw passkey enroll --config env:DBGW_CONFIG_YAML --email <email>
```

ブラウザで確かめるときは、`dig +short "$(terraform output -raw alb_dns_name)"` で得た IP アドレスのどれかを `/etc/hosts` で `hostname` に向け、`alb-cert.pem` を信頼します（ALB の IP アドレスは変わることがあります）。

**8. 検証を実行する**

```sh
go test -tags cloud -count=1 ./test/cloud/
```

**9. 削除する**

```sh
cd deploy/aws-ecs
terraform plan -destroy -out tfplan        # 削除されるリソースを確認する
terraform apply tfplan
```

ECR のイメージ、Secrets Manager のシークレット（復旧期間なし）、RDS（スナップショットなし）もすべて消えます。手元の `terraform.tfvars`、`rds-global-bundle.pem`、`alb-cert.pem` は必要に応じて消してください。

## セキュリティ上の注意

- 検証専用です。ALB（443）と RDS（5432）に接続できるのは `allowed_cidr` からだけです。`allowed_cidr` は自分のグローバル IP の `/32` にします。IP アドレスが変わったら `terraform.tfvars` を直して apply し直します
- ALB の証明書は Terraform が作る自己署名証明書です（有効期間30日）。秘密鍵は Terraform の状態ファイルに入ります。状態ファイルには RDS のマスターパスワード、管理用DBのパスワードと DSN も入るため、共有しないでください
- RDS はパブリックアクセスを有効にしています（`allowed_cidr` からの `setup.sh` のため）。本番ではプライベートサブネットに置き、パブリックアクセスを無効にします
- dbgateway のタスクは ALB からの HTTP（VPC 内）だけを受け付けます。外部への通信は HTTPS（NAT 経由）と RDS への PostgreSQL だけです
- パスキーの登録リンクは、そのリンクを持つ人がその人としてパスキーを登録できる秘密です。ログや共有の場所に残さないでください
