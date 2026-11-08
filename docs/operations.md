# dbgateway 運用手順

本番の PostgreSQL の前に dbgateway を置いて運用するための手順です。対象は次の5つです。

1. クラウドの IAM 認証で DB に接続する（Amazon RDS / Cloud SQL）
2. 監査ログを OpenTelemetry で外部に転送する
3. 監査ログの保存期間と改ざん検証
4. 緊急迂回経路（dbgateway を通らない直接接続）の手順
5. Web画面の本人確認（パスキーとステップアップ）と閲覧権限

設定項目の全体は [設計ドキュメント](dbgateway-design.md) と [フェーズ2〜4 詳細設計](design-phase2-4.md) を参照してください。以下で `<...>` はそれぞれの環境の値に置き換えます。

## 1. IAM 認証

dbgateway は、接続先ごとに `auth` で認証方式を選びます。

| `auth` | パスワードの代わりに使うもの | 資格情報の探し方 |
| --- | --- | --- |
| `password` | `password_env` で指定した環境変数の値 | — |
| `aws_iam` | RDS の認証トークン（15分有効） | AWS SDK の標準の探索順（環境変数、プロファイル、ECS タスクロール、EKS Pod Identity / IRSA、EC2 インスタンスプロファイル） |
| `gcp_iam` | Google の OAuth 2.0 アクセストークン（1時間有効） | アプリケーションのデフォルト認証情報（ADC）。GKE の Workload Identity、GCE のサービスアカウントなど |

共通の動き:

- トークンは、新しい物理接続を張るたびに `BeforeConnect` で取得し、パスワードとして送ります。毎回発行しないように、残りの有効期間が5分を切るまで使い回します（RDS は発行から10分、Google はトークンの期限の5分前まで）。DB はログイン時だけトークンを確認するので、確立済みの接続はトークンの期限が切れても使えます
- トークンが取れないときは接続しません（パスワード認証に切り替えることはしません）
- TLS が必須です。`sslmode` は `verify-full`（Cloud SQL の個別CAなら `verify-ca`）にします。`disable`、`allow`、`prefer` は平文に落ちる可能性があるため設定の検証で拒否します。`require` は証明書を検証しないため、トークンを盗まれるおそれがあるとして警告します
- `password_env`、`write_password_env` は一緒に設定できません
- 書き込み用ユーザー（`write_user`）にも同じ方式が使われます。書き込み用ユーザーにも IAM ログインの権限を付けてください

### 1.1 Amazon RDS / Aurora（`aws_iam`）

**1. インスタンスで IAM 認証を有効にする**

```sh
aws rds modify-db-instance --db-instance-identifier <instance> \
  --enable-iam-database-authentication --apply-immediately
```

Terraform では `iam_database_authentication_enabled = true` です（[deploy/aws](../deploy/aws) の `iam_auth` 変数）。

**2. DB ユーザーを作る**（管理者ユーザーで接続して実行）

```sql
CREATE USER dbgw_iam;                -- パスワードは付けない
GRANT rds_iam TO dbgw_iam;           -- IAM 認証でのログインを許可
GRANT CONNECT ON DATABASE <db> TO dbgw_iam;
GRANT USAGE ON SCHEMA public TO dbgw_iam;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO dbgw_iam;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO dbgw_iam;
```

`rds_iam` を付けたユーザーはパスワードではログインできなくなります。読み取り用の最後の防御は GRANT なので、読み取り用ユーザーには SELECT 以外を付けません。

**3. dbgateway の実行ロールに `rds-db:connect` を許可する**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "rds-db:connect",
      "Resource": [
        "arn:aws:rds-db:<region>:<account-id>:dbuser:<DbiResourceId>/dbgw_iam",
        "arn:aws:rds-db:<region>:<account-id>:dbuser:<DbiResourceId>/dbgw_writer"
      ]
    }
  ]
}
```

`<DbiResourceId>` はインスタンスの「リソースID」（`db-` で始まる値。`aws rds describe-db-instances --query 'DBInstances[].DbiResourceId'`）で、インスタンス名ではありません。Aurora ではクラスターのリソースID（`cluster-` で始まる値）を使います。

**4. dbgateway の設定**

```yaml
databases:
  - name: prod-main
    primary:
      host: <instance>.<id>.<region>.rds.amazonaws.com
      auth: aws_iam
      region: <region>            # 省略時は AWS_REGION などの標準の設定
      read_user: dbgw_iam
      sslmode: verify-full
      sslrootcert: /etc/dbgateway/rds-global-bundle.pem
```

CA は `https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem` から取得します。`host` と `port` はトークンの署名に含まれるため、CNAME などの別名ではなく RDS のエンドポイント名をそのまま書きます。

注意:

- IAM 認証の新規接続数には上限があります（AWS は毎秒数百を超える新規接続には推奨していません）。dbgateway はプールで接続を使い回すので通常は問題になりませんが、多数のインスタンスを同時に再起動するときは気にかけてください
- `rds.force_ssl=1` をパラメータグループに設定し、DB 側でも平文の接続を拒否します

### 1.2 Cloud SQL for PostgreSQL（`gcp_iam`）

**1. インスタンスで IAM 認証を有効にし、TLS を必須にする**

```sh
gcloud sql instances patch <instance> \
  --database-flags=cloudsql.iam_authentication=on \
  --ssl-mode=ENCRYPTED_ONLY
```

`--database-flags` は既存のフラグを置き換えるので、他のフラグがあるときは一緒に指定します。dbgateway はクライアント証明書を使わずに直接接続するため、`ssl_mode` は `ENCRYPTED_ONLY` にします（`TRUSTED_CLIENT_CERTIFICATE_REQUIRED` では接続できません）。

**2. IAM ユーザーを DB に登録する**

```sh
# サービスアカウント（推奨）。DB ユーザー名はメールアドレスから .gserviceaccount.com を除いたもの
gcloud sql users create dbgw@<project>.iam --instance=<instance> --type=cloud_iam_service_account
# 人のアカウントの場合（検証用）
gcloud sql users create <user@example.com> --instance=<instance> --type=cloud_iam_user
```

登録しただけでは権限がないので、管理者ユーザーで GRANT します（ユーザー名は二重引用符で囲む）。

```sql
GRANT CONNECT ON DATABASE <db> TO "dbgw@<project>.iam";
GRANT USAGE ON SCHEMA public TO "dbgw@<project>.iam";
GRANT SELECT ON ALL TABLES IN SCHEMA public TO "dbgw@<project>.iam";
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO "dbgw@<project>.iam";
```

**3. IAM ロールを付ける**

| ロール | 用途 |
| --- | --- |
| `roles/cloudsql.instanceUser` | IAM データベース認証でのログイン（`cloudsql.instances.login`）。必須 |
| `roles/cloudsql.client` | Cloud SQL Auth Proxy やコネクタでの接続、インスタンス情報の取得。dbgateway の直接接続には不要だが、運用で Auth Proxy を使うなら付ける |

```sh
gcloud projects add-iam-policy-binding <project> \
  --member=serviceAccount:dbgw@<project>.iam.gserviceaccount.com --role=roles/cloudsql.instanceUser
gcloud projects add-iam-policy-binding <project> \
  --member=serviceAccount:dbgw@<project>.iam.gserviceaccount.com --role=roles/cloudsql.client
```

**4. サーバー証明書の CA と sslmode**

Cloud SQL のサーバー証明書は、CA の方式によって中身が違います。

| `server_ca_mode` | サーバー証明書 | 使う sslmode | `host` |
| --- | --- | --- | --- |
| `GOOGLE_MANAGED_INTERNAL_CA`（インスタンスごとのCA、既定） | `CN=<project>:<instance>`。IP アドレスの SAN はない（PSC のときだけ DNS 名が入る） | `verify-ca`。CA がそのインスタンス専用なので、CA の検証でサーバーの身元も確かめられる | IP アドレス |
| `GOOGLE_MANAGED_CAS_CA`（共有CA） | SAN にインスタンスの DNS 名（`<uid>.<project-dns-label>.<region>.sql.goog`） | `verify-full`。CA が共有なのでホスト名の検証が必要 | DNS 名（DNS レコードは自分で作る） |

```sh
# インスタンスごとのCA
gcloud sql instances describe <instance> --format='value(serverCaCert.cert)' > server-ca.pem
# 共有CA
gcloud sql ssl server-certs list --instance=<instance> --format='value(ca_cert.cert)' > server-ca.pem
```

CA をローテーションするときは、新旧両方の CA を1つのファイルに並べて `sslrootcert` に指定し、切り替え後に古い方を外します（`gcloud sql ssl server-ca-certs list`）。

**5. dbgateway の設定**

```yaml
databases:
  - name: prod-analytics
    primary:
      host: 10.20.0.5              # プライベートIP（推奨）
      auth: gcp_iam
      read_user: dbgw@<project>.iam
      sslmode: verify-ca
      sslrootcert: /etc/dbgateway/cloudsql-server-ca.pem
```

注意:

- 資格情報は ADC から取ります。GKE では Workload Identity、GCE では VM のサービスアカウントを使い、サービスアカウントキーのファイルは使いません。トークンは `https://www.googleapis.com/auth/sqlservice.login` のスコープで要求します（Cloud SQL の Go コネクタと同じスコープ。人の ADC やメタデータサーバーのトークンはスコープの指定が無視され、`cloud-platform` のトークンになりますが、ログインに使えます）
- ユーザー名は小文字だけです。サービスアカウントのメールアドレスをそのまま書くと設定の検証でエラーになります
- 本番ではパブリックIPではなく、プライベートIP（プライベートサービスアクセスまたは PSC）で接続します

**Cloud SQL Go コネクタを使わない理由**

`cloud.google.com/go/cloudsqlconn` を pgx の `DialFunc` に組み込む方法もありますが、採用していません。直接の TLS 接続で十分に安全に検証でき（上の表）、コネクタを使うと Cloud SQL Admin API の有効化と `roles/cloudsql.client`、Admin API への通信経路、依存ライブラリの追加が必要になり、DB 以外の障害点が増えるためです。PSC や共有CAでホスト名の検証が難しい構成が必要になったら、`instance_connection_name` の設定とコネクタの追加を検討します。

### 1.3 検証環境での確認

`deploy/aws`（RDS）と `deploy/gcp`（Cloud SQL）に、使い捨ての検証環境の Terraform があります。`setup.sh` が最後に表示するコマンドで、`TestIAMIntegration` が IAM 認証でログインして `current_user` を確かめます。手順は各ディレクトリの README を参照してください。使い終わったら必ず `terraform destroy` します。

## 2. 監査ログの OpenTelemetry 転送

```yaml
audit:
  output: file                    # 主の出力先
  dir: /var/lib/dbgateway/audit
  otlp:
    endpoint: otel-collector.internal:4317   # host:port（スキームは書かない）
    insecure: false                          # true は同じホストのコレクターに限る
    headers_env: DBGW_OTLP_HEADERS           # 任意。gRPC メタデータ
```

**動き**

- リクエストの成否は主の出力先（file / stdout）だけで決まります。主の出力先に書けなければ結果を返しません（失敗したら止める）
- 転送は補助です。主の出力先に書けた行を、転送先ごとの上限つきキュー（4096件）に入れ、別のゴルーチンが最大256件ずつ OTLP/gRPC で送ります。キューが一杯のときや送信に失敗したときは、その行の転送を諦め、件数を数えて最大1分に1回ログに出します（`audit forwarder queue full; entry dropped`、`audit forwarding failed`）。停止時には送信済み・破棄・失敗の合計を出します
- コレクターに届かなくても起動は止めません（接続は遅延して張ります）。`headers_env` の環境変数が無いときは起動を止めます
- TLS はシステムの CA で検証します。社内CAのコレクターでは、`OTEL_EXPORTER_OTLP_CERTIFICATE` に CA ファイルを指定できます（OpenTelemetry の標準の環境変数も効きます）

`headers_env` の値は `key=value` をカンマで区切ったもので、値は URL エンコードします。

```sh
export DBGW_OTLP_HEADERS='authorization=Bearer%20<token>,x-tenant=<tenant>'
```

**送るログレコード**

| 項目 | 内容 |
| --- | --- |
| 本文（body） | 監査ログの1行そのもの（JSON、`hash` を含む）。受け取った側でハッシュを再計算できる |
| 属性 | 各項目を `dbgw.` の下に平らにしたもの。例: `dbgw.request_id`、`dbgw.principal.human`、`dbgw.principal.agent`、`dbgw.database`、`dbgw.decision`、`dbgw.rule`、`dbgw.analysis.tables`（文字列の配列）、`dbgw.result.rows`、`dbgw.hash`、`dbgw.prev_hash`。SQL の文面は本文だけに入れ、属性にはしない |
| 時刻 | 監査ログの `ts` |
| イベント名 | `dbgateway.audit` |
| 重要度 | `deny` と `error` は WARN、それ以外は INFO |
| リソース | `service.name=dbgateway` |

監査ログには結果の値が入らないので、転送先にも入りません。SQL のリテラルは既定で伏せてあります（`log_raw_sql: false`）。

**コレクターの例**（SIEM へはコレクター経由で送る）

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
        tls:
          cert_file: /etc/otelcol/tls.crt
          key_file: /etc/otelcol/tls.key
processors:
  batch: {}
exporters:
  otlphttp/siem:
    endpoint: https://<siem-endpoint>
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlphttp/siem]
```

転送は補助のため、件数が欠けることがあります。正本は主の出力先です。SIEM 側では `dbgw.prev_hash` と `dbgw.hash` のつながりで欠けを見つけられます。

## 3. 監査ログの保存と検証

**保存**

- `audit.output: file` では、`audit.dir` に UTC の日ごとのファイル（`audit-YYYY-MM-DD.jsonl`）を書きます。1行ごとに fsync します（`no_fsync: true` で無効にできますが、停止時に直近の行を失うおそれがあります）
- `audit.retention`（既定 365日）より古いファイルは削除します。削除の前に、そのファイルの最後のハッシュを `checkpoints.jsonl` に記録し、同じ内容をプロセスのログ（`audit checkpoint`）にも出します。残ったログは、このチェックポイントから検証できます
- 改ざんされた（検証に失敗する）ファイルは削除しません
- `audit.output: stdout` はハッシュチェーンを起動のたびに始め直すので、検証できる履歴が必要な本番では `file` を使います
- 長期の保存と改ざん防止のため、日付が変わった前日のファイルを、上書きできない保存先（S3 Object Lock、GCS のバケットロックなど）に毎日コピーします。プロセスのログ（チェックポイントを含む）も別のログ基盤に送ります

**検証**

```sh
dbgw audit verify --dir /var/lib/dbgateway/audit
# ok: 12345 entries in 30 files, chained from genesis; last hash <hash>
```

- 1行ずつハッシュを再計算し、`prev_hash` のつながりを確かめます。行の書き換え、削除、並べ替えがあると `FAILED` を表示して終了コード 1 で終わります
- 毎日 cron や CI で実行し、失敗したらセキュリティ用チャンネルに通知します。最後のハッシュを外部（チケットや別のログ基盤）に記録しておくと、末尾の切り詰めも見つけられます
- 検証に失敗したら、そのディレクトリを書き込み禁止にして保全し、外部にコピーしたファイルや OTLP の転送先と突き合わせて、どの行が変わったかを調べます

**検索**

監査ログの検索（`/audit` の画面と API）は、ファイルを新しい順に読み、期間、申請者（人またはエージェントの部分一致）、接続先、判定、イベント、テーブル、リクエストIDで絞り込みます。読み込みは後ろから少しずつ行うため、ログが大きくてもメモリの使用量は一定です。

## 4. 緊急迂回経路（break-glass）

dbgateway が止まっていて、復旧を待てない障害対応のときだけ、dbgateway を通らずに DB へ直接接続します。dbgateway が動いているなら、まず dbgateway の「緊急昇格」（approver が理由とステップアップ認証つきで時間を限って使う）を使います。迂回経路では dbgateway の解析、ポリシー、マスキング、監査が一切効かないので、最後の手段です。

### 4.1 事前の準備（平常時）

**封印した資格情報**

- 緊急用の DB ユーザー（例: `dbgw_breakglass`）を作り、普段は `NOLOGIN` にしておきます。dbgateway の設定にも、dbgateway の実行環境にも、この資格情報を置きません
- 有効にするための資格情報は、dbgateway とは別の場所に封印します。どちらか、または両方を使います
  - **クラウドの IAM で封印する（推奨）**: RDS なら `dbgw_breakglass` に `rds_iam` を付け、`rds-db:connect` を許可した専用の IAM ロールを用意します。このロールは指名した数名だけが MFA 付きで引き受けられるようにします。Cloud SQL なら専用のグループに `roles/cloudsql.instanceUser` を、普段は付けずに、緊急時だけ期限付きの条件で付与します
  - **パスワードを封印する**: パスワードをパスワード管理ツールの緊急用の保管庫や、アクセスが記録されるシークレット管理（AWS Secrets Manager、Secret Manager）に置き、取り出せる人を限ります。取り出しは2人で行う（承認つき）ようにします
- 管理者ユーザー（RDS のマスターユーザー、Cloud SQL の `postgres`）の資格情報も同じ扱いにします

**通知の仕組み**

使った時点で必ず通知されるように、DB とクラウドの両方で検知します。

- DB: `log_connections = on` にし、`dbgw_breakglass` と管理者ユーザーのログインをログから検知して、セキュリティ用チャンネルと管理者に通知します（CloudWatch Logs のメトリクスフィルター、Cloud Logging のログベースのアラート）。pgaudit を使えるなら、このユーザーの全操作を記録します
- クラウド: 緊急用 IAM ロールの AssumeRole、シークレットの取得（`GetSecretValue`、`AccessSecretVersion`）、IAM の付与を CloudTrail / Cloud Audit Logs から検知して通知します
- 設計の通知イベント「緊急経路の使用」（`break_glass_used`）と同じ通知先に送ります

**接続経路**

DB へのネットワーク経路は普段 dbgateway だけが持っています。緊急時の経路（SSM Session Manager のポート転送、Cloud SQL Auth Proxy、普段は止めてある踏み台など）を決めておき、それ自体も使用を記録・通知します。

**訓練**

四半期に1回、検証環境で手順を通しで実行し、通知が届くこと、資格情報が取り出せること、事後の無効化とローテーションができることを確かめます。

### 4.2 使う手順（緊急時）

1. **宣言する**: インシデントとして記録し、迂回経路を使う理由、作業内容、作業者と立会人をセキュリティ用チャンネルに書きます（自動通知とは別に、人が先に書く）
2. **2人で行う**: 作業者と立会人を分け、立会人は画面共有などで操作を見ます
3. **資格情報を取り出す**: 緊急用 IAM ロールを MFA 付きで引き受ける、またはシークレットを取り出します。パスワード方式なら `ALTER ROLE dbgw_breakglass LOGIN VALID UNTIL '<2時間後>'` で期限付きで有効にします
4. **接続する**: TLS を検証して接続し、操作を記録します

   ```sh
   script -q breakglass-$(date -u +%Y%m%dT%H%M%SZ).log
   psql "host=<host> dbname=<db> user=dbgw_breakglass sslmode=verify-full sslrootcert=<ca>"
   ```

   ```sql
   \set ECHO all
   SET default_transaction_read_only = on;   -- 書き込みが必要になるまで読み取りだけ
   SET statement_timeout = '30s';
   ```

5. **必要最小限の操作をする**: 書き込みは1件ずつ、`BEGIN` してから影響行数を確かめて `COMMIT` します。実行した SQL はインシデントの記録に貼ります
6. **終わらせる**: 接続を切り、`ALTER ROLE dbgw_breakglass NOLOGIN` に戻し、パスワードを変えて封印し直します（IAM 方式なら一時的な付与を外す）。緊急時の接続経路を閉じます。終わったことをチャンネルに書きます

### 4.3 事後レビュー

使ったら、2営業日以内に事後レビューを行います。

- 集めるもの: インシデントの記録、`script` の記録、DB のログ（接続と pgaudit）、CloudTrail / Cloud Audit Logs、通知の記録、同じ時間帯の dbgateway の監査ログ
- 確かめること: 宣言と通知が操作より先だったか、操作がインシデントの範囲に収まっていたか、実行した SQL と DB のログが一致するか、無効化とローテーションが終わっているか
- 決めること: なぜ dbgateway（緊急昇格を含む）で対応できなかったか。冗長化、緊急昇格の範囲、手順の改善など、次に迂回経路を使わずに済むための対策
- レビューの結果は管理者とセキュリティ担当が承認し、インシデントの記録に残します。通知が届かなかった、無効化を忘れたなど手順の不備があれば、次の訓練の前に直します

## 5. Web画面の本人確認と閲覧権限

### 5.1 パスキー

- パスキー（WebAuthn）のRP IDは `server.public_url` のホスト名です。IPアドレスは使えません（その場合パスキーは無効になり、`auth.passkeys: true` は設定エラーになります）。ホスト名を変えると、登録済みのパスキーは使えなくなります
- IdPを使う環境では、各自がアカウント画面の「パスキーを追加」から登録します。追加の前に本人確認（IdPの再認証）を求めます
- `auth.passkeys: true` にすると、ログイン画面でパスキーでログインできます。IdPのない環境ではこれを使います。最初のパスキーは、サーバー上で次のコマンドを実行して得る1回限りのリンク（24時間有効）から登録します。リンクは本人にだけ、信頼できる経路で渡します

```sh
dbgw passkey enroll --config /etc/dbgateway/dbgateway.yaml --email hanako@example.com
```

- IdPと併用すると、IdPから外した人もパスキーでログインできてしまいます。SCIMで無効化するか、パスキーを使わない設定にします

### 5.2 ステップアップ（承認・緊急昇格の前の本人確認）

承認と緊急昇格の前に、`approvals.step_up_max_age`（既定5分）以内の本人確認を求めます。方法は、パスキー、IdPの再認証（`prompt=login`、`max_age=0` で要求し、IDトークンの `auth_time` が5分以内であることを確認）、開発用ログインでの再確認ボタン（ループバックのみ）のいずれかです。IdPが `auth_time` を返さない場合、IdPの再認証は使えません。

### 5.3 監査ログとユーザー画面

監査ログの検索（`/audit`）とユーザー画面（`/users`）を使えるのは、`auditors` に書いた人・グループと、いずれかの接続先に `admin` ロールを持つ人です。監査ログの検索は `audit.output: file` のときだけ使えます。

```yaml
auditors:
  - group: security
  - user: hanako@example.com
```
