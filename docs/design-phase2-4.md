# dbgateway フェーズ2〜4 詳細設計（補足）

Nov 8, 2026

[dbgateway 設計ドキュメント](dbgateway-design.md) のフェーズ2〜4について、実装に必要なのに書かれていなかった点を決めたものです。元の設計と食い違う点は、元の設計の「未決事項」にも記録します。

## 共通の方針

- 入口（MCP、connectRPC、Web画面、PostgreSQLプロトコル互換のプロキシ）はすべて `internal/gateway` を呼び、同じ解析・ポリシー・マスキング・監査を通す
- MCPと OAuth の標準エンドポイント以外のAPIは protobuf で定義し、connectRPC で提供する（`proto/dbgateway/v1`）
- Web画面は日本語と英語に対応する（`internal/web/i18n`）。見た目は UI デザイン案（Design キャンバス）に合わせる
- 失敗したら止める。状態が分からないとき、外部サービスが落ちたとき、設定が読めないときは、実行しない側に倒す

## フェーズ2: 承認

### 有効化と既定値

```yaml
approvals:
  enabled: true
  default_max_affected_ratio: 2.0   # 影響行数の上限 = 見積もり × この値（最低1行）
  step_up_max_age: 5m               # 承認の直前に本人確認してからの有効時間
```

- `approvals.enabled: false`（既定）のときは、フェーズ1と同じく書き込みを常に拒否する
- 有効にしてポリシーを書いていない場合の既定ルールは、読み取りは許可、DDLは拒否、書き込みは承認待ち
- ポリシーが `approve` と判定したのに、どの承認ルールにも一致しない場合は拒否する（承認経路がない）

### リスクレベル

`risk.high` → `risk.medium` の順にCELの条件を評価し、どれかに一致したレベルを採用、どれにも一致しなければ `low`。評価には見積もり（`estimate`）を使うので、書き込みでは常に EXPLAIN を実行する。書き込みの EXPLAIN は書き込み用ユーザーで、読み取り専用トランザクションの中で行う（EXPLAIN は実行を伴わない）。

### 承認リクエスト

状態遷移は元の設計の図のとおり（pending → approved → running → succeeded / failed、pending → rejected / expired）。加えて、申請者が取り下げる `canceled` を設ける。

保存する項目（管理用DB）:

| 項目 | 内容 |
| --- | --- |
| `id` | `req_` + 128ビットの乱数（推測できない） |
| 申請者 | 種類（人・エージェント）、人、エージェント名、クライアントID |
| 接続先、SQL原文、正規化したSQL、`reason` | 原文は承認画面と実行にだけ使う。一覧や通知には正規化したSQLを使う |
| 解析結果の要約、見積もり行数、リスク | 承認画面と通知に表示 |
| 承認ルール名、ステップ、期限 | 申請時点の承認ルールを固定して保存 |
| 設定のバージョン | 申請時点 |
| 固定ハッシュ | `sha256(接続名 · SQL原文 · 申請者 · 承認ルール名 · 設定のバージョン)`。承認と実行の直前に照合する |
| 承認の記録 | ステップごとに、承認者、日時、本人確認の方法 |
| 却下・取り下げ | 誰が、いつ、コメント |
| 実行結果 | 影響行数、RETURNING の結果（マスク済み）、所要時間、エラー |

### 承認の制約

- 承認者は、ステップの `role`（その接続先にそのロールを持つ人）または `group` を満たす人
- 申請者本人は承認できない。エージェントの申請では、代理元の人を申請者とみなす
- 同じ人が複数のステップを承認できない
- 承認には、`approvals.step_up_max_age` 以内の本人確認（パスキー、またはIdPの再認証）が必要
- 承認できるのは人だけ（エージェントのトークンでは承認画面もAPIも使えない）

### 実行

最後のステップが承認されたら、dbgateway が非同期で実行する。

1. 固定ハッシュを照合する。一致しなければ失敗
2. 申請者のロール（writer）とポリシーを、その時点の設定で再評価する。判定が `approve` でない、または承認ルールが変わっていれば失敗（「判定が変わったため実行しない」）
3. 書き込み用ユーザーで、読み書きのトランザクションを開始し、`statement_timeout`、`lock_timeout`、`search_path` を設定する
4. 文を実行する。影響行数が上限（見積もり × `default_max_affected_ratio`、最低1行。承認ルールの `max_affected_rows` があればそれ）を超えたらロールバックして失敗
5. コミットし、RETURNING の結果に読み取りと同じマスキングをかけて保存する
6. 監査ログと通知（`execution_finished`）

承認は1回しか使えない（状態が approved から running に移った時点で消費される）。

### MCP

- `execute_sql` は承認が必要なとき、エラーにせず `status: "pending"`、`request_id`、`approvers`（承認できる人）、`expires_at`、`approval_url` を返す
- `get_request`（入力: `request_id`）は、状態、承認の進み具合、実行結果を返す。参照できるのは申請者（代理元の人と、その人のエージェント）と承認者だけ。それ以外には「存在しない」と同じ応答を返す
- `explain_policy`（入力: 接続名、SQL）は、実行せずに判定、適用ルール、リスク、承認ルール、承認できる人、マスクされる列を返す
- **Tasks拡張は保留。** MCPの公式Go SDK（v1.8.0）がTasks拡張に未対応のため、すべてのクライアントに承認待ちIDで返す。SDKが対応したら追加する

### 本人確認（パスキーとステップアップ）

- パスキー（WebAuthn）を、アカウント画面で登録・削除できる
- IdPのない環境では、パスキーだけでログインできる。最初のパスキーは、サーバー上で `dbgw passkey enroll --email <人>` を実行して得る1回限りの登録リンク（24時間有効）から登録する
- ステップアップ: 承認・緊急昇格などの前に、パスキーで再確認するか、IdPの再認証（`prompt=login`、`max_age=0`、`auth_time` を確認）を行い、セッションに確認日時を記録する
- 開発用ログインでは、開発用の再確認ボタンでステップアップできる（開発用ログインと同じくループバック限定）

### 期限付きロールと unmask

- ロールの割り当てに `user`（メールアドレス）も指定できるようにし、`expires_at` と合わせて個人への一時的な付与（JIT）に使う
- マスクの解除は、ロールとは別の設定で、人にだけ付与する

```yaml
unmask:
  - user: hanako@example.com        # または group
    databases: ["prod-main"]
    expires_at: 2026-11-30T00:00:00Z
```

unmask を持つ人には masked の列をそのまま返す（no_ai は人にはもともと見える）。エージェントには適用しない。

### 通知

- イベント: `approval_requested`、`approval_decided`、`execution_finished`、`query_denied`、`break_glass_used`、`anomaly_detected`、`config_changed`
- 送り先: Slack のチャンネル、申請者へのDM（`slack: requester`）、承認者へのメンション（`mention: approvers`）、汎用Webhook（`webhook_env` に URL を入れた環境変数名）
- 承認依頼の投稿をスレッドの起点にし、後続のイベントは同じスレッドに返す（スレッドの位置を管理用DBに保存）
- 通知には、正規化したSQL、対象テーブル、見積もり行数、`reason`、申請者だけを載せる。リテラルとクエリ結果は載せない
- 送信は非同期で、失敗しても処理は止めない（通知は補助。承認画面と `get_request` が正）
- `config_changed`: 起動時に、前回起動時の設定のバージョンと比べて変わっていれば送る
- `anomaly_detected`: 同じ申請者による拒否が10分間に10回を超えたとき、または1時間に返した行数が設定の上限（既定 100,000 行）を超えたとき

### Slack

- Socket Mode（外向きの WebSocket だけ）。必要な環境変数は `SLACK_APP_TOKEN`（xapp-）と `SLACK_BOT_TOKEN`（xoxb-）で、名前は設定で変えられる
- 承認依頼のメッセージに「承認画面を開く」（URLボタン）と「却下」（対話ボタン）を付ける
- 却下ボタンは、押した人のSlackアカウントがdbgatewayのユーザーと紐づいていて、そのリクエストの承認者であるときだけ有効。却下後はメッセージを更新する
- 紐づけ: アカウント画面で1回限りのコード（10分有効）を表示し、Slackで `/dbgw link <コード>` を実行する
- Slackアプリの manifest を `deploy/slack/manifest.yaml` に置く

## フェーズ3: 人の利用と運用強化

### 人のクエリ（CLIとWeb簡易コンソール）

- connectRPC の `GatewayService`: `ListDatabases`、`SearchObjects`、`ExecuteSQL`、`ExplainPolicy`、`GetRequest`、`ListRequests`、`CancelRequest`、`ApproveRequest`、`RejectRequest`（承認・却下は人のトークンだけ。承認にはステップアップ済みのセッションが要るため、APIでは却下だけを受け付け、承認はWeb画面で行う）
- `dbgw query --db <接続名> --reason <理由> "<SQL>"`（表形式・JSON・CSV で出力）。人のトークン（`dbgw login`）で呼ぶ
- Web簡易コンソール（`/console`）: 接続先、SQL、理由を入力して実行し、結果を表で表示する。読み取りはすぐに結果が出て、書き込みは承認待ちになる

### IAM認証

```yaml
primary:
  host: prod-main.xxxx.ap-northeast-1.rds.amazonaws.com
  auth: aws_iam          # aws_iam | gcp_iam | password
  read_user: dbgw_reader
  region: ap-northeast-1 # aws_iam のみ。省略時は AWS の標準の設定から
```

- `aws_iam`: 接続のたびに RDS の認証トークン（15分有効）を発行して、パスワードの代わりに使う。資格情報は AWS SDK の標準の探索順（環境変数、プロファイル、タスクロールなど）
- `gcp_iam`: Cloud SQL の IAM データベース認証。Google の標準の認証情報（ADC）でアクセストークンを取得し、パスワードの代わりに使う。ユーザー名はサービスアカウントのメールアドレスから `.gserviceaccount.com` を除いたもの
- どちらも TLS 必須（`sslmode` は `verify-full` を推奨。Cloud SQL はサーバー証明書のCAを `sslrootcert` に指定する。インスタンスごとのCAの証明書には IP の SAN がないため `verify-ca` を使う。CAがインスタンス専用なので身元も確かめられる。詳細は [operations.md](operations.md)）

### 監査ログの出力先の追加

```yaml
audit:
  output: file           # file | stdout | postgres
  otlp:                  # 追加の転送先（任意）
    endpoint: otel-collector.internal:4317
    insecure: false
```

- `postgres`: 管理用DB（PostgreSQL）に記録する。複数台で1本のハッシュチェーンを保つため、書き込みは管理用DBのアドバイザリーロックで直列化する。`dbgw audit verify` も管理用DBを検証できる
- `otlp`: OpenTelemetry のログとして送る（SIEM へはコレクター経由）。転送は補助で、主の出力先（file / postgres）に書けたことをもって成功とする
- 監査ログの検索画面（`/audit`）: 期間、申請者、接続先、判定、テーブルで絞り込む。閲覧できるのは `auditor` 権限を持つ人（設定の `auditors`）

### 管理用DBの PostgreSQL 対応（冗長構成）

```yaml
store:
  driver: postgres       # sqlite | postgres
  dsn_env: DBGW_STORE_DSN
```

複数台の dbgateway が同じ管理用DBを使うことで、トークン、セッション、承認リクエストを共有する。承認後の実行は、リクエストの状態を `approved → running` に更新できた1台だけが行う（条件付き更新）。

### 緊急昇格

```yaml
break_glass:
  max_duration: 1h
  databases: { labels: { env: prod } }
```

- approver ロールを持つ人だけが、Web画面から、理由とステップアップ認証つきで、時間を限って緊急昇格できる
- 昇格中は、その人の書き込みが承認なしで実行される（解析段階の拒否、ポリシーの拒否、影響行数の上限はそのまま）。エージェントのトークンでは使えない
- 昇格した時点で `break_glass_used` を通知する。監査ログには昇格中の操作に印を付ける
- 緊急迂回経路（dbgateway を通らない、封印した資格情報での直接接続）は運用手順として `docs/operations.md` に定める

### ユーザー画面

- ユーザー一覧と詳細（グループ、接続先ごとのロール、エージェント、最近のアクセス）
- 権限の変更は Git の PR で行う方針を変えない。画面では「変更の提案」として、設定ファイルに貼る YAML の差分を生成する

## フェーズ4: 拡張

### PostgreSQL プロトコル互換のプロキシ

```yaml
pgproxy:
  listen: 127.0.0.1:5433
  tls_cert: /etc/dbgateway/tls.crt   # ループバック以外では必須
  tls_key: /etc/dbgateway/tls.key
```

- psql や DBeaver から接続する。ユーザー名は任意、パスワードに `dbgw login` で得たトークン（または `dbgw token create` のトークン）を使う。TLSなしの平文パスワードはループバックでだけ受け付ける
- データベース名が dbgateway の接続名になる
- 対応: 簡易問い合わせプロトコルと、パラメータのない拡張問い合わせプロトコル。パラメータ付きの文、COPY、関数呼び出しプロトコルは拒否する
- 理由は `SET dbgw.reason = '...'` で指定する（この文だけはプロキシが受け取り、DBには送らない）。未設定なら接続時の `application_name` を使い、それもなければ拒否する
- クライアントの接続確認用の文（`SET client_encoding` などのセッション設定、`SELECT version()`）は、プロキシが既定の応答を返す
- 結果はテキスト形式で返す。マスキングは他の入口と同じ

### MySQL アダプタ

- パーサは TiDB のパーサ（`github.com/pingcap/tidb/pkg/parser`）
- 解析段階で拒否するもの: 複数文、トランザクション制御、`SET`、`LOAD DATA`、`SELECT ... INTO OUTFILE/DUMPFILE/@var`、`FOR UPDATE`/`LOCK IN SHARE MODE`、`HANDLER`、`CALL`、`DO`、`LOCK TABLES`、`PREPARE`、許可リストにない関数（`LOAD_FILE`、`SLEEP`、`BENCHMARK`、`GET_LOCK` など）
- 実行は `START TRANSACTION READ ONLY` と `MAX_EXECUTION_TIME`、接続ごとの `sql_mode` 固定。カタログは `information_schema`
- PostgreSQL と同じ抜け穴集の観点で、MySQL 用の抜け穴集を用意する

### SCIM

- `/scim/v2/Users` と `/scim/v2/Groups`（SCIM 2.0、IdP からの同期用）。認証は設定で指定した環境変数のベアラートークン
- 同期したグループは、OIDC のグループと同じく `groups[].oidc_group` で dbgateway のグループに対応づける
- `active: false` になったユーザーは、セッションとトークンをすべて失効させる

### 値の中身による個人情報の検出

```yaml
pii_detection:
  enabled: true
  detectors: [email, phone_jp, credit_card, my_number]
  action: mask            # mask | deny
```

- エージェントに返す public の列の値を検査し、メールアドレス、電話番号、クレジットカード番号（Luhn）、マイナンバー（検査用数字）を見つけたら、その値を伏せる（`deny` なら結果全体を返さない）
- 列の区分の付け忘れを補う安全網であり、区分の代わりではない

## 実装で判断した点（要確認）

フェーズ2〜4の実装中に、設計に書かれていなかったことを次のように決めました。

- **エージェントの書き込みスコープ。** 承認機能が有効なとき、OAuthの同意画面に「書き込みの申請」の選択肢を出し、選ぶと `db:write` を付与する（writer ロールを持つ接続先がある場合のみ）。`dbgw token create` と `dbgw mcp stdio` は `--write` で同じスコープを要求する。書き込みは常に人の承認を通る
- **承認は2回のクリック。** 承認ボタン → 本人確認の画面 → 詳細画面に戻ってもう一度承認。GETでは状態を変えない
- **承認画面の表示。** 承認ルール、ステップ、影響行数の上限は表示するが、ポリシーのルール名と固定ハッシュは保存していないため表示しない
- **ゲートウェイの拒否理由は日本語のみ。** 英語のWeb画面でも、ゲートウェイが返す理由とヒントは日本語のまま表示される
- **承認待ちの再評価。** 実行直前の再評価では、申請者の現在のロールとポリシーを確認する。エージェントのトークンが失効していても、代理元の人が writer であれば実行する
- **PostgreSQLプロキシ。** 拡張問い合わせのバイナリ形式は、テキストで受けた値を変換して返す（pgx の既定モードが使えるように）。読み取りの Describe は文を1回実行して結果を30秒キャッシュする。データの注意書きは人の接続にも毎回付ける
- **MySQL。** セッションの `sql_mode` を `ANSI_QUOTES` を含む固定値にするため、`"..."` は識別子として扱われる。実行可能コメント（`/*! ... */`）とヒントは、MySQL のバージョン判定を悪用した解析のずれを防ぐため、すべて拒否する。接続は毎回破棄する（MySQL に `DISCARD ALL` 相当がないため）
- **通知の内容。** 正規化したSQL、表、見積もり行数、理由、申請者、状態、URLだけを送る。DBのエラーメッセージとパーサのメッセージは値を含みうるため送らない
- **PII検出。** エージェントに返す public の列だけを検査し、見つけた部分だけを伏せる（`deny` なら結果全体を返さない）。人の結果は区分だけで決める
- **管理用DBと監査ログの PostgreSQL 対応。** 監査ログは複数台でも1本のハッシュチェーンになるよう、アドバイザリーロックで書き込みを直列化する。SQLite から PostgreSQL への移行は `dbgw store import-sqlite`
- **ユーザー画面は読み取りのみ。** 権限の変更は Git の PR で行う方針のまま、画面では設定に貼る YAML と PR の説明文を生成する
