# イベント通知（Slack と Webhook）

dbgateway は、承認依頼・承認結果・実行結果・拒否・緊急昇格・異常・設定変更を Slack と汎用 Webhook に通知します。Slack では承認依頼の投稿に「承認画面を開く」と「却下」のボタンが付き、後続のイベントは同じスレッドに返ります。

通知は補助です。承認画面と `get_request` が正で、通知の送信は非同期・ベストエフォートです。送信に失敗しても、リクエストの処理（承認、実行、拒否）には一切影響しません。

## 送るもの・送らないもの

| 送る | 送らない |
| --- | --- |
| 正規化したSQL（リテラルを `$1` などに置き換えたもの） | SQL原文、リテラル |
| 対象テーブル、見積もり行数、リスク、承認ルール名 | クエリの結果、RETURNING の値 |
| `reason`（申請者が書いた理由。リンクやメンションにならないプレーンテキストで表示） | データベースのエラーメッセージ（値を含むことがあるため。「実行に失敗しました。詳細は承認画面で」とだけ表示） |
| 申請者（人、エージェント名）、状態、操作した人、承認画面の URL | 構文エラーなどの判定メッセージ（SQLの一部を引用することがあるため）。ルール名と段階だけを送る |

- Slack の文面はすべてエスケープし（`&`、`<`、`>`）、`verbatim` で自動リンクを止めています。`reason` はプレーンテキストのブロックに入れるので、`<!channel>` や `<https://…|…>` を書かれても通知にもリンクにもなりません
- リンクの展開（unfurl）は無効にしています
- ログにも、メッセージ本文、トークン、Webhook の URL は出しません（イベントの種類、リクエストID、送り先の名前、エラーだけ）

## 設定

```yaml
notifications:
  - events: [approval_requested]
    to: { slack: "#db-approvals", mention: approvers }   # 承認できる人をメンション
  - events: [approval_decided, execution_finished]
    to: { slack: requester }                              # 申請者にDM
  - events: [query_denied]
    when: database.labels.env == "prod"
    to: { slack: "#security-alerts" }
  - events: [break_glass_used, anomaly_detected]
    to: { slack: "#security-alerts", webhook_env: PAGERDUTY_WEBHOOK_URL }
  - events: [config_changed]
    to: { slack: "#dbgateway-admin" }

slack:                              # 省略時は下の既定値
  app_token_env: SLACK_APP_TOKEN    # xapp-（connections:write）
  bot_token_env: SLACK_BOT_TOKEN    # xoxb-

anomaly:
  denials_per_10m: 10               # 同じ申請者の拒否が10分間にこの回数を超えたら
  rows_per_hour: 100000             # 同じ申請者に1時間に返した行数がこれを超えたら

notifications_language: ja          # ja（既定）または en
notifications_webhook_secret_env: DBGW_WEBHOOK_SECRET   # 任意。Webhook の署名鍵
```

### ルート

- `events`: `approval_requested`、`approval_decided`、`execution_finished`、`query_denied`、`break_glass_used`、`anomaly_detected`、`config_changed` から選ぶ
- `when`（任意）: CEL の条件。使える変数は `database`（`name`、`labels`）と `event`（`type`、`status`、`risk`）。例: `database.labels.env == "prod" && event.risk == "high"`。評価に失敗した条件（例: その接続先にないラベルを参照した）は「一致しない」として扱います。ラベルがない接続先もあるときは `"env" in database.labels && database.labels.env == "prod"` のように書きます
- `to.slack`: `"#チャンネル名"`、チャンネルID（`C0123ABC`）、または `requester`（申請者のSlackユーザーへのDM。紐づけていない人には送らない）
- `to.mention: approvers`: 次に承認できる人を、紐づいたSlackユーザーとしてメンションする（紐づいていない人はメールアドレスを表示）。チャンネル宛てのときだけ使える
- `to.webhook_env`: Webhook の URL を入れた環境変数の名前
- 一致したルートはすべて使います（最初の一致だけではありません）。同じチャンネルや同じ Webhook には1回だけ送ります

設定の読み込み時に、イベント名、CEL のコンパイル、チャンネルの書式、環境変数名を検査します。トークンや Webhook の環境変数が空のときは警告を出し、その送り先を飛ばします（起動は止めません）。

### スレッド

- `approval_requested` をチャンネルに投稿すると、その投稿（チャンネルと `ts`）を管理用DBに保存し、承認・却下・期限切れ・取り下げ（`approval_decided`）と実行結果（`execution_finished`）を **同じスレッドに返信** します。これはルートの設定にかかわらず行います。同じチャンネル宛てのルートがあっても、チャンネルに別の投稿はしません
- 元の投稿の「状態」の行も更新します（例: 「却下（hanako@example.com）」「実行成功」）。承認待ちでなくなったら「却下」ボタンを消します

### 異常検知（anomaly_detected）

- 同じ申請者（エージェントの申請は代理元の人。人ごとにまとめて数えます）の `query_denied` が10分間に `denials_per_10m` 回を超えたとき
- 同じ申請者に1時間に返した行数が `rows_per_hour` を超えたとき
- 一度通知したら、その申請者・その種類については窓の時間（10分、1時間）が過ぎるまで再通知しません
- カウントはプロセスのメモリ上で行います（複数台構成では台ごと）

### 設定変更（config_changed）

起動時に、設定のバージョン（ファイルの SHA-256 の先頭12文字）を前回の起動時と比べ、変わっていれば通知します（前回と今回のバージョンを載せます）。初回の起動は通知しません。

## Slack のセットアップ

1. https://api.slack.com/apps で「Create New App」→「From an app manifest」を選び、[`deploy/slack/manifest.yaml`](../deploy/slack/manifest.yaml) を貼り付けて作成する
2. 「Basic Information」→「App-Level Tokens」で `connections:write` のトークンを作り、`SLACK_APP_TOKEN`（`xapp-…`）に入れる
3. 「Install to Workspace」でインストールし、「Bot User OAuth Token」を `SLACK_BOT_TOKEN`（`xoxb-…`）に入れる
4. 通知先のチャンネルにボットを招待する（`/invite @dbgateway`）
5. dbgateway を再起動する。ログに `Slack Socket Mode connected` が出れば接続できています

Socket Mode なので、dbgateway から Slack への外向きの WebSocket だけを使います。Slack から dbgateway へのインバウンドの URL は不要です。複数台で動かすと各台が接続し、Slack がボタン操作をどれか1台に届けます。

必要なボットの権限: `chat:write`（投稿・更新・本人にだけ見える返信）、`im:write`（申請者へのDM）、`users:read`、`commands`（`/dbgw`）。

### Slack アカウントの紐づけ

メンション、申請者へのDM、却下ボタンには、Slackユーザーとdbgatewayのユーザーの紐づけが必要です。

1. dbgateway のアカウント画面で Slack 連携のコードを発行し、1回限りのコード（例: `7KQ2-M9XD`、10分有効）を表示する
2. Slack で `/dbgw link 7KQ2-M9XD` を実行する

- コードは管理用DBにハッシュだけを保存します。新しいコードを発行すると前のコードは無効になります
- 同じSlackユーザーが10分間に5回コードを間違えると、しばらく受け付けません
- `/dbgw whoami` で紐づいているアカウントを確認、`/dbgw unlink`（またはアカウント画面）で解除できます
- 1つのSlackユーザーは1つのdbgatewayユーザーにだけ紐づきます。別のアカウントで紐づけ直すと、前の紐づけは外れます

### 却下ボタン

- 押した人のSlackユーザーがdbgatewayのユーザーと紐づいていて、そのリクエストのいずれかのステップの承認者であるときだけ却下できます（承認画面の却下と同じ判定。コメントは「Slackから却下」）
- 申請者本人、紐づいていない人、承認者でない人、SCIM で無効化された人には、本人にだけ見えるメッセージで理由を返し、何もしません。すでに処理済みのリクエストも同様です
- 却下するとスレッドに結果が返り、元の投稿の状態が更新されます
- **承認は Slack ではできません**。「承認画面を開く」から承認画面に移り、本人確認（パスキーまたは IdP の再認証）をして承認します

## Webhook

`webhook_env` の環境変数に入れた URL に、イベントを JSON で POST します（Microsoft Teams、PagerDuty などへの中継用）。

```json
{
  "type": "approval_requested",
  "time": "2026-11-08T01:02:03Z",
  "request_id": "req_…",
  "database": "prod-main",
  "labels": { "env": "prod" },
  "principal": { "kind": "agent", "human": "taro@example.com", "agent": "claude-code", "client_id": "…" },
  "sql": "UPDATE users SET plan = $1 WHERE id = $2",
  "tables": ["public.users"],
  "estimate_rows": 1,
  "reason": "問い合わせ#1234の対応",
  "status": "pending",
  "approvers": ["hanako@example.com"],
  "url": "https://dbgw.example.com/approvals/req_…",
  "detail": { "risk": "high", "approval_rule": "prod-writes", "max_affected_rows": "2" },
  "text": "承認依頼 · prod-main · claude-code · taro@example.com の代理 · 承認待ち"
}
```

- `detail` に入るのは `risk`、`approval_rule`、`max_affected_rows`、`step`、`rows_affected`、`stage`、`rule`、`databases`、`expires_at`、`anomaly`、`count`、`threshold`、`window`、`previous_version`、`version` だけです
- ヘッダー: `Content-Type: application/json`、`User-Agent: dbgateway`、`X-Dbgw-Event: <イベント名>`
- タイムアウトは5秒。接続エラー、429、5xx のときは間隔を倍にしながら（1秒、2秒）**最大3回** まで試します。それ以外の 4xx は再送しません
- URL はログに出しません（URL に秘密が含まれることが多いため）

### 署名の検証

`notifications_webhook_secret_env` を設定すると、本文の HMAC-SHA256 を `X-Dbgw-Signature: sha256=<16進>` で付けます。受け側では、受け取った本文そのもの（パースし直す前のバイト列）で同じ値を計算し、定数時間で比較してください。

```python
import hmac, hashlib
expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
ok = hmac.compare_digest(expected, request.headers["X-Dbgw-Signature"])
```

本文には `time` が入るので、古すぎるイベントを捨てることで再送攻撃を防げます。

## 運用

- 送信待ちのイベントは最大1024件までメモリに積みます。あふれた分は捨て、件数をログに出します（1分に1回まで）
- 停止時は最大10秒、送信待ちのイベントを送り切るのを待ちます
- 管理用DBは SQLite（`store.driver: sqlite`）が前提です。スレッドの位置と紐づけは `slack_threads`、`slack_links`、`slack_link_codes` テーブルに入ります

## 組み込み（開発者向け）

- `notify.New` が `events.Publisher` を実装する `*Dispatcher` を返します。`server` パッケージが、通知が設定されているときにゲートウェイと承認サービスへ渡しています（`notify.NewAnomaly` で包んだもの）
- `Anomaly.ObserveRows(principal, database, rows)`: 読み取りが成功するたびにゲートウェイから呼ぶと、`rows_per_hour` の判定に使われます
- `Dispatcher.Linker()` の `Linked(email)`、`IssueCode(email)`、`Unlink(email)` を、Webのアカウント画面から使います
- `Dispatcher.SetPrincipalResolver` で、却下ボタンを押した人の principal の組み立てを auth パッケージのものに置き換えられます（既定は管理用DBのユーザーと IdP グループから `RBAC.ResolveGroups` で解決し、SCIM で無効化された人は拒否）
