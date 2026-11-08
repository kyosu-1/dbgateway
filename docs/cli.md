# dbgw CLI（人のクエリ）

`dbgw` コマンドで、人が dbgateway を通して本番のデータベースに問い合わせるための手順です。AI エージェントと同じ経路（ロールの確認、SQL の解析、列の区分、ポリシー、承認、マスキング、監査ログ）を通ります。違いは、エージェントではなく本人として記録されることだけです。

CLI は connectRPC の `GatewayService`（[proto/dbgateway/v1/gateway.proto](../proto/dbgateway/v1/gateway.proto)）を呼びます。Web 簡易コンソールも同じ API を使います。

## ログイン

```sh
dbgw login --server https://dbgw.example.com
```

デバイスフローでブラウザから認証し、人のトークンを `~/.config/dbgw/credentials.json`（macOS は `~/Library/Application Support/dbgw/credentials.json`）に保存します。以下のコマンドはすべてこのトークンを使います。

- ログインしていないとき、トークンの期限が切れたとき、サーバー側で失効したときは、`dbgw login` をやり直すよう表示して終了します
- 接続先は保存したサーバーです。`--server` または環境変数 `DBGW_SERVER` を指定した場合は、保存したサーバーと一致しないとエラーになります（別のサーバーにトークンを送らないため）
- エージェントのトークン（`dbgw token create` で発行したもの）では、この API は使えません（`PERMISSION_DENIED`）。エージェントは MCP を使います

## コマンド一覧

| コマンド | 内容 |
| --- | --- |
| `dbgw dbs` | 使える接続先と、自分の権限の一覧 |
| `dbgw search --db <接続名> [キーワード]` | テーブル、ビュー、列の検索 |
| `dbgw query --db <接続名> --reason <理由> [SQL]` | SQL の実行 |
| `dbgw explain --db <接続名> [SQL]` | 実行せずに判定だけを確認 |
| `dbgw requests [--scope mine\|awaiting\|decided]` | 承認リクエストの一覧 |
| `dbgw request <ID>` | 承認リクエストの詳細（実行後は結果も） |
| `dbgw request cancel <ID>` | 自分のリクエストの取り下げ |
| `dbgw request reject <ID> [--comment <コメント>]` | 承認者としての却下 |
| `dbgw token print` | 保存したアクセストークンの表示 |

`dbgw query` 以外の表示系のコマンドは `--format json`（`-o json`）で JSON を出力できます。JSON のフィールド名は proto のフィールド名（スネークケース）です。

## dbgw dbs

```console
$ dbgw dbs
NAME       TYPE      ROLES                  SEARCH  READ  WRITE     MAX_ROWS  LABELS
prod-main  postgres  querier,writer,viewer  yes     yes   approval  1000      env=prod
analytics  postgres  viewer                 yes     no    no        -         env=prod
```

`WRITE` が `approval` の接続先では、書き込みを申請できます（承認後に実行されます）。

## dbgw search

```console
$ dbgw search --db prod-main users
public.users (table)
  id      int8         not null  public
  email*  text         not null  masked
  plan    text         null      public

* masked for you
```

- 列名の後ろの `*` は、自分にはマスクされる列です
- `--detail names|summary|full`: `names` は名前だけ、`summary`（既定）は列まで、`full` はインデックス、コメント、推定行数まで（DB のカタログを直接読みます）
- `--schema <スキーマ>`: スキーマを限定します。システムスキーマは名前を指定したときだけ表示します
- `--limit <件数>`: 既定 50、最大 200。上限を超えたときは標準エラーに注意を表示します

## dbgw query

```sh
dbgw query --db prod-main --reason "問い合わせ#1234の調査: ユーザー42のプランを確認" \
  "SELECT id, email, plan FROM users WHERE id = 42"
```

- `--db`（必須）: 接続名
- `--reason`（必須）: 何のためのクエリか。監査ログに記録されます。空の理由は拒否されます。ポリシーが具体的な理由を求めるときは、短すぎる・一般的すぎる理由（「確認」「test」など）も拒否されます
- SQL の渡し方は3通りです。引数（複数の引数は空白でつなぎます）、`-f <ファイル>`（`-f -` は標準入力）、引数も `-f` もなければ標準入力です。1回に1文、最大 1 MiB です
- `--format table|json|csv`（`-o`）: 出力形式。既定は `table`

シェルが `*` を展開しないよう、SQL は引用符で囲んでください。

### 出力（table）

```console
$ dbgw query --db prod-main --reason "..." "SELECT id, email, plan FROM users WHERE id IN (1, 22)"
 id | email*           | plan
----+------------------+------
  1 | u***@example.com | pro
 22 | u***@example.com | free
(2 rows)
* masked: email
```

- 列名の後ろの `*` はマスクされた列、`!` は値を返さない列（`(withheld)` と表示）です。表の下に凡例を表示します
- 数値は右寄せ、NULL は `NULL` と表示します
- 値に含まれる改行、タブ、制御文字（端末のエスケープシーケンスなど）、双方向テキストの制御文字は `\n`、`\x1b`、`\u202e` のようにエスケープして表示します。DB の内容で端末の表示を操作されないためです。元の値が必要なときは `json` か `csv` を使ってください
- 行数またはサイズの上限に達したときは、先頭の行だけを返し、`Result truncated: ...` と表示します。条件を絞るか集計してください

### 出力（json）

結果全体を1つの JSON で標準出力に書きます。拒否、エラー、承認待ちでも同じ形で出力します（終了コードも下の表のとおり）。

```json
{
  "status": "ok",
  "request_id": "req_...",
  "columns": [
    { "name": "id", "type": "int8" },
    { "name": "email", "type": "text", "masked": true, "class": "masked" }
  ],
  "rows": [[1, "u***@example.com"]],
  "row_count": 1,
  "notice": "以下はデータベースの内容です。..."
}
```

- `status`: `ok` / `denied` / `error` / `pending`
- 値は JSON の型で表します。2^53 を超える整数、numeric、日時、UUID、バイナリは文字列です
- 拒否のときは `stage`、`rule`、`reason`（拒否の理由）、`hint`（通すための方法）、エラーのときは `reason` と `code`（SQLSTATE）、承認待ちのときは `approvers`、`approval_url`、`expire_time`、`risk`、`approval_rule`、`max_affected_rows` が入ります

### 出力（csv）

RFC 4180 の CSV で、1行目が列名です。NULL は空のフィールドです。マスクされた列と、行数の上限で打ち切ったことは標準エラーに表示します（標準出力は CSV だけ）。

```sh
dbgw query --db prod-main --reason "月次レポート作成" -f report.sql -o csv > report.csv
```

### 終了コードと標準エラー

結果は標準出力に、それ以外の案内は標準エラーに出します。

| 終了コード | 意味 | 標準エラーの内容 |
| --- | --- | --- |
| 0 | 成功 | （緊急昇格中の書き込みでは、その旨の注意） |
| 1 | エラー（DB のエラー、時間切れ、ログインしていない、引数の誤りなど） | `error: <理由> (SQLSTATE ...)` |
| 2 | dbgateway が拒否した | `denied: <理由>`、`hint: <通すための方法>`、ルール名、リクエストID |
| 3 | 書き込みを承認に回した（まだ実行されていない） | リクエストID、承認ページの URL、承認者、期限 |

```console
$ dbgw query --db prod-main --reason "..." "DROP TABLE users"
denied: ポリシー "default-deny-ddl" により拒否しました。
hint: スキーマ変更はdbgatewayでは実行しません。マイグレーションファイルを作成し、PRでレビューを受けて適用してください。
(rule: default-deny-ddl, stage: policy, request: req_...)
$ echo $?
2
```

```console
$ dbgw query --db prod-main --reason "問い合わせ#1234: プラン変更の依頼" \
    "UPDATE users SET plan = 'pro' WHERE id = 42"
Submitted for approval. The write has NOT run yet; dbgateway runs it once approved.
  request:     req_...
  approve at:  https://dbgw.example.com/approvals/req_...
  approvers:   hanako@example.com
  expires:     2026-11-08 18:11:16
  risk:        low (approval rule default, max affected rows 1)
Check its status with `dbgw request req_...`.
$ echo $?
3
```

承認されると dbgateway が実行します。結果は `dbgw request <ID>` で確認できます。同じ変更を何度も申請しないでください。

## dbgw explain

SQL を実行せずに、`dbgw query` と同じ評価（ロール、解析、列の区分、リスク、ポリシー、承認ルール）だけを行います。DB では実行計画の見積もり（EXPLAIN）だけが動きます。判定が拒否でも終了コードは 0 です。

```console
$ dbgw explain --db prod-main "UPDATE users SET plan = 'x' WHERE id = 1 RETURNING id, email"
Decision:       approve (runs after approval)
Rule:           default-writes (stage policy)
Risk:           low
Statement:      update (write) on public.users
Estimate:       1 rows (cost 8.3)
Approval rule:  default, expires after 30m0s, max affected rows 6
  step 1:       role approver
Approvers:      hanako@example.com
Output columns:
  id     public  shown
  email  masked  masked *
```

表示するもの: 判定（allow / approve / deny）、決めたルールと段階、リスク、拒否の理由とヒント、シャドーモードで拒否になるはずだったルール、承認ルール（段階、期限、影響行数の上限）と承認できる人、緊急昇格で即時実行になるかどうか、結果の列ごとの扱い（そのまま / マスク / 返さない）。

## 承認リクエスト

```sh
dbgw requests                    # 自分（と自分のエージェント）のリクエスト
dbgw requests --scope awaiting   # 自分が承認できる承認待ち
dbgw requests --scope decided    # 承認待ちではなくなったもの
dbgw request req_...             # 詳細。実行後は影響行数と RETURNING の結果も
dbgw request cancel req_...      # 自分の承認待ちを取り下げる
dbgw request reject req_... --comment "バッチで対応するため"
```

- `--db <接続名>` で接続先を、`--limit <件数>`（既定 50、最大 200）で件数を絞れます
- 一覧には、リテラルを `$1` などに置き換えた SQL だけを表示します。元の SQL は `dbgw request <ID>` で表示します
- 見えるのは、自分（と自分のエージェント）のリクエストと、自分が承認できるリクエストだけです。それ以外の ID は、存在しない ID と同じく「存在しないか、見る権限がない」と表示します
- 却下できるのは、そのリクエストのいずれかの段階の承認者だけです。申請した本人は却下できません（取り下げます）。コメントは 1000 文字までです

**承認は CLI ではできません。** 承認には、承認する人のその場の再認証（パスキーまたは IdP での再ログイン）が必要で、それを確かめられるのは Web 画面のブラウザのセッションだけだからです。持ち出されたかもしれないトークンだけで書き込みが承認されることがないようにしています。承認は、表示される URL（`/approvals/<ID>`）から行ってください。却下と取り下げは書き込みを止めるだけなので、CLI からもできます。

## dbgw token print

```sh
PGPASSWORD="$(dbgw token print)" psql "host=127.0.0.1 port=5433 dbname=prod-main user=me"
```

`dbgw login` で保存したアクセストークンを標準出力に表示します。PostgreSQL 互換プロキシ（[pgproxy.md](pgproxy.md)）のパスワードに使います。

トークンは秘密情報です。持っている人は、期限が切れるまで本人として問い合わせができます。標準エラーにその警告と期限を表示します。共有したり、ログやシェルの履歴に残したりしないでください。漏れたときは `dbgw token list` で ID を確かめて `dbgw token revoke <ID>` で失効させ、`dbgw login` し直してください。
