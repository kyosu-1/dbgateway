# PostgreSQL プロトコル互換のプロキシ

psql や DBeaver などの PostgreSQL クライアントから、dbgateway を通してデータベースを参照するための入口です。プロキシはデータベースに直接つながず、受け取った文を1つずつ `internal/gateway` に渡します。ロールの確認、SQLの解析、ポリシー、マスキング、監査ログは MCP や Web 画面と同じです。

## 設定

```yaml
pgproxy:
  listen: 127.0.0.1:5433             # 空なら無効（既定）
  tls_cert: /etc/dbgateway/tls.crt   # ループバック以外で待ち受けるなら必須
  tls_key: /etc/dbgateway/tls.key
  max_connections: 100               # 同時接続数の上限（既定 100）
  idle_timeout: 30m                  # 何も送られてこない接続を切るまでの時間（既定 30m）
```

- パスワードとしてトークンを受け取るため、ループバック以外のアドレスで待ち受ける場合は TLS が必須です。証明書がなければ設定の検証で失敗し、起動もしません
- ループバック以外では、TLS を使わない接続を `FATAL 28000` で拒否します

## 接続する

| 接続パラメータ | 指定する値 |
|---|---|
| `host` / `port` | `pgproxy.listen` のアドレス |
| `dbname` | dbgateway の接続名（`databases[].name`、例: `dev-main`） |
| `user` | 任意（記録用。権限はトークンの持ち主で決まります） |
| `password` | dbgateway のアクセストークン（`dbgw_at_...`） |
| `application_name` | 任意。文として読める内容なら理由として使います（後述） |

人として使うときは `dbgw login` で得たトークンを使います。トークンはユーザー設定ディレクトリの `dbgw/credentials.json` に保存されます（macOS は `~/Library/Application Support`、Linux は `~/.config`）。

```sh
dbgw login --server https://dbgw.example.com
TOKEN=$(jq -r .access_token "$HOME/.config/dbgw/credentials.json")
psql "host=dbgw.example.com port=5433 sslmode=verify-full dbname=dev-main user=me password=$TOKEN"
```

`dbgw token create` で発行したエージェント用トークンでも接続できます。その場合はエージェントとして扱われ、エージェント向けのマスキング（`no_ai` の列は NULL）とトークンの接続先の制限がかかります。

## 理由を指定する

dbgateway ではすべてのクエリに理由が必要です。プロキシでは次の順に理由を決めます。

1. セッションで `SET dbgw.reason = '...'` した値（`SET dbgw.reason TO '...'` も可。`RESET dbgw.reason` で消去）
2. 接続時の `application_name` が文として読める場合はその値（8文字以上で、空白か日本語を含み、`psql` や `DBeaver ...` のようなクライアント名でないもの）
3. どちらもなければ、その文は実行せずにエラー（SQLSTATE `42501`）を返します

```sql
SET dbgw.reason = '問い合わせ#1234の調査のため、該当ユーザーのプランを確認';
SELECT id, email, plan FROM users WHERE id = 3;
```

`SET dbgw.reason` はプロキシが受け取り、データベースには送りません。理由は監査ログに文ごとに記録されます。

## 応答の見え方

- 結果はテキスト形式で返します。拡張問い合わせプロトコルでバイナリ形式を求められた場合は、pgx のコーデックで変換して返します
- マスクした列は値が文字列になるため、型は `text` として返します。伏せた列（エージェントに対する `no_ai`）は NULL です
- マスクした列・伏せた列があるとき、行数の上限で打ち切ったとき、およびデータの扱いに関する注意は、NOTICE（打ち切りは WARNING）で知らせます
- 拒否されたときは `ERROR 42501` で、メッセージに理由、HINT に通すための方法、DETAIL に `request_id`（監査ログの検索用）とポリシーのルール名が入ります
- データベースのエラーは、dbgateway が返す SQLSTATE をそのまま使います（不明なら `XX000`）
- 承認待ちになった文（フェーズ2）は、NOTICE で承認待ちであることと `request_id`、承認画面の URL を知らせ、`UPDATE 0` のようなコマンドタグを返します。この時点では実行されていません

## 対応しているもの

- 簡易問い合わせプロトコル。1回の問い合わせに複数の文があれば PostgreSQL のパーサで分割し、1文ずつ dbgateway に送ります。途中の文がエラーになれば、残りは実行しません
- パラメータのない拡張問い合わせプロトコル（Parse / Bind / Describe / Execute / Close / Sync / Flush）。Describe で列を返すために、読み取りの文（SELECT、SHOW、EXPLAIN）はその時点で実行し、直後の Execute ではその結果を使います。書き込みの可能性がある文は Describe では実行しません
- プロキシが自分で応答する文（データベースには送りません）
  - `SET client_encoding`（UTF8 のみ）、`SET extra_float_digits`、`SET application_name`、`SET client_min_messages`、`SET DateStyle`・`SET TimeZone` など表示形式の設定（受け付けますが、形式は ISO・UTC 固定）
  - `SHOW`（`server_version`、`TimeZone`、`DateStyle`、`search_path`、`dbgw.reason` など。`SHOW ALL` も可）
  - `BEGIN` / `COMMIT` / `ROLLBACK`。コマンドタグは返しますが、各文はそれぞれ別のトランザクションで実行されることを NOTICE で知らせます
  - `SELECT version()`、`SELECT 1`（接続確認用）、`DISCARD ALL`、`DEALLOCATE`
- キャンセル要求（psql の Ctrl-C）。実行中の文を中止します

## 対応していないもの

- パラメータ付きの文（`$1` など）。値を SQL に直接書いてください（監査ログでは値は伏せられます）。pgx なら `default_query_exec_mode=simple_protocol`、JDBC なら `preferQueryMode=simple` が使えます
- `COPY`、関数呼び出しプロトコル、レプリケーション接続
- `SET search_path`（スキーマ名を付けて書いてください）、`SET ROLE` などの権限やセッションに関わる設定、`SAVEPOINT`、`PREPARE TRANSACTION`
- 複数の文をまとめたトランザクション
- psql の `\d` などのメタコマンドや、DBeaver のナビゲータが発行するカタログ問い合わせの多く。`pg_get_userbyid` などの関数が許可リストにないため拒否されます。表と列の確認は `dbgw` の MCP ツール（search_objects）か Web 画面を使ってください

## クライアントごとの注意

- psql: `sslmode=verify-full`（ループバックなら `disable` でも可）。`-c` を複数並べるか、スクリプトの先頭に `SET dbgw.reason` を書きます
- DBeaver: 「接続の初期化」（Bootstrap queries）に `SET dbgw.reason = '...'` を登録するか、`application_name` に理由を書きます。メタデータの読み込みはほとんど失敗するため、SQL エディタで使ってください
- pgx（Go）: すべての実行モードで動きますが、パラメータは使えません。パラメータを使うコードは `simple_protocol` にすると、pgx がクライアント側で値を埋め込みます

## 運用とセキュリティ

- 接続ごとにトークンを検証し、db:read スコープと、その接続先でクエリを実行する権限があるかを確認します。接続先が存在しない場合と権限がない場合は区別しません
- 監査ログの `trace_id` には接続ごとの ID（`pgproxy_...`）が入るため、同じセッションの文をまとめて追えます
- プロキシのログにはトークンも SQL も書きません（接続元、利用者、接続先、`request_id` だけ）
- 1メッセージは 4MiB まで、認証は 30 秒以内に終える必要があります。`max_connections` を超えた接続には `FATAL 53300` を返します
