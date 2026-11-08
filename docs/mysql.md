# MySQL アダプタ

dbgateway は PostgreSQL に加えて MySQL（8.0 以降、推奨は 8.4 LTS）に対応しています。解析・ポリシー・マスキング・監査は PostgreSQL と共通で、DB ごとの違いは `internal/adapter/mysql` に閉じています。

- パーサ: TiDB の SQL パーサ（`github.com/pingcap/tidb/pkg/parser`）
- ドライバ: `github.com/go-sql-driver/mysql`

## 設定

```yaml
databases:
  - name: prod-mysql
    type: mysql
    labels: { env: prod }
    primary:
      host: mysql.internal
      port: 3306              # 省略時 3306
      dbname: app             # 必須。既定のデータベース
      read_user: dbgw_reader
      password_env: DBGW_MYSQL_READER_PASSWORD
      sslmode: verify-full    # disable | require | verify-full（省略時 verify-full）
      sslrootcert: /etc/dbgateway/mysql-ca.pem
    replica:                  # 任意。dbname を省略すると primary と同じ
      host: mysql-replica.internal
      read_user: dbgw_reader
      password_env: DBGW_MYSQL_READER_PASSWORD
    limits:
      max_rows: 1000
      max_bytes: 1MiB
      statement_timeout: 10s  # max_execution_time に設定する
      lock_timeout: 2s        # lock_wait_timeout / innodb_lock_wait_timeout に設定する（秒単位に切り上げ）
```

- **スキーマ = MySQL のデータベース。** 列の区分（`data_classes`）や監査ログでは `app.users.email` のように `データベース名.表名.列名` で書きます。
- **`search_path` は `[dbname]` だけ。** MySQL は修飾されていない表名を既定のデータベースからしか探さないため、省略するか `dbname` と同じ1要素にします（それ以外は設定エラー）。他のデータベースの表は `other_db.table` と修飾すれば読めます（権限とポリシーが許せば）。
- `sql.allowed_functions` には関数名（`my_func`）か、ストアドファンクションならデータベース名で修飾した名前（`app.my_func`）を書きます。修飾した名前は、修飾して呼び出したときだけ一致します。

### TLS（`sslmode`）

| `sslmode` | 動作 |
| --- | --- |
| `disable` | TLS を使わない（ループバック以外の prod では警告） |
| `require` | TLS で暗号化するが、サーバー証明書を検証しない |
| `verify-full` | サーバー証明書を `sslrootcert`（省略時はシステムのルート証明書）で検証し、ホスト名も確認する |

`allow` / `prefer` / `verify-ca` は MySQL では使えません（設定エラー）。go-sql-driver では「CA は検証するがホスト名は確認しない」設定を素直に表せないため、`verify-ca` は用意していません。Amazon RDS / Aurora では RDS の CA バンドルを `sslrootcert` に指定して `verify-full` を使ってください。

### 読み取り用ユーザー

```sql
CREATE USER 'dbgw_reader'@'%' IDENTIFIED BY '...';
GRANT SELECT, SHOW VIEW ON app.* TO 'dbgw_reader'@'%';
```

- `SHOW VIEW` は、ビューの定義（`information_schema.VIEWS.VIEW_DEFINITION`）を読むために必要です。定義が読めないビューは列の出どころを追跡できないため、そのビューを参照するクエリは「判断できない（unknown）」になり、自動許可されません。
- `PROCESS`、`FILE`、`SUPER` などの管理権限や、`mysql` / `performance_schema` の権限は付けないでください。

## sql_mode の前提

dbgateway は、すべてのセッションで `sql_mode` を次の値に固定し、パーサも同じモードで字句解析します。解析した文と実際に実行される文の区切り方（文字列・識別子・コメント）を一致させるためです。

```
ANSI_QUOTES,NO_BACKSLASH_ESCAPES,ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,
NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION
```

利用者（人・AI）に影響する点:

- **`ANSI_QUOTES`: `"..."` は識別子です（PostgreSQL と同じ）。** 文字列は必ず `'...'` で書きます。`WHERE name = "taro"` は列 `taro` の参照になり、列が見つからないため「判断できない」かDBのエラーになります。識別子はバッククォート `` `...` `` でも書けます。
- **`NO_BACKSLASH_ESCAPES`: 文字列の中のバックスラッシュはただの文字です。** 引用符は `''` と重ねて書きます（`'it''s'`）。`'\n'` は改行ではなく `\` と `n` の2文字です。クライアント側のパーサとサーバーでエスケープの解釈が食い違う、という典型的な抜け穴をなくすためです。
- 残りは MySQL 8.4 の既定値です。
- アプリケーションが別の `sql_mode` を使っていても、dbgateway のセッションにだけ適用されるので影響しません。

ビューの定義は、MySQL が `information_schema` に出力する形式（識別子はバッククォート、文字列はバックスラッシュでエスケープ）に合わせて、別のモード（`ANSI_QUOTES` のみ）で解析します。

## 実行時の安全策

- 読み取りは専用の接続で、次の順に実行します。
  1. `SET SESSION sql_mode = ..., time_zone = '+00:00', max_execution_time = <statement_timeout>, lock_wait_timeout = <lock_timeout>, innodb_lock_wait_timeout = <lock_timeout>`
  2. `START TRANSACTION READ ONLY`
  3. 文をサーバー側のプリペアドステートメント（`COM_STMT_PREPARE`）で実行する。クライアント側での値の埋め込み（`interpolateParams`）と複数文（`multiStatements`）は無効
  4. 行数とバイト数の上限をかけて結果を読み、上限を超えた後も総行数を数える
  5. `ROLLBACK`
- **接続は1回使うごとに破棄します。** MySQL には SQL からセッションをリセットする文（PostgreSQL の `DISCARD ALL` 相当）がなく、go-sql-driver は `COM_RESET_CONNECTION` を送らないため、プールに戻さずに閉じます。リクエストごとに接続を張り直す分（TLS ありで数ミリ秒〜数十ミリ秒）遅くなりますが、セッション状態が次のリクエストに漏れることはありません。
- `LOAD DATA LOCAL INFILE` はクライアント側でも拒否されます（`allowAllFiles` は無効、読み取り可能なファイルの登録なし）。
- 書き込み（承認後の実行）は、`write_user` で読み書きのトランザクションを開き、影響行数（一致した行数。`CLIENT_FOUND_ROWS` を有効にしているため、値が変わらない行も数える）が上限以下のときだけコミットします。MySQL には RETURNING がないため、結果の行は返しません。書き込みの見積もり（EXPLAIN）は、MySQL が READ ONLY トランザクションでの書き込みの EXPLAIN を拒否するため、`write_user` の読み書きのトランザクションで行い、必ずロールバックします。
- 見積もり（`estimate`）は `EXPLAIN FORMAT=JSON` から求めます。行数は外側の問い合わせの表ごとの `rows_produced_per_join`（なければ `rows_examined_per_scan`）の最大値、コストは `query_cost` です（`explain_json_format_version=2` の `estimated_rows` / `estimated_total_cost` にも対応）。統計情報が古いと見積もりも不正確になるので、必要に応じて `ANALYZE TABLE` を実行してください。

### 値の変換

| MySQL の型 | 返す値 |
| --- | --- |
| 整数 | 数値（`BIGINT UNSIGNED` で 2^63 以上は文字列） |
| `DECIMAL` | 文字列（精度を落とさないため） |
| `FLOAT` / `DOUBLE` | 数値 |
| `DATETIME` / `TIMESTAMP` | RFC 3339 の文字列（UTC。セッションの `time_zone` は `+00:00`） |
| `DATE` | `YYYY-MM-DD` |
| `TIME` | `HH:MM:SS` の文字列 |
| `JSON` | 解析したJSONの値 |
| `BINARY` / `VARBINARY` / `BLOB` / `GEOMETRY` | `\x` + 16進（PostgreSQL の `bytea` と同じ） |
| `BIT` | 数値 |
| 文字列型・`ENUM` / `SET` | 文字列 |

### DBのエラー

MySQL のエラーメッセージには値が含まれることがあります（例: 1292 `Truncated incorrect DOUBLE value: '...'`）。`mysql.DescribeError` は、識別子しか含まないと分かっているエラー（列や表が存在しない、構文エラー、権限不足など）だけメッセージを返し、それ以外は番号だけを返します。時間切れ（3024）とロック待ちの時間切れ（1205）は専用のメッセージにします。

## 解析段階で拒否するもの

PostgreSQL と同じく、設定に関係なく拒否します（失敗したら止める）。`testdata/bypass/mysql.yaml` に抜け穴集があります。

- 解析できないSQL、複数の文、空の文
- 実行可能コメント `/*! ... */`、`/*!NNNNN ... */`、`/*T! ... */`、`/*M! ... */` と、オプティマイザヒント `/*+ ... */`。**文字列の中に書いた場合も拒否します**（文脈によらない単純な検査にして、検査自体が引用符でだまされないようにするため）
  - 理由: MySQL はバージョン番号がサーバーより新しい `/*!NNNNN ... */` の中身を無視しますが、パーサは常に中身を解析します。`SELECT /*!99999 email AS id, */ id FROM users` のように、解析結果と実際に返る列がずれるとマスキングをすり抜けられます。ヒントの `MAX_EXECUTION_TIME` / `SET_VAR` はセッションの制限を外せます
- 制御文字（改行・タブ以外）と不正な UTF-8（`--` コメントの判定などで MySQL とパーサの解釈が分かれるため）
- トランザクション制御（`BEGIN` / `START TRANSACTION` / `COMMIT` / `ROLLBACK` / `SAVEPOINT` / `RELEASE SAVEPOINT` / `XA`）
- `SET`（`SET @x`、`SET ROLE`、`SET PASSWORD`、`SET NAMES`、`SET TRANSACTION` などすべて）
- ユーザー変数（`@x` の参照と `@x := ...`）、システム変数（`@@...`）。サーバーのバージョンは `VERSION()`、既定のデータベースは `DATABASE()` で取得できます
- パラメータ（`?`）
- `LOAD DATA` / `LOAD XML` / `IMPORT INTO`、`SELECT ... INTO OUTFILE / DUMPFILE / @var`
- `FOR UPDATE` / `FOR SHARE` / `LOCK IN SHARE MODE`、`LOCK TABLES` / `UNLOCK TABLES`
- `HANDLER`、`CALL`、`DO`、`PREPARE` / `EXECUTE` / `DEALLOCATE`、`USE`、`KILL`、`FLUSH`、`SHUTDOWN` などの管理文
- `EXPLAIN`（`ANALYZE` 付きも、なしも）、`DESCRIBE`、`SHOW`（表や列は `search_objects` で調べます）
- `SQL_CALC_FOUND_ROWS`
- 許可リストにない関数

`GRANT` / `REVOKE` / `CREATE USER` などのユーザー管理、`ANALYZE TABLE` / `OPTIMIZE TABLE`、`CREATE` / `ALTER` / `DROP` / `RENAME` は DDL（`stmt.kind == "ddl"`）、`INSERT` / `REPLACE` / `UPDATE` / `DELETE`（複数表を含む）は書き込み、`TRUNCATE` は `truncate` に分類します。`UPDATE` / `DELETE` の `WHERE` の有無は `stmt.has_where` に入ります。

### 関数の許可リスト

既定では、副作用のない組み込み関数（集計、ウィンドウ、文字列、数値、日付、JSON、ハッシュ、`VERSION()` などの情報関数）だけを許可します。次は既定で含みません。

| 関数 | 理由 |
| --- | --- |
| `LOAD_FILE` | サーバー上のファイルを読む |
| `SLEEP`、`BENCHMARK` | 時間稼ぎ・負荷 |
| `GET_LOCK`、`RELEASE_LOCK`、`RELEASE_ALL_LOCKS`、`IS_FREE_LOCK`、`IS_USED_LOCK` | ロック |
| `MASTER_POS_WAIT`、`SOURCE_POS_WAIT`、`WAIT_FOR_EXECUTED_GTID_SET` など | レプリケーションの待機 |
| `group_replication_*`、`asynchronous_connection_failover_*` | レプリケーションの操作 |
| `LAST_INSERT_ID`、`FOUND_ROWS`、`ROW_COUNT` | セッション状態（`LAST_INSERT_ID(expr)` は値を設定する） |
| `UUID_SHORT` | サーバー全体のカウンタを進める（無害だが状態を変えるので外した） |
| `NEXTVAL` / `SETVAL` / `LASTVAL` | シーケンス |
| `PASSWORD`、`ENCODE`、`DECODE`、`VALIDATE_PASSWORD_STRENGTH` | 削除済み・パスワード関連 |
| ストアドファンクション、UDF（`sys_exec` / `sys_eval` など） | 中身が分からない |

空間関数（`ST_*`）や暗号化関数の一部も既定では含みません。必要なら `sql.allowed_functions` で追加します。

## 列の出どころ（リネージ）

PostgreSQL と同じ規則で、結果の各列と、条件・集計・並べ替えに使われた列を元の表の列まで追跡します。

- 表・別名・`*` / `t.*` / `db.t.*`、派生表（`LATERAL` を含む）、CTE（再帰CTEは不動点まで繰り返す）
- ビュー: `information_schema.VIEWS` の定義を再帰的に展開する。ビューの内部の条件は利用者が選んだものではないので、利用者の列の使い方としては記録しない
- 結合: `ON`、`USING`、`NATURAL`（MySQL の列の並び順どおりに、共通列 → 1つ目の表の残り → 2つ目の表の残り。`RIGHT JOIN` では右の表が1つ目）。`USING` / `NATURAL` の共通列は比較に使われるので filter として記録する
- 式の中のサブクエリ（スカラー、`EXISTS`、`IN`、`ANY` / `ALL`）、`UNION` / `INTERSECT` / `EXCEPT`、ウィンドウ関数、`GROUP_CONCAT(... ORDER BY ...)`
- `GROUP BY` / `HAVING` / `ORDER BY` での別名・位置（`ORDER BY 2`）の参照。MySQL は句によって別名と入力列のどちらを優先するかが異なるため、両方に一致する名前は両方の列を使ったものとして記録する（危険側に倒す）
- 使い方の区分は PostgreSQL と同じ（output / filter / group / order / other / write）

### 名前の大文字・小文字

- 列名は大文字・小文字を区別せずに照合します（MySQL と同じ）。
- 表名・データベース名は、MySQL では `lower_case_table_names` によって区別されることがあります（Linux の既定は区別する）。dbgateway のカタログは大文字・小文字を区別せずに表を探すため、**大文字・小文字だけが違う表（`Users` と `users`）が両方あるときは、どちらもカタログから外し**、参照すると「判断できない」にします。違う表に解決してしまうことはありません。
- 表の別名は、完全に一致するものを優先し、大文字・小文字の違いだけで複数に一致するときは「判断できない」にします。

## 制限事項

- TiDB のパーサが対応していない構文は解析できず、拒否します。例: `JSON_TABLE`、派生表の列名リスト（`AS t(a, b)`）、`SELECT ... INTO @var` / `INTO DUMPFILE`、`BEGIN WORK`、`HANDLER`、`XA`、`CHECKSUM TABLE`、`CREATE TRIGGER` / `CREATE EVENT`。
- TiDB 独自の構文（`AS OF TIMESTAMP`、`TABLESAMPLE`、ヒント類など）は拒否します。
- `/*+` や `/*!` を文字列リテラルに含むクエリも拒否します（上記）。
- 書き込みの結果の行（RETURNING）は返せません（MySQL に RETURNING がないため）。
- `sql_mode` は固定で、利用者が変えることはできません（`SET` は拒否）。
- カタログは `information_schema.COLUMNS` / `TABLES` / `VIEWS` から、読み取り用ユーザーに見える範囲を読みます。`mysql` / `performance_schema` / `sys` / `information_schema` のビューは展開せず、元の表として扱います。`search_objects` では、スキーマを明示しない限りこれらのシステムスキーマを表示しません。
- `INVISIBLE` 列（`sql_generate_invisible_primary_key` で作られる `my_row_id` を含む）はカタログに入れません。`SELECT *` はこれらの列を返さないため、入れると `*` の展開と実際の結果がずれるからです。名前を明示して参照すると「判断できない」になります。
- 接続を毎回張り直すため、PostgreSQL より1リクエストあたりの遅延が少し大きくなります。

## 開発環境とテスト

```sh
docker compose -f examples/dev/mysql/compose.yaml up -d --wait   # MySQL 8.4 を 127.0.0.1:53306 で起動
go test ./internal/adapter/mysql/                                 # 単体テスト（解析・抜け穴集）
go test -tags integration ./internal/adapter/mysql/               # 実DBでの結合テスト
```

サンプルのスキーマとデータ（`users`、`subscriptions`、`orders`、`support_tickets`、ビュー `user_contacts`）は PostgreSQL の開発環境と同じで、読み取り用ユーザー `dbgw_reader`（パスワード `reader`、`SELECT` と `SHOW VIEW` のみ）を作成します。結合テストの接続先は環境変数 `DBGW_TEST_MYSQL_HOST` / `DBGW_TEST_MYSQL_PORT` / `DBGW_TEST_MYSQL_PASSWORD` / `DBGW_TEST_MYSQL_ROOT_PASSWORD` で変えられます。
