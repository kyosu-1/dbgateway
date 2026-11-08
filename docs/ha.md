# dbgateway の冗長構成（複数台での運用）

dbgateway を複数台で動かすための手順です。既定の管理用DB（SQLite）は1台でしか使えないため、複数台にするときは管理用DBを PostgreSQL にします。設計の背景は [フェーズ2〜4 詳細設計](design-phase2-4.md) の「管理用DBの PostgreSQL 対応（冗長構成）」と「監査ログの出力先の追加」を参照してください。

## 1. 構成

```
             ┌──────────────┐
  利用者 ──► │ ロードバランサ │ ──► dbgateway #1 ─┐
  エージェント │ （TLS 終端）   │ ──► dbgateway #2 ─┼──► 管理用DB（PostgreSQL）
             └──────────────┘ ──► dbgateway #3 ─┘     ・トークン、セッション、承認リクエスト、SCIM
                                        │              ・監査ログ（audit.output: postgres の場合）
                                        └──────────► 接続先のDB（本番の PostgreSQL など）
```

- すべての台が同じ管理用DBを使い、トークン、ブラウザのセッション、OAuth のコード、承認リクエスト、緊急昇格、SCIM で同期したユーザーとグループを共有します
- ロードバランサのスティッキーセッションは不要です。どの台にリクエストが届いても同じ結果になります（ログイン途中の状態は Cookie に、セッションは管理用DBにあります）
- 承認されたリクエストは、どの台からでも1回だけ実行されます。各台の定期処理は承認済みのリクエストを探して実行を試みますが、状態を `approved → running` に変えられた（条件付き更新に勝った）1台だけが実行します。実行中に台が止まった場合は、一定時間後にほかの台が「結果不明の失敗」にします（再実行はしません）
- 認可コード、デバイスコード、リフレッシュトークンの使い回し防止も、条件付き更新で台をまたいで1回だけになります

### 1.1 設定

```yaml
store:
  driver: postgres           # sqlite（既定）| postgres
  dsn_env: DBGW_STORE_DSN    # 接続文字列（DSN）を入れた環境変数の名前

audit:
  output: postgres           # file（既定）| stdout | postgres
  # dsn_env: DBGW_AUDIT_DSN  # 監査ログを別のDB・別のロールに書くとき。省略時は store.dsn_env
  retention: 400d
```

- DSN にはパスワードが含まれるため、設定ファイルには環境変数の名前だけを書きます（`dsn_env` に DSN そのものを書くと設定の検証で拒否します）
- DSN の例: `postgres://dbgateway:<password>@mgmt-db.internal:5432/dbgateway?sslmode=verify-full&pool_max_conns=10`
- 1台あたり、管理用DB用と監査ログ用にそれぞれ接続プールを持ちます。`pool_max_conns`（既定は CPU 数と 4 の大きいほう）× 2 × 台数が、管理用DBの `max_connections` に収まるようにします
- `audit.output: postgres` は `store.driver: postgres` のときだけ使えます
- すべての台で同じ設定ファイル（ポリシー、ロール、接続先、`server.public_url`）と同じ秘密（OIDC のクライアント、`masking.hmac_key_env` のキー、DB のパスワード）を使います。設定を変えるときは全台を順に入れ替えます。入れ替えの途中は台によって設定の版（`config_version`）が違うことを前提にしてください
- 承認の「実行中のまま止まった」判定は各台の時計を使うため、全台の時刻を NTP で合わせます

### 1.2 管理用DBの準備

管理用DBには専用のデータベースとロールを用意します。テーブルは dbgateway が起動時に作ります（マイグレーションは `schema_migrations` で版を管理し、アドバイザリーロックで直列化するので、複数台を同時に起動しても1回だけ適用されます）。

```sql
CREATE ROLE dbgateway LOGIN PASSWORD '<password>';
CREATE DATABASE dbgateway OWNER dbgateway;
```

- PostgreSQL 13 以降を想定しています（テストは 17 で行っています）。拡張機能は使いません
- 時刻は UTC（`timestamptz`）、リスト類は `jsonb` で保存します
- 管理用DBは、接続先の本番DBとは別のインスタンスにします（dbgateway が守る対象と、dbgateway の状態を同じ障害に巻き込まないため）
- 管理用DB自体の冗長化（Multi-AZ、レプリカへの自動フェイルオーバー）はマネージドサービスの機能を使います。フェイルオーバー中は管理用DBに書けないため、ログインやトークンの検証、監査ログの書き込みが失敗し、dbgateway は問い合わせを拒否します（安全側に倒れます）

## 2. 監査ログ

複数台のときの監査ログの置き場所は2通りです。

| 方式 | 設定 | 特徴 |
| --- | --- | --- |
| 管理用DBに1本 | `audit.output: postgres` | 全台で1本のハッシュチェーン。全台の記録をまとめて検索できる。書き込みは全台でアドバイザリーロックにより直列化される |
| 台ごとのファイル | `audit.output: file` | 台ごとに独立したチェーン。台ごとに `dbgw audit verify --dir` で検証し、ファイルを外部に保管する。検索できるのはその台の記録だけ |

### 2.1 管理用DBに書く場合（`audit.output: postgres`）

- 行の形式はファイルと同じです（1行の JSON、`prev_hash` と `hash`）。テーブル `audit_log` の `line` 列に行をそのまま保存し、検索用に時刻、リクエストID、イベント、判定、接続先、申請者、テーブルを別の列にも入れます
- 各台は、書き込みのたびに管理用DBのアドバイザリーロックを取り、最後の行のハッシュにつないでから追加します。そのため複数台でもチェーンは分岐しません。書き込みに失敗したら、その問い合わせの結果は返しません（ファイルと同じく安全側）
- 保存期間（`audit.retention`）を過ぎた行は、古い順に削除します。削除の前に、削除する最後の行のハッシュを `audit_checkpoints` テーブルに記録し、同じ内容をプロセスのログ（`audit checkpoint`）にも出します。検証に失敗する行は削除しません
- OTLP 転送（`audit.otlp`）を設定すると、管理用DBに保存したとおりの行（つなぎ直した後の行）を転送します

検証は設定ファイルから行います。

```sh
DBGW_STORE_DSN=... dbgw audit verify --config /etc/dbgateway/dbgateway.yaml
# ok: 12345 entries in the PostgreSQL audit log, chained from genesis; last hash <hash>
```

- 先頭の行は、ゼロのハッシュ（最初から）か、最新のチェックポイントにつながっていなければなりません。行の書き換え、削除、並べ替え、検索用の列と行の不一致は `FAILED` になり、終了コード 1 で終わります
- 管理用DBへの書き込み権限を持つ人は、末尾の行を消すことができます。ファイルの場合と同じく、最後のハッシュを毎日外部に記録するか、OTLP で別のログ基盤に送っておくと、末尾の切り詰めも見つけられます
- より強く守るなら、`audit.dsn_env` で監査ログ専用のロールを使い、そのロールから `audit_log` の `UPDATE` 権限を外します（テーブルは最初の起動時に作られるので、作成後に `REVOKE UPDATE ON audit_log FROM <role>` します。保存期間の削除に `DELETE` は必要です）

### 2.2 台ごとのファイルにする場合

各台の `audit.dir` は、その台だけが使うディレクトリ（共有ファイルシステムではなく）にします。複数台で同じディレクトリに書くとチェーンが壊れます。保管と検証の手順は [運用手順](operations.md) の「3. 監査ログの保存と検証」と同じで、台ごとに行います。

## 3. 管理用DBのバックアップと復元

**バックアップ**

マネージドサービスの自動バックアップ（ポイントインタイムリカバリ）を有効にします。論理バックアップを取る場合は次のとおりです。

```sh
pg_dump --format=custom --file=dbgateway-$(date -u +%F).dump "$DBGW_STORE_DSN"
```

管理用DBにはトークンなどの秘密そのものは入っていません（SHA-256 のハッシュだけです）が、利用者の一覧、承認待ちのSQL、監査ログを含むため、バックアップは本番データと同じ扱いで保管します。

**復元**

古い時点に戻すと、その後に行った「失効」や「実行」の記録も消えます。復元したら、dbgateway を起動する前に次を行います。

```sql
BEGIN;
-- バックアップ後に実行済みだった可能性がある承認リクエストを、再実行しないように失敗扱いにする
UPDATE approval_requests
   SET status = 'failed', finished_at = now(), version = version + 1,
       result_json = '{"rows_affected":0,"row_count":0,"duration_ms":0,"error":"管理用DBをバックアップから復元したため、結果は不明です。データベースを確認してください。"}'
 WHERE status IN ('approved', 'running');
-- バックアップ後に失効させたトークンやセッションが復活しないように、すべて無効にする
UPDATE tokens SET revoked_at = now() WHERE revoked_at IS NULL;
TRUNCATE sessions, auth_codes, device_codes;
COMMIT;
```

- トークンとセッションは失効させても、利用者が `dbgw login` やブラウザでログインし直し、エージェントを接続し直せば元に戻ります
- SCIM を使っている場合は、IdP から全件の再同期（プロビジョニングの再実行）を行い、バックアップ後に無効化・削除されたユーザーを反映させます
- 監査ログを管理用DBに置いている場合、復元した時点より後の行は失われます。OTLP の転送先や外部に記録したハッシュと突き合わせて記録を補います

## 4. SQLite からの移行

1台構成（SQLite）から PostgreSQL に移すときの手順です。

1. 管理用DB（PostgreSQL）を 1.2 のとおり用意する
2. dbgateway を止める
3. 設定ファイルを `store.driver: postgres` と `store.dsn_env` に変える（監査ログも移すなら `audit.output: postgres`）
4. SQLite の内容をコピーする（任意）

   ```sh
   DBGW_STORE_DSN=... dbgw store import-sqlite --from /var/lib/dbgateway/dbgateway.db --config /etc/dbgateway/dbgateway.yaml
   ```

   すべてのテーブル（ユーザー、トークン、セッション、OAuth クライアント、承認リクエスト、緊急昇格、SCIM のユーザーとグループ）を1つのトランザクションでコピーします。コピー先が空でなければ何もせずに終わります
5. dbgateway を起動し、`dbgw audit verify` とログインを確認してから台を増やす

コピーを省いても動きます。その場合は次のようになります。

- トークン、セッション、OAuth クライアントは引き継がれません。利用者はログインし直し、エージェントは接続し直します（MCP クライアントはクライアント登録からやり直します）。これらは発行し直せば済むものです
- 承認待ち・承認済みのリクエストは引き継がれません。移行の前に処理を終えておくか、移行後に申請し直します。過去の承認の記録は監査ログに残っています
- SCIM で同期したユーザーとグループは、IdP から全件を再同期します。削除済みユーザーの記録（ログインを拒否し続けるための記録）は引き継がれないため、IdP 側でもそのユーザーを無効にしておきます

監査ログは移行しません。`audit.output: file` のまま使い続けるか、`postgres` に切り替えた場合は、それまでのファイルを従来どおり保管・検証します（PostgreSQL 側のチェーンは最初から始まります）。

## 5. 確認項目

- [ ] 全台が同じ設定ファイルと同じ秘密を使っている
- [ ] 管理用DBの `max_connections` に、全台の接続プールの合計が収まる
- [ ] ロードバランサのヘルスチェックに `GET /healthz` を使っている
- [ ] 全台の時刻が NTP で合っている
- [ ] 管理用DBの自動バックアップを有効にし、復元の手順（3章）を確認した
- [ ] `dbgw audit verify` を毎日実行し、失敗を通知している
