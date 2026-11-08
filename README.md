# dbgateway

AIエージェントが本番DBに触るときに必ず通す「SQLを理解する関所」です。MCPサーバーとして動き、受け取ったSQLを PostgreSQL 本体のパーサで解析して、**自動で通す・拒否する**（フェーズ2で**人の承認待ち**も）に振り分けます。人もAIも、同じ解析・ポリシー・マスキング・監査ログを通ります。

- 設計: [docs/dbgateway-design.md](docs/dbgateway-design.md)
- ライセンス: [Apache-2.0](LICENSE)（ガバナンス機能を有償版に分けません）
- 脆弱性の報告: [SECURITY.md](SECURITY.md)

> **状態: フェーズ1（読み取りMVP）。** 書き込みは常に拒否し、「承認機能がまだ有効ではない」と理由を返します。承認、Slack、パスキー、緊急昇格はフェーズ2以降です。

## できること（フェーズ1）

| 機能 | 内容 |
| --- | --- |
| MCPツール | `list_databases`、`search_objects`、`execute_sql`（Streamable HTTP） |
| 解析段階の拒否 | 解析できないSQL、複数文、トランザクション制御、`SET`/`RESET`、`DO`、`COPY`、`EXPLAIN`、`SELECT ... INTO`、`FOR UPDATE`、`CALL`、`LOCK`、`NOTIFY`、`PREPARE`、許可リストにない関数（`pg_read_file`、`dblink`、`set_config` など） |
| ポリシー | YAMLのルール＋CELの条件式。上から評価して最初に一致したものを採用、一致しなければ拒否。`allow` が書き込みやDDLに一致しうる設定は読み込み時にエラー |
| マスキング | 列ごとに `public` / `masked` / `no_ai`。ビュー、別名、式、サブクエリ、CTE、`SELECT *` を通しても元の列までたどって伏せる。AIが機密列を WHERE / GROUP BY / ORDER BY に使うと拒否 |
| 実行時の安全策 | 読み取り専用トランザクション、`statement_timeout`、`lock_timeout`、固定の `search_path`、行数とバイト数の上限、リクエストごとの `DISCARD ALL`、拡張プロトコル |
| 認証 | OAuth 2.1 の認可サーバー（PKCE必須、Client ID Metadata Documents優先、動的登録も可）、上流はOIDC。CLIはデバイスフロー。エージェントは人の代理の短命トークンで、権限は人以下 |
| 監査ログ | 拒否を含む全リクエストをJSON Linesで記録。ハッシュチェーン、保存期間、`dbgw audit verify`。書けなければ結果を返さない |
| 導入の補助 | 観察モード（`server.mode: shadow`）、`dbgw config validate`、`dbgw policy test` |

## クイックスタート（ローカル）

必要なもの: Go 1.27+（cgo が使えること）、Docker。

```sh
make dev-db     # PostgreSQL 17 をサンプルデータつきで起動（127.0.0.1:55432）
make run-dev    # examples/dev/dbgateway.yaml で起動（http://127.0.0.1:8443）
```

開発用の設定では `auth.dev_login: true` なので、パスワードなしでメールアドレスだけでログインできます（ループバックで待ち受けるときだけ有効）。

### Claude Code から使う（OAuth）

```sh
claude mcp add --transport http dbgateway http://127.0.0.1:8443/mcp
```

最初のツール呼び出しでブラウザが開き、ログインと同意（エージェント名と、許可する接続先）を行います。

### stdio のMCPクライアントから使う

```sh
dbgw login --server http://127.0.0.1:8443     # デバイスフロー。ブラウザでコードを確認
dbgw mcp stdio --agent my-agent               # 短命のエージェント用トークンを発行してHTTPに中継
```

OAuthに対応していないクライアントには、手動で短命トークンを発行できます。

```sh
dbgw token create --agent ci-report --databases dev-main --ttl 1h
dbgw token list
dbgw token revoke <id>
```

## 設定

設定は1つのYAMLファイルにまとめ、Gitで管理してPRでレビューします。秘密情報は環境変数の名前だけを書きます。

- 本番向けの例: [examples/dbgateway.yaml](examples/dbgateway.yaml)
- ローカル開発用: [examples/dev/dbgateway.yaml](examples/dev/dbgateway.yaml)

何も設定しなければ、読み取りだけを許可し、書き込みとDDLは拒否します。区分を指定していない列は、`env: prod` の接続ではAIに対して `masked` 扱いです。

### ポリシーのテスト（CI向け）

DBに接続せずに、「このSQLはこの判定・マスキングになるべき」を検証します。カタログ（表と列）はテストファイルに書きます。

```sh
dbgw config validate --config examples/dbgateway.yaml
dbgw policy test testdata/policy/*.yaml
```

例: [testdata/policy/example_test.yaml](testdata/policy/example_test.yaml)

### 監査ログの検証

```sh
dbgw audit verify --config dbgateway.yaml
```

## 開発

```sh
make lint               # go vet, gofmt, buf lint
make test               # ユニットテスト（抜け穴集 testdata/bypass を含む）
make test-integration   # Docker の PostgreSQL に対する結合テスト
make generate           # proto から connectRPC のコードを生成
```

| ディレクトリ | 内容 |
| --- | --- |
| `cmd/dbgw` | CLI（serve, login, mcp, token, config, policy, audit） |
| `internal/analysis` | DBに依存しない解析結果の型と `Adapter` インターフェース |
| `internal/adapter/postgres` | pg_query_go による解析、カタログ、見積もり、実行 |
| `internal/policy` | ロールの確認とCELの評価 |
| `internal/mask` | データ区分とマスキング |
| `internal/audit` | 監査ログ（JSON Lines、ハッシュチェーン、保存期間） |
| `internal/gateway` | 全段階をつなぐパイプライン（MCP以外の入口も共通で使う） |
| `internal/mcp` | MCPツールの定義 |
| `internal/auth` | OAuth 2.1 の認可サーバー、OIDC連携、トークン |
| `internal/api`, `proto/` | connectRPC のAPI（MCP以外のAPIはprotobufで定義） |
| `internal/store` | 管理用DB（SQLite） |
| `testdata/bypass` | 拒否されるべきSQLの一覧（抜け穴集） |
| `testdata/policy` | ポリシーのテスト |

DBアダプタを追加するときは、`analysis.Adapter` を実装し、`testdata/bypass` と同じ観点のテストを用意してください。
