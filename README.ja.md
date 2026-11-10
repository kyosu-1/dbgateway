# dbgateway

**AIエージェントと人が、本番DBを安全に使うための「SQLを理解する関所」です。**

dbgateway は PostgreSQL / MySQL と、そこに問い合わせるすべての人・AIの間に置きます。受け取った SQL をデータベース自身のパーサで解析し、ロールとポリシーに照らして **自動で通す・人の承認を待つ・拒否する** に振り分けます。結果は列の区分に従ってマスクし、拒否を含むすべてのリクエストを改ざんを検知できる監査ログに残します。

AIエージェントは [MCP](https://modelcontextprotocol.io)（OAuth）で、人は Web の SQL エディタと CLI で接続し、どちらも同じ確認を通ります。

📖 **ドキュメント（英語）: <https://kyosu-1.github.io/dbgateway/>** · [English README](README.md)

## 主な機能

- **SQL を理解する** — PostgreSQL は pg_query、MySQL は TiDB パーサで解析。複数文、トランザクション制御、副作用のある関数、解析しきれない SQL は拒否
- **ポリシーをコードで管理** — グループ、5つのロール、列の区分、CEL のルールを1つの YAML に。既定は拒否、観察モード、CI 向けの `dbgw policy test`
- **書き込みは人の承認つき** — リスク判定、多段の承認ルール、パスキーか IdP での再認証、SQL の固定、実行直前の再評価、影響行数の上限
- **出どころをたどるマスキング** — ビュー、CTE、式、`SELECT *` を通しても元の列まで追跡。`no_ai` の列はAIに渡さない。値の中身による個人情報の検出も可能
- **AIは人の代理** — OAuth 2.1 の同意と短命のトークン。AIの権限は代理元の人を超えない
- **Web 画面（日本語・英語）** — 補完・履歴・監査つきエクスポートのある SQL エディタ、承認、リクエスト、監査ログ、ユーザー
- **改ざんを検知できる監査ログ** — ハッシュチェーン、`dbgw audit verify`、書けなければ結果を返さない
- **本番向け** — AWS / Google Cloud の IAM データベース認証、レプリカ、複数台構成、Slack・Webhook 通知、SCIM

## クイックスタート

Docker と、リリースのバイナリが使える Linux または macOS（Apple シリコン）が必要です。それ以外の環境では Go（cgo が使えること）でビルドします（`make run-dev`）。

```sh
git clone --depth 1 https://github.com/kyosu-1/dbgateway.git && cd dbgateway
make download         # 最新リリースの bin/dbgw を取得
make serve-dev        # サンプルの PostgreSQL と dbgateway を起動（http://127.0.0.1:8443）
claude mcp add --transport http dbgateway http://127.0.0.1:8443/mcp
```

AIエージェントに `dev-main` について質問するか、<http://127.0.0.1:8443/console> を開いてください。開発用の設定は、ループバックでだけ使えるパスワードなしのログインです。詳しくは [Quickstart](https://kyosu-1.github.io/dbgateway/quickstart) を参照してください。

## 状態

初期段階のソフトウェアです。1.0 までは設定の形式、API、MCP ツールが変わることがあります。DB 側の最小権限のユーザーの代わりにはなりません。最後の守りとして残してください。

## 貢献とセキュリティ

貢献は歓迎します（[CONTRIBUTING.md](CONTRIBUTING.md)）。脆弱性は [SECURITY.md](SECURITY.md) の手順で非公開で報告してください。

## ライセンス

[Apache License 2.0](LICENSE)
