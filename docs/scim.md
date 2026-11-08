# SCIM によるユーザーとグループの同期

dbgateway は SCIM 2.0（RFC 7643 / RFC 7644）のエンドポイントを持ち、Okta や Microsoft Entra ID からユーザーとグループを同期できます。同期したグループは OIDC のグループと同じく `groups[].oidc_group` で dbgateway のグループに対応づけられ、IdP でユーザーを無効化すると dbgateway のセッションとトークンもすぐに失効します。

## 有効化

```yaml
scim:
  enabled: true
  token_env: DBGW_SCIM_TOKEN   # ベアラートークンを入れた環境変数の名前
```

- トークンは長いランダム値にします（例: `openssl rand -base64 48`）。32文字未満だと設定の読み込み時に警告が出ます
- 環境変数が空のときは、すべての SCIM リクエストを 401 で拒否します（失敗したら止める）
- `enabled: false`（既定）のときは `/scim/v2/` 以下はすべて 404 です
- トークンは IdP の管理画面にだけ登録し、ほかの用途に使い回さないでください。比較は定数時間で行います

エンドポイントのベース URL は `<server.public_url>/scim/v2` です（例: `https://dbgw.example.com/scim/v2`）。

## 対応範囲

Okta と Entra ID のプロビジョニングが実際に使う範囲に絞っています。

| リソース | 操作 |
| --- | --- |
| `/Users` | POST（作成）、GET（一覧。`filter=userName eq "..."`、`externalId`、`id`、`emails.value` の `eq` と `and`、`startIndex` / `count`）、GET `/Users/{id}`、PUT（置き換え）、PATCH（`add` / `replace` / `remove`）、DELETE |
| `/Groups` | POST、GET（一覧。`displayName`、`externalId`、`id`、`members[value eq "..."]` で絞り込み、`excludedAttributes=members`）、GET `/Groups/{id}`、PUT、PATCH（メンバーの追加・削除・置き換え、名前の変更）、DELETE |
| `/ServiceProviderConfig`、`/ResourceTypes`、`/Schemas` | GET（上の範囲だけを説明する最小限の内容） |

- 応答の Content-Type は `application/scim+json`、エラーは SCIM のエラー形式（`status`、`scimType`、`detail`）です
- 未対応: Bulk、並べ替え、ETag、`/Me`、パスワード変更、ネストしたグループ、`or` や `co` / `sw` などの演算子
- dbgateway が保存するユーザー属性は `userName`、`externalId`、`name`、`displayName`、`emails`、`active` だけです。それ以外の属性（`title`、`phoneNumbers`、エンタープライズ拡張など）は受け付けて無視します
- グループの PATCH は 204 No Content を返します。ユーザーの PATCH は更新後のユーザーを返します
- 一覧の `count` の上限は 200 です

## ユーザーの対応づけ

SCIM のユーザーは **メールアドレス** で dbgateway のユーザーに対応づけます。使うのは次の順で最初に見つかったものです（小文字にそろえます）。

1. `emails` のうち `primary: true` のもの
2. `emails` のうち `type: "work"` のもの
3. `emails` の先頭
4. `userName`（メールアドレスの形のとき）

このメールアドレスは OIDC ログインの `email` クレームと一致している必要があります。Okta では既定で一致します。Entra ID では `userName` が UPN、`emails[type eq "work"].value` が `mail` 属性になるので、ID トークンの `email` クレーム（`mail`）と同じものが使われます。

メールアドレスが変わった場合、古いメールアドレスのトークンとセッションは失効し、古いユーザーのグループは空になります。

## グループの対応づけ

SCIM のグループの `displayName` が IdP のグループ名として扱われます。

```yaml
groups:
  - name: analysts
    oidc_group: dbgw-analysts   # SCIM のグループ名（OIDC のグループ名と同じ扱い）
```

ユーザーのグループが変わるたびに（グループの作成・削除・名前変更、メンバーの追加・削除、ユーザーの有効化・無効化）、そのユーザーの IdP グループ一覧（ログイン時に記録しているもの）を、所属する SCIM グループの `displayName` の集合で書き換えます。権限はトークンの検証時に毎回この一覧から計算するので、変更は次のリクエストから効きます。

### OIDC のグループとの優先順位

- SCIM が有効で、ユーザーが SCIM で同期されているときは、**SCIM のグループがログイン時の ID トークンのグループを置き換えます**。ログインしても ID トークンの `groups` クレームは使いません
- SCIM で同期されていないユーザー（SCIM を有効にする前からいるユーザーなど）は、これまでどおりログイン時の `groups` クレームを使います
- SCIM でユーザーを作成した時点で、そのユーザーの IdP グループは（グループが同期されるまで）空になります。Okta ではユーザーの割り当てとグループのプッシュを両方設定してください
- `members` に書いた静的なメンバーは SCIM と関係なく有効です

## 無効化と削除

- `active: false` にしたユーザー（PATCH、PUT、作成時のいずれでも）と、DELETE したユーザーは、同じトランザクションの中で次を行います
  - そのユーザーのトークン（そこから発行されたエージェントのトークンやリフレッシュトークンも含む）をすべて失効させる
  - ブラウザのセッションをすべて削除する
  - IdP グループを空にする
- 無効化・削除されたユーザーはログインできず、トークンも使えません。削除したユーザーは SCIM からは見えなくなりますが、記録を残してロックしたままにします。IdP が同じユーザーをもう一度作成すると、新しいユーザーとして使えるようになります（失効したトークンは戻りません）
- SCIM を後から無効にしても、無効化・削除済みのユーザーはロックされたままです

## IdP の設定

### Okta

1. アプリケーションの「Provisioning」で「SCIM」を有効にする
2. SCIM connector base URL: `https://dbgw.example.com/scim/v2`
3. Unique identifier field for users: `userName`（または `email`）
4. Supported provisioning actions: 「Push New Users」「Push Profile Updates」「Push Groups」
5. Authentication Mode: 「HTTP Header」、Authorization に `DBGW_SCIM_TOKEN` の値（`Bearer` は Okta が付ける）
6. 「To App」で「Create Users」「Update User Attributes」「Deactivate Users」を有効にする
7. 「Push Groups」で、`groups[].oidc_group` に書いたグループをプッシュする

### Microsoft Entra ID

1. エンタープライズアプリケーションの「プロビジョニング」で、モードを「自動」にする
2. テナントの URL: `https://dbgw.example.com/scim/v2`
3. シークレットトークン: `DBGW_SCIM_TOKEN` の値
4. 「テスト接続」で確認する
5. 属性マッピングは既定のままでよい（`userName` ← `userPrincipalName`、`emails[type eq "work"].value` ← `mail`、`active` ← `Switch([IsSoftDeleted], ...)`）。dbgateway が保存しない属性のマッピングは削除しておくと、同期のたびに差分が出るのを避けられます
6. 「ユーザーとグループ」で、同期するグループを割り当てる。グループ名が `groups[].oidc_group` と一致するようにする

## 認証側の確認（実装メモ）

SCIM で無効化されたユーザーを止めるため、認証は次を行います。

- ログイン時: `UpsertUser` の代わりに `store.SQLite.RecordLogin(ctx, email, idTokenGroups, now, cfg.SCIM.Enabled)` を呼び、`store.ErrUserInactive` ならログインを拒否する
- トークンの検証時とセッションの利用時: `store.SQLite.UserActive(ctx, email)` が false なら拒否する（エラーのときも拒否する）

## 値の中身による個人情報の検出

```yaml
pii_detection:
  enabled: true
  detectors: [email, phone_jp, credit_card, my_number]   # 省略するとすべて
  action: mask            # mask | deny（省略すると mask）
```

エージェントに返す `public` の列（マスクしない列）の値を検査し、個人情報が含まれていたら伏せます。列の区分（`data_classes`）の付け忘れを補う安全網であり、区分の代わりではありません。

| 検出器 | 見つけるもの |
| --- | --- |
| `email` | メールアドレス（`local@domain.tld`、TLD は英字2文字以上） |
| `phone_jp` | 日本の電話番号。携帯・IP電話（070/080/090/050 の11桁）、固定電話（10桁）、0120/0800、`+81` 表記。ハイフン・空白・括弧の有無を問わず、全角数字も対象 |
| `credit_card` | 13〜19桁のカード番号（空白・ハイフン区切り可）。先頭が2〜6で、Luhn のチェックに通るものだけ |
| `my_number` | 12桁の個人番号（`1234 5678 9018` のような4桁区切りも可）。検査用数字が正しいものだけ |

- 長い文章の中にあっても見つけます（例: `my card is 4111 1111 1111 1111`）
- `mask` は見つかった部分だけを `****` に置き換えます（`カード 4111 1111 1111 1111` → `カード ****`）。JSON の配列やオブジェクトの中の文字列も対象です。数値の列はまるごと `****` になります
- `deny` は結果全体を返しません
- 誤検出を減らすため、英数字に続く番号（`ID123456789012`、`ORD-123456789018`）、小数、区切り方が不自然な数字の並び、検査用数字・Luhn に通らない番号は対象にしません。12桁の注文番号は、検査用数字が偶然合う場合（約1割）に限ってマイナンバーとして伏せられます
- 処理量を抑えるため、文字列ごとに先頭 4 KiB、1つの値（JSON）あたり合計 16 KiB・1024 要素・深さ 8 までを検査します。それより後ろにある個人情報は見つけられません
