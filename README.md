# CTF Challenge Collector

Python 3.10 の標準ライブラリだけで動く、pull-only の CTF 問題収集ツールです。
CTFd と rCTF から問題 metadata と添付ファイルを GET し、再現可能なディレクトリと
`manifest.json` に保存します。問題提出、unlock、更新などの書き込み API は呼びません。
ただし、認証済みの CTFd 詳細 GET は CTFd サーバー側で `Tracking` row を書き込むため、
GET-only はサーバー側も副作用がないという意味ではありません。

## 必要環境

- Python 3.10 以上
- 追加パッケージなし

launcher はリポジトリ直下の `./ctf-collect` です。

## 最短の使い方

安全な設定雛形を作ります。既存ファイルは上書きしません。

```console
./ctf-collect init --config ./collector.json
```

CTF ごとに token ファイルを作り、設定の `token_file` から参照します。token の値を
JSON 設定へ直接書かないでください。

```console
mkdir -p secrets
umask 077
printf '%s\n' 'YOUR_TOKEN_HERE' > secrets/example-ctfd.token
./ctf-collect sync --config ./collector.json
```

名前を指定すると、その CTF だけを同期します。

```console
./ctf-collect sync --config ./collector.json --ctf example-ctfd
```

## 設定

完全な例は [`config.example.json`](config.example.json) にあります。相対パスは設定
ファイルがあるディレクトリを基準に解決されます。

各 `ctfs` 要素の主な項目は次のとおりです。

- `name`: CTF の一意な名前
- `platform`: `ctfd` または `rctf`
- `base_url`: API の基準 URL。HTTP(S) のみで、query は指定不可
- `token_file`: token だけを格納したファイル
- `output_root`: 収集先の親ディレクトリ
- `tls.verify`: TLS 証明書を検証するか。通常は `true`
- `tls.ca_file`: 任意の CA bundle
- `timeouts.request_seconds`: 1 回の request timeout
- `retries.max_attempts`: GET の最大試行回数（1〜10）
- `retries.backoff_seconds`: exponential backoff の初期値
- `retries.max_retry_after_seconds`: `Retry-After` と backoff の待機上限
- `limits.page_size`: CTFd の `per_page`（最大 100）
- `limits.max_pages`: CTFd の最大ページ数
- `limits.max_file_bytes`: 添付 1 個の最大 byte 数
- `limits.max_total_bytes`: 1 回の CTF 同期で受理する添付の合計上限
- `limits.max_redirects`: 手動で検証する redirect の上限
- `limits.max_metadata_bytes`: JSON response の最大 byte 数
- `unauthenticated_attachment_origins`: 匿名 GET を許可する外部 origin の配列
- `fail_on_partial`: 一部失敗を終了コード 1 にするか。既定値は `true`

`fail_on_partial` は top-level に既定値を置き、CTF ごとに上書きできます。数値には
実装上の安全な上限があり、範囲外の設定は開始前に拒否されます。
既定値以外の custom `output_root` を使う場合は、収集物や添付を誤って commit
しないよう、そのパスをリポジトリの `.gitignore` に追加してください。

## API の読み方

CTFd は `/api/v1/challenges` を bounded pagination し、各
`/api/v1/challenges/{id}` の詳細を取得します。`meta.pagination` の `pages`、`page`、
`next` があればそれを使用します。metadata がない互換 response は空ページまで読み、
短いページだけを終端とはみなしません。同一ページの反復、新規 ID が増えないページ、
終端でない `next` が現在ページ + 1 でない pagination、その他の矛盾、または
`max_pages` 到達は silent success にせず、manifest に
構造化した部分失敗を記録します。`data` の array/object と、文字列または object の
`files` を扱い、不正な attachment entry があっても他の正常な entry は処理します。
summary の `type` が `hidden` の項目はアクセス不能として manifest に構造化した失敗を
記録し、匿名化された ID に対する詳細 GET は行いません。

rCTF は次の list route を順に試します。次の route へ進むのは 404 の場合だけです。

1. `/api/v1/challs`
2. `/api/v1/challenges`
3. `/api/challs`

fallback response は direct array、および `data`、`challs`、`challenges` 内の
array/object を扱います。公式 rCTF の `/api/v1/challs` は
`kind: goodChallenges` を検証して完全な list response として扱い、存在しない detail route
は呼びません。fallback route を使う fork でだけ、list item の `detail_url`、
`detailUrl`、`_links.detail`、または同一 origin の API `url` から明示された detail
link をたどります。推測した submit/unlock route にはアクセスしません。

rCTF が HTTP 401 の JSON envelope を返した場合、`kind: badNotStarted` は
`rctf_not_started`、`kind: badToken` は `auth_error` として区別し、retry や fallback
を行いません。error response も `limits.max_metadata_bytes` の上限内だけ読みます。

## 認証と URL の安全性

- HTTP method は常に GET です。
- CTFd の metadata/API GET は同一 origin にだけ
  `Authorization: Token ***` を送り、CTFd 3.8.6 が GET の token を認識するために
  `Content-Type: application/json` も必ず送ります。
- rCTF は同一 origin にだけ `Authorization: Bearer ***` を送ります。
- 添付 GET は JSON の request ではないため `Content-Type` を送りません。同一 origin
  の添付には認証 header を送りますが、許可した外部 origin の添付には
  `Content-Type` と `Authorization` のどちらも送りません。
- 自動 redirect は無効です。すべての `Location` を解決し、scheme、origin、
  redirect 回数を request 前に再検証します。
- 外部 origin は `unauthenticated_attachment_origins` に完全一致する場合だけ添付
  GET を許可します。
- metadata/API の redirect は同一 origin だけです。
- token、Authorization、cookie、secret 系 metadata と URL の query/fragment は
  永続化前に redact します。サーバーが token 値を本文へ反射した場合も保存しません。

TLS 検証を無効にすると通信相手を認証できません。閉じた検証環境以外では
`tls.verify: true` を使ってください。
`http://` の `base_url` では token と取得内容が平文で流れるため、loopback や隔離済みの
検証ネットワーク以外では `https://` を使用してください。

## 出力

出力は次の形式です。

```text
OUTPUT_ROOT/
└── ctf-safe-name/
    ├── manifest.json
    └── category/
        └── challenge-id-safe-name/
            ├── challenge.json
            └── files/
                └── attachment.bin
```

パス要素から traversal、絶対パス、separator、control 文字、Windows device 名を
除去します。CTF 名は同じ `output_root` 内で sanitize 後に大文字小文字を無視して
一意でなければなりません。同期対象すべての token を出力や HTTP より先に読み、
いずれかの token を含む CTF 名は拒否します。検証と収集はどちらも raw の CTF 名へ
同じ sanitize を適用します。保存処理は各 component を `O_DIRECTORY|O_NOFOLLOW` で
開いた directory fd に固定し、root 内を指すものも含めて symlink を拒否します。
必要な directory-fd API がない OS では安全性を弱めず、開始前に明示的に失敗します。

`challenge.json` の `raw` は取得 metadata を保持しますが、上記の機密値と URL query
だけは redact します。添付は mode `0600` の排他的 `.part` へ streaming し、上限を
逐次確認して `fsync` 後に atomic replace します。replace 後にも、保持した directory
fd と現在の ancestry/identity を再検証します。移動を検出した場合は保持した fd から
今回作成した target を削除して directory を `fsync` し、`unsafe_path` で失敗します。
この処理は添付、`challenge.json`、`manifest.json` に共通です。失敗時の `.part` は
削除されます。

`manifest.json` は時刻を含めず、安定した順序で書きます。各添付に query/fragment を
除いた表示用 source URL、CTF root からの相対パス、size、SHA-256、status、および
full validated source URL の HMAC-SHA256 identity を記録します。identity は現在の
認証 token を key とし、URL の query を保存せずに query-only の変更も区別します。
失敗は code/message を持つ object です。再実行時は、以前の manifest にある size と
SHA-256 の両方を現在ファイルで再検証でき、かつ現在 token で計算した source identity
が一致するものだけ download を省略します。identity のない旧 manifest は再取得します。

安全性の境界は、信頼しない remote metadata と、開始前から存在する symlink を含む
出力 path です。同じ UID で同時実行される悪意ある process は user 所有の出力を任意に
変更できるため、confidentiality/integrity の境界外です。検出できた directory 移動は
失敗させ、今回作成した target を上記の方法で cleanup しますが、同じ UID の adversary
に対して数学的に race-free であるとは主張しません。

## 終了コード

- `0`: 完全成功、または `fail_on_partial: false` の部分成功
- `1`: download/API の失敗、または既定設定での部分成功
- `2`: CLI、設定、CTF 名選択など開始前のエラー

複数 CTF の同期では、token/CTF 名/出力 directory の preflight に失敗した場合は
どの CTF も収集せず終了します。preflight 完了後の個別の失敗では、可能な CTF を続行し、
最後に集約した終了コードを返します。

部分失敗では今回の `manifest.json` が `status: partial` と失敗一覧を保持します。一方、
API 取得や安全な出力準備などが fatal error で終了した attempt は最終 manifest を
置き換えません。その場合、以前の manifest や添付が stale output として残り得るため、
終了コード 1/2 の実行後に既存出力だけを今回の成功結果として扱わないでください。

## テスト

```console
python3 -m unittest discover -v
```

統合テストは `ThreadingHTTPServer` を loopback 上に立て、CTFd/rCTF、pagination、
認証 header、redirect、retry、上限、部分失敗、再実行を検査します。socket を禁止する
sandbox では同じシナリオの memory transport テストが実行され、loopback 統合テスト
だけが理由付きで skip されます。
