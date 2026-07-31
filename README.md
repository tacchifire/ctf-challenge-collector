# CTF Challenge Collector

CTFdとrCTFから問題情報と添付ファイルをGETで収集する、Python 3.10以降向けのツールです。
追加パッケージは使いません。

問題提出、hintの解除、問題やアカウントの更新は行いません。
ただし、CTFdは認証済みの詳細GETをサーバー側で記録する場合があります。

## 使い方

設定雛形を作ります。
既存ファイルは上書きしません。

```console
./ctf-collect init --config ./collector.json
```

CTFごとにtokenファイルを作ります。
token自体はJSONへ書きません。

```console
mkdir -p secrets
umask 077
printf '%s\n' 'YOUR_TOKEN_HERE' > secrets/example-ctfd.token
```

`collector.json`には、CTFごとに変わる4項目を設定します。

```json
{
  "ctfs": [
    {
      "name": "example-ctfd",
      "platform": "ctfd",
      "base_url": "https://ctf.example.invalid",
      "token_file": "./secrets/example-ctfd.token"
    }
  ]
}
```

- `name`：CTFを識別する名前
- `platform`：`ctfd`または`rctf`
- `base_url`：CTFの基準URL
- `token_file`：tokenだけを保存したファイル

同期を実行します。

```console
./ctf-collect sync --config ./collector.json
```

一つだけ同期する場合は名前を指定します。

```console
./ctf-collect sync --config ./collector.json --ctf example-ctfd
```

相対パスは設定ファイルがあるディレクトリを基準に解決されます。
最小設定の例は[`config.example.json`](config.example.json)にもあります。

## オプション設定

次の項目は必要な場合だけ各CTFへ追加します。

| 項目 | 既定値 |
|---|---:|
| `output_root` | `./collected` |
| `tls.verify` | `true` |
| `timeouts.request_seconds` | `30` |
| `retries.max_attempts` | `3` |
| `retries.backoff_seconds` | `0.5` |
| `retries.max_retry_after_seconds` | `30` |
| `limits.page_size` | `100` |
| `limits.max_pages` | `100` |
| `limits.max_file_bytes` | `104857600`（100 MiB） |
| `limits.max_total_bytes` | `1073741824`（1 GiB） |
| `limits.max_redirects` | `5` |
| `limits.max_metadata_bytes` | `16777216`（16 MiB） |
| `unauthenticated_attachment_origins` | `[]` |
| `fail_on_partial` | `true` |

独自CAを使う場合は`tls.ca_file`を指定します。
`fail_on_partial`はトップレベルにも置け、各CTFの既定値として使えます。

対話端末で`Content-Length`が判明している添付がサイズ上限を超えると、CLIは必要なファイルサイズと合計サイズを表示します。
`yes`と入力した場合だけ、その添付に必要な有限量まで一時的に許可します。
非対話実行、サイズ不明の応答、絶対上限を超える応答は確認せずに部分失敗となります。
承認は設定値、次の添付、次回実行へ引き継ぎません。

外部の添付配信元を許可する場合は、originを完全なURLで指定します。
外部originへのGETには認証情報を送りません。

```json
{
  "ctfs": [
    {
      "name": "example-ctfd",
      "platform": "ctfd",
      "base_url": "https://ctf.example.invalid",
      "token_file": "./secrets/example-ctfd.token",
      "unauthenticated_attachment_origins": [
        "https://cdn.example.invalid"
      ]
    }
  ]
}
```

custom `output_root`を使う場合は、そのパスを`.gitignore`へ追加してください。

## 出力と終了コード

収集結果は既定で、設定ファイルと同じディレクトリの`collected/<安全化したCTF名>/`へ保存されます。
各問題の`challenge.json`、添付ファイル、収集状態を記録した`manifest.json`が生成されます。

| 終了コード | 意味 |
|---:|---|
| `0` | 完全成功、または`fail_on_partial: false`での部分成功 |
| `1` | APIや添付の失敗、または部分成功 |
| `2` | CLI、設定、同期対象の指定に関する開始前エラー |

部分成功では、今回の失敗が`manifest.json`に記録されます。
fatal errorで終了した実行はmanifestを置き換えないため、以前の出力がstaleな状態で残る場合があります。
終了コードが`1`または`2`のときは、既存ファイルだけで今回の成功を判断しないでください。

## 進捗表示

`sync`の実行中は、進捗をstderrへ出力します。
端末でも、pipeやredirectでも同じように出力します。
stdoutはCTFごとの結果行だけのままなので、進捗は混ざりません。

出力する内容は次のとおりです。

- CTFの開始と、完了、部分成功、失敗
- 問題一覧の取得と、取得した問題数
- 処理中の問題の位置、category、名前
- 添付の受信bytes、転送速度、保存、再利用、失敗

進捗行にはtoken、URL、応答本文を出しません。
失敗はerror codeだけを示します。
名前に含まれる改行やescape sequenceは除去するため、進捗行を偽造できません。
ダウンロード中の進捗行は経過時間と転送量で間引くので、chunkごとには出力しません。

## 安全上の境界

- HTTPメソッドはGETだけです。
- 認証情報は同一originのAPIと添付にだけ送ります。
- redirectと外部originは送信前に検証します。
- token、cookie、secret系metadata、URLのqueryとfragmentは保存前に除去します。
- 添付サイズと総量を制限し、一時ファイルからatomicに保存します。
- 出力先のsymlinkと危険なパス要素を拒否します。

同じUIDで同時に動く悪意あるプロセスは保護対象外であり、その相手に対するrace-freeな保存は保証しません。

通常はHTTPSと`tls.verify: true`を使ってください。
HTTPやTLS検証の無効化は、隔離した検証環境に限ってください。

## テスト

```console
python3 -m unittest discover -v
```
