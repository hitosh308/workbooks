# DEV-002 / POC-01 — Google OIDC・本人再認証

## 目的と判定

F002、F007、IF001 および AC02-007〜010、AC02-030 のうち、Google OIDC の認可コードフローと、重要操作直前に同一の Google アカウントで本人再認証したことを確認できるかを検証した。会員の代わりに、初回ログインで検証した Google の `sub` を PoC 専用のサーバーセッションに保持した。規約同意を伴う新規登録、管理者認証、退会処理は今回の検証範囲外。

| 検証項目 | 判定 | 根拠 |
| --- | --- | --- |
| PoC 実装・自動試験 | PASS | HTTP モックと合成 ID トークンによる検証。署名検証は実ライブラリを使用 |
| ローカル HTTP スモーク試験 | PASS | 検証画面、CSRF 付き POST、セッション保持、Google 宛リダイレクト、模擬キャンセルの結果表示 |
| Google OIDC 実接続 | BLOCKED | OAuth 検証用クライアントが未設定。認可コード取得と交換は未実行 |
| Google によるオンデマンドの本人再認証 | BLOCKED | Google はアプリからの Google アカウント再認証要求をサポートしないと明記している |
| Composer ロック全体の脆弱性監査 | BLOCKED | Packagist の監査 API への接続が環境のプロキシから HTTP 403 を返した |
| **POC-01 総合** | **BLOCKED** | Google 実接続が未確認で、重要操作の開始に合わせて Google 再認証を強制できない |

## ライブラリと選定理由

**`firebase/php-jwt` v7.2.2**（BSD-3-Clause）を採用した。既存の CakePHP 5.4.5 と PHP 8.4.28 に適合し、既存の CakePHP HTTP Client で Google のコード交換と JWKS 取得を行える。JWT ライブラリが公開鍵の取り込み、RS256 署名の照合、有効期限などの JWT 検証を担い、アプリが OIDC に固有のクレームとトランザクションを検証する。選定時点で v7.2.2 のリリースと公式の検証 API を確認した。既存の依存パッケージの更新は 0 件で、追加はこの 1 件。RSA 検証に使用する OpenSSL 拡張が実行環境で有効なことも確認した。[公式リポジトリ](https://github.com/googleapis/php-jwt/tree/v7.2.2) · [Packagist](https://packagist.org/packages/firebase/php-jwt)

比較した `google/apiclient` は Apache-2.0 の Google 公式クライアントで、Google API を広く扱い、保守モードで重大バグとセキュリティ修正が提供される。今回は CakePHP の HTTP 機能を再利用し、追加依存を署名検証に絞れる `firebase/php-jwt` を採用した。[Google APIs Client Library for PHP](https://github.com/googleapis/google-api-php-client)

## 実装と実現可能性

- 有効化は `POC_GOOGLE_OIDC_ENABLED=1` の明示設定で行う。ルートは PoC プレフィックスに限定し、開始は CSRF 保護付き POST、コールバックは GET。state・nonce・PKCE verifier はサーバー側で生成する。既存の PHP ファイルセッションのロック下でトランザクションを読み出して消費し、成功・拒否・キャンセル後の再送を拒否する。同じセッションで新たに開始すると前のトランザクションは失効する。
- Discovery に基づき PKCE `S256` と RS256 を使用。コード交換と JWKS 取得は TLS を検証し、タイムアウトを設け、リダイレクト追従を無効にした。ID トークンの `iss`、`aud`、存在する場合の `azp`、`exp`、`iat`、`nonce` と `sub` を検証する。成功時にセッション ID を更新し、検証済み `sub` を保持する。アクセストークン、ID トークン、メール、プロフィールは保存・表示しない。エラー画面には固定メッセージを表示する。[Google Discovery](https://accounts.google.com/.well-known/openid-configuration) · [Google OIDC API リファレンス](https://developers.google.com/identity/openid-connect/reference)
- 個人情報を最小化するため PoC は `scope=openid` のみリクエストする。Google の OIDC リファレンスでは `profile` または `email` の併用が記載されているため、この最小スコープで実クライアントを使った認証が成立するかは未確認。Google が追加スコープを要求した場合は、取得される項目と必要性をオーナーに報告し、承認後に検証する。[Google OIDC リファレンスの認証リクエスト](https://developers.google.com/identity/openid-connect/reference#authenticationrequest)
- 再認証要求には `claims={"id_token":{"auth_time":{"essential":true}}}` と、検証用に `max_age=0` を付ける。OIDC Core では `max_age=0` は `prompt=login` 相当だが、Google のリファレンスは `max_age` を掲載しておらず、`prompt` に掲載されている値は `none`、`consent`、`select_account`。Google はアプリからの再認証要求を非サポートとしている。PoC は `max_age` の効力に依存しない。[OIDC Core §3.1.2.1](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) · [Google OIDC API リファレンス](https://developers.google.com/identity/openid-connect/reference) · [Google Security Bundle](https://developers.google.com/identity/siwg/security-bundle)
- 再認証を受け入れる条件は、検証済みの `sub` が再認証開始時と現在の PoC セッションの両方に一致し、署名済み ID トークンの整数 `auth_time` が開始時刻より後で、受信時点から 300 秒以内、かつ発行時刻と現在時刻より後でないこと。300 秒は PoC のトランザクション上限で、承認済みの本番値ではない。秒単位で前後が確定しない開始同秒の結果は拒否する。`iat`、同意、アカウント選択は本人認証の証拠として扱わない。Google の認証時刻が条件に合えば鮮度を確認できるが、アプリがその Google 認証を毎回起こせる保証はない。[Google Security Bundle — Authentication time](https://developers.google.com/identity/siwg/security-bundle#authentication-time)

## 変更ファイル

| ファイル | 内容 |
| --- | --- |
| `composer.json`、`composer.lock` | JWT ライブラリの追加とロック |
| `config/.env.example` | 有効化フラグと OAuth 設定のダミー値 |
| `config/routes.php`、`src/Application.php` | PoC のルーティングとサービス登録 |
| `src/Poc/GoogleOidc.php` | PKCE、コード交換、JWT と鮮度の検証 |
| `src/Controller/Poc/GoogleOidcController.php` | 開始・コールバック、セッション、結果表示 |
| `templates/Poc/GoogleOidc/index.php` | Bootstrap の SSR 検証画面 |
| `tests/TestCase/Controller/Poc/GoogleOidcControllerTest.php` | CakePHP の HTTP 統合試験と Google 通信のモック |
| `webroot/index.php` | チェックアウトに欠けていた HTTP エントリーポイント |
| `docs/poc-results.md` | 本結果書 |

## 実行コマンドとテスト結果

既存クラウド環境では `export PATH=/workspace/.workbooks-runtime/bin:$PATH` を設定した。PHP 8.4.28、PHPUnit 12.5.45、テスト用 SQLite を使用。本番 DB や Google の実クライアントには接続していない。

| コマンド・試験 | 結果 |
| --- | --- |
| 変更前の `vendor/bin/phpunit` | PASS。既存 9 テスト、23 アサーション |
| `composer install --no-interaction --no-scripts` | PASS。GitHub API のアーカイブ取得は HTTP 403。ロック済みの同一コミットの公式アーカイブを GitHub codeload から一時 Composer キャッシュに取得してインストール |
| `composer validate --strict` | PASS |
| `vendor/bin/phpunit --filter GoogleOidcControllerTest` | PASS。PoC の 21 テスト、227 アサーション |
| `vendor/bin/phpunit` | PASS。既存を含む 30 テスト、250 アサーション |
| `vendor/bin/phpcs --report=summary` | PASS |
| `git diff --check` | PASS |
| ローカル PHP サーバーと `curl` | PASS。ダミー OAuth 設定で画面・開始リダイレクト・模擬キャンセル確認。初回起動では既定セッション保存先を使えず HTTP 500。書込み可能な専用ディレクトリを指定して再試験 |
| `composer audit --locked` | BLOCKED。監査 API への接続が HTTP 403 |
| Google Authorization / Token / JWKS による OAuth 実接続試験 | BLOCKED。検証用 OAuth クライアント未設定 |

モック試験では、正常認証、state・nonce 不一致、不正署名・発行者・audience・azp、期限切れトークン、同一 sub での再認証、別 sub、古い・開始と同秒・将来の認証時刻、認証時刻欠落、取引期限切れ、キャンセル、正常・キャンセル両方のコールバックの再送、通信障害、PoC 無効時の全ルート、開始 POST の CSRF 保護を確認した。通信障害後に既存ホームが 200 で返ることも確認した。ホームはこのチェックアウトで使用できる既存のゲスト入口であり、学習機能全体の障害試験は実施していない。

## オーナー側の設定と再現手順

1. アプリ本番環境と分離した Google Cloud プロジェクトで、Google Auth Platform の同意画面と OAuth の「ウェブ アプリケーション」クライアントを設定する。検証専用のテストアカウントを使い、テスト公開の場合は対象アカウントをテストユーザーに追加する。
2. 承認済みのリダイレクト URI に `http://localhost:8765/poc/google-oidc/callback` を完全一致で登録する。ブラウザーとサーバーが別の環境なら、隔離した検証用 HTTPS ホストの URI に置き換え、`APP_FULL_BASE_URL` もそのホストに合わせる。コールバックのクエリ文字列をアクセスログやプロキシログに記録しないようにする。
3. `auth_time` の実測には、Google が要求する OAuth アプリの公開・確認済みステータスと、Google Auth Platform の **Settings → Advanced Settings → Session age claims** が必要。ここでの「In production」は Google の OAuth アプリ公開ステータス。検証専用プロジェクトを使用し、公開・審査が必要ならオーナーが判断する。設定できない場合は鮮度の実接続試験を BLOCKED と記録する。[Google Security Bundle — Setup](https://developers.google.com/identity/siwg/security-bundle#setup)
4. 既存手順で `config/app_local.php` を準備し、検証環境では CakePHP のログにコールバック URL が記録されないよう `'Error' => ['log' => false]` を追記する。下記の環境変数は検証プロセスのみに注入する。クライアントシークレットは環境のシークレット設定を使い、コマンド履歴、Git、チャットに貼らない。既存の `.env` 自動読込みは初期状態でコメントアウトされているため、実行プロセスに直接環境変数を渡す。

   ```sh
   composer install --no-interaction
   vendor/bin/phpunit
   composer audit --locked

   export DEBUG=false
   export APP_FULL_BASE_URL=http://localhost:8765
   export POC_GOOGLE_OIDC_ENABLED=1
   export POC_GOOGLE_CALLBACK_URL=http://localhost:8765/poc/google-oidc/callback
   # POC_GOOGLE_CLIENT_ID と POC_GOOGLE_CLIENT_SECRET は検証用環境から供給する
   poc_sessions=$(mktemp -d)
   php -d "session.save_path=$poc_sessions" -d log_errors=0 \
       -S localhost:8765 -t webroot webroot/index.php >/dev/null 2>&1
   ```

5. 検証専用ブラウザープロファイルで `http://localhost:8765/poc/google-oidc` を開く。初回ログインのあと、Google にログイン済みの状態から再認証を開始し、Google が新しい本人認証を要求するか、PoC がどう判定するかを確認する。別テストアカウント、既存セッションの再利用、キャンセルも試す。署名済み `auth_time` が開始後のケースを観測できても、Google が毎回その認証を強制できるという判定には使わない。試験記録は結果の区分と観測内容だけを残す。
6. 終了時にサーバーを停止し、専用セッションディレクトリとブラウザーの検証セッションを破棄して有効化フラグを戻す。

## 残課題と本実装への提案

- まず検証用クライアントで `openid` 単独、PKCE のコード交換、実際の `auth_time` の返却を確認する。Google の制約上、退会を Google 再認証だけで承認できるという判断は保留する。
- 要件変更案として、ログインの Google OIDC を維持し、退会直前にはサービス側で登録済みパスキーを用いた WebAuthn のユーザー検証を要求する。チャレンジを既存会員 ID と退会操作に結び付け、短時間・一度限りとする。登録・紛失時の復旧手順と受入条件はオーナー承認の対象。承認までは現行の退会要件を維持する。
- 本実装では JWKS を Google のキャッシュ指示に従ってキャッシュし、鍵の更新時に再取得する案を評価する。複数インスタンスでセッションを運用する場合は、コールバックの一度限りの消費を共有ストア上で原子的に保証する。再認証の結果は対象会員と対象操作に紐付け、処理直前に一度だけ使えるようにする。

## DEV-002 / POC-02 — 3独立セッション

検証日 2026-11-28（日本時間）。CakePHP 5.4.5、PHP 8.4.28、PHPUnit 12.5.45。ブランチは `poc02-independent-sessions`。初回検証は POC-01 を含まないコミット `8fc8f1a` で実施し、PR作成時に POC-01 がマージ済みの `main` に統合した。POC-02 は POC-01 を前提とせず、承認済み要件の変更は提案しない。

### 採用方式と選定理由

| 比較項目 | 検証結果・設計 |
| --- | --- |
| PHP / CakePHP 標準 Session の多重利用 | 起動中のネイティブセッションは PHP リクエストにつき1つ。Cookie名を変えた Session インスタンスを並べても、`$_SESSION` とネイティブハンドラは共有される。同一リクエストで3つを順に切り替える方式には、設定・状態の復元や保存順序の管理が必要。 |
| 採用方式 | ゲストの学習ペイロードは `Cake\Http\Session` の `read/write` で扱う。ゲスト処理の間だけネイティブセッションを開き、専用ハンドラがシリアライズ結果を受け取る。会員・管理者は独立したファイルの状態を参照し、PHP のネイティブセッションを開かない。3種別の状態を単一の GET で確認できる。 |
| セッションIDと保存領域 | 種別ごとに `__Host-poc02-guest`、`__Host-poc02-member`、`__Host-poc02-admin`。各IDは `random_bytes(32)` から独立に生成され、HTTP Cookie からのみ受け取る。保存キーはIDの SHA-256。保存領域は `tmp/poc02-sessions/{guest,member,admin}/`。PHP内部のゲストIDは外部に発行せず、アプリケーション上の保存キーにも使わない。 |
| CSRF | CakePHP のCookieベースの署名付きCSRFミドルウェアを PoC 専用Cookie `__Host-poc02-csrf` で使う。SSRフォームのトークンを全状態変更で検証する。3セッションの開始や終了とCSRFトークンの寿命は独立する。通常ルートの既存CSRF設定は維持した。 |
| 同時アクセス・保存失敗 | 種別ごとの安定したロックファイルに `flock` を取得する。ゲストでは期限確認、revision照合、CakePHPのデータ更新とシリアライズ、同一ディレクトリ内の `rename` によるコミットをロック内で実施する。競合は 409、保存エラーは 503。レスポンス描画はロック解放後。 |
| 通常ログアウトと全端末失効 | 通常ログアウトは対象レコードを削除し、対応Cookieを期限切れにする。ログイン成功時には旧IDのレコードを削除して新IDを発行する。アカウント無効化・管理者認証リセット時は、種別と対象アカウントの世代を原子的に変更して旧世代を拒否する。別端末のCookieは、その端末からの次回リクエストで削除する。 |
| 期限切れの削除 | アクセス時に無効レコードを削除し、アクセスされないレコードは `poc02_purge` で掃除できる。検証環境で定期実行を設定すれば未アクセス分も自動削除される。PHP既定の確率的GCはこの保存領域に使用しない。 |

| 種別 | 無操作期限 | 最大期限 | Cookie |
| --- | --- | --- | --- |
| ゲスト | 24時間 | 7日 | 絶対期限まで永続 |
| 一般会員 | 7日 | 30日 | 絶対期限まで永続 |
| 管理者 | 30分 | 8時間 | ブラウザセッションCookie |

全Cookieに `Secure`、`HttpOnly`、`SameSite=Lax`、`Path=/` を付け、`Domain` は指定しない。Lax は Google OIDC の一般的なクロスサイトのトップレベルGETコールバックと両立する。実際のGoogle連携は範囲外。生成・最終アクセス・最大期限はUTCのUnix秒で保存し、期限到達時点で失効する。Cookieの有効期限とサーバー側の最大期限はアクセスで延長しない。検証では時刻を注入した。

ゲストは明示操作で開始し、閲覧のみではゲストレコードやゲストCookieを生成しない。Cookieを削除して新規に開始すると空の学習状態になる。学習データに認証情報を格納せず、会員の学習データもコピーしない。互換性のない `schema_version` はゲスト学習データを初期化し、revisionを進め、SSR画面で通知する。簡易データで、回答500件を超えると終了済みの最も古い演習を削除できる場合に限り保存する。進行中データだけで上限に達した場合は保存を拒否する。ブックマーク100件では解除を案内する。

検証用画面は `POC02_ENABLED=1`、`APP_ENV=poc02-isolated`、デバッグ無効、Webサーバーが設定したHTTPS、ホスト直下の5条件を必要とする。固定の架空アカウント2件を会員・管理者それぞれの名前空間で使う。Cookie値やセッションIDは画面・PoCログに出力せず、セッション画面は `Cache-Control: no-store, private` を返す。学習履歴DB、会員DB、本番DBへの接続は行わない。

### 試験結果

**判定 PASS（PoCの実装・検証範囲）。**

| 検証区分 | 成功 | 失敗 | 未実施 |
| --- | ---: | ---: | ---: |
| PHPUnit／PoC-02 | 17 | 0 | 0 |
| PHPUnit／既存 | 9 | 0 | 0 |
| Chromium／ローカルTLS | 4 | 0 | 0 |
| 外部連携の実環境検証 | 0 | 0 | 2 |

- PHPUnit は CakePHP の実HTTP処理とネイティブPHPセッションを使用する。TLSの代わりにテストルーターがサーバー側の `HTTPS` を設定し、クライアント側では応答のCookieヘッダーを検査する。3種別の共存・独立ログアウト、ログイン後の旧ID、アカウント単位の全端末失効、別アカウントへの非波及、逆種別Cookie、期限境界、期限延長防止、CSRF、無効環境、schema_version、容量、掃除を検証した。
- 同じゲストCookieとrevisionを、別々のPHPプロセスへ並行送信した。応答は 200 が1件と 409 が1件で、保存された回答は1件だった。書き込み権限を外した試験では 503 が返り、元データは維持された。
- Chromium 156 では実際のローカルTLS上で、3種別の共存とCookie属性・ゲスト保存、別サイトからのトップレベルGET、ブラウザプロファイル再起動後のゲスト・会員の継続、復元された管理者Cookieの無操作30分での失効を検証した。TLS証明書は試験用に生成し、Chromiumにテスト証明書の公開鍵をピン留めした。PHP側のHTTPS情報はテスト用ルーターで設定した。
- 外部連携の未実施2件は実Google OIDCとMySQL上の認証・学習連携。PoCはファイルのみを使い、既存PHPUnitのテストDBはインメモリSQLiteに切り替えた。

### 技術的制約、本実装への影響、未解決事項

- Chromiumの同じプロファイルを再起動した際、永続化属性のない管理者Cookieも復元された。初回の追加試験で想定した「再起動直後に管理者Cookieが必ず消える」という挙動は確認できなかった。ブラウザ終了をサーバー側で確実に観測する手段はなく、復元後もサーバーが無操作30分と最大8時間を適用する。重要な管理操作で都度の本人確認が必要かは、本認証設計で決める。
- 種別単位のファイルロックは単一ホストの検証向け。ゲスト更新は他のゲストと同じロックを使う。複数ホスト構成では共有ストアの原子操作を使い、停止・退会・認証リセットとアカウント世代の更新を整合させる。会員と管理者の名前空間は分ける。DBテーブルの追加はない。
- ゲスト学習データのフォーマット、上限時の利用者導線、同期、DB排他、冪等性、OWNER・ADMINの認可は後続工程で扱う。Google OIDC実装ではコールバックの応答モードと `state`・`nonce`・PKCE を実環境で確認する。

### 再現手順

1. 既存のComposer依存があるチェックアウトを用意する。Codex Cloudの今回の環境では `export PATH=/workspace/.workbooks-runtime/bin:$PATH` で既存PHPを使える。
2. 全PHPUnitは `DATABASE_URL=sqlite:///:memory: DATABASE_TEST_URL=sqlite:///:memory: php vendor/bin/phpunit`。PoCのみ実行するときは同コマンドに `tests/TestCase/Poc02` を追加する。HTTP試験はループバックの空きポート、一時領域、PHP cURLを使用する。
3. 実ブラウザ試験は Python Playwright、Chromium、OpenSSL がある環境で `python3 tests/Support/Poc02/browser.py`。PHPの実行パスは `POC02_PHP`、Chromiumの実行パスは `POC02_CHROMIUM` で指定できる。一時証明書とブラウザプロファイルを生成して終了時に破棄する。
4. 手動確認では、専用のHTTPSホストに既存のCakePHPフロントコントローラを置き、公開ディレクトリを限定してリポジトリと `tmp` は公開しない。WebサーバーでHTTPSリクエスト時にPHPの `HTTPS=on` を設定する。隔離したPHPプロセスに `APP_ENV=poc02-isolated POC02_ENABLED=1 DEBUG=0 APP_FULL_BASE_URL=https://<隔離検証ホスト>` を設定し、`/poc02/sessions` を開く。ゲスト保存、会員・管理者ログイン、個別ログアウトを確認する。
5. 放置レコードの掃除は、同じ検証環境と実行ユーザーで `APP_ENV=poc02-isolated POC02_ENABLED=1 php bin/cake.php poc02_purge`。PoCを継続稼働させる場合は同コマンドを定期実行に登録する。

### 変更ファイル

- ルート・ミドルウェア `config/routes.php`、`src/Application.php`、`src/Middleware/Poc02AccessMiddleware.php`
- セッション処理 `src/Poc02/SessionKind.php`、`src/Poc02/SessionStore.php`、`src/Poc02/Sessions.php`、`src/Poc02/GuestSessionHandler.php`、`src/Poc02/GuestLearning.php`、`src/Command/Poc02PurgeCommand.php`
- 検証画面 `src/Controller/Poc02/SessionsController.php`、`templates/Poc02/Sessions/index.php`
- テスト `tests/TestCase/Poc02/SessionsHttpTest.php`、`tests/Support/Poc02/router.php`、`tests/Support/Poc02/browser.py`
- 検証記録 `docs/poc-results.md`
