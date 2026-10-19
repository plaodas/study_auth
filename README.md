# study-auth

FastAPI と async SQLAlchemy で、アクセス JWT と不透明リフレッシュトークンの発行・検証を追うためのリポジトリです。画面と予約ドメインはありません。

## アクセスは 15 分の RS256 JWT、リフレッシュは DB にハッシュだけ置く不透明トークンで、使用時に失効してローテーションする

ログインに成功すると、次の Cookie が付きます。レスポンスボディに生トークンは入れません。

- `access_token` は RS256 の JWT です。`exp` は timezone 付き UTC の現在時刻から `ACCESS_TOKEN_EXPIRE_MINUTES`（既定 15 分）です。HttpOnly です。
- `refresh_token` は `secrets.token_urlsafe` で作った生トークンです。JWT ではありません。HttpOnly です。有効期限の既定は `REFRESH_TOKEN_EXPIRE_DAYS`（7 日）です。
- `csrf_token` は署名付きの CSRF トークンです。HttpOnly ではありません。

リフレッシュトークンは HMAC-SHA256 のハッシュだけを `tokens` に保存します。HMAC の鍵は `SECRET_KEY` です。生トークンはレスポンスの Cookie に一度だけ載せ、以降は復元できません。

`POST /api/auth/refresh` は、ハッシュが一致し、未使用・未失効・期限内の行を `used_at` で原子的に消費します。成功したら新しい生トークンを発行します。消費済みの生トークンはもう一度使えません。

`POST /api/auth/logout` はそのユーザーの DB 上のトークンを失効し、`access_token` / `refresh_token` / `csrf_token` を消します。失効できるのは DB にハッシュがあるトークンです。アクセス JWT はサーバに控えないので、Cookie から外したあとも、すでに手元にある JWT は `exp` までは署名検証に通ります。

パスワードは bcrypt です。`POST /api/auth/signup` はメール、パスワード、名前を受け取り、未検証ユーザーと確認用の生トークンを作ります。確認 URL はログに出します。`GET /api/auth/confirm?token=` がそのトークンを一度だけ消費し、`mail_verified` を true にします。未検証の同じメールでもう一度 signup したときは、その行の名前とパスワードを更新します。検証済みのメールは 400 です。

ログインは `POST /api/auth/token` です。フォームの `username` にメールアドレスを入れます。未検証ユーザーは 403 です。`GET /api/auth/me` はアクセス JWT の動作確認用で、`Authorization: Bearer` か `access_token` Cookie を受け付けます。

## 検証鍵は `kid` と JWKS で選ぶ

アクセス JWT のヘッダには `kid` を入れます。値は、公開鍵を SubjectPublicKeyInfo の DER にして SHA-256 し、base64url（パディングなし）にしたものです。検証側はヘッダの `kid` で公開鍵を選びます。

公開鍵は `GET /jwks` と `GET /.well-known/jwks.json` が JWK Set で返します。秘密鍵は返しません。

`JWT_PRIVATE_KEY` または `JWT_PRIVATE_KEY_PATH` と、`JWT_PUBLIC_KEY` または `JWT_PUBLIC_KEY_PATH` が無いと、プロセスは起動時に失敗します。鍵が無いときにディスクへ自動生成することはありません。生成は `scripts/bootstrap_dev_secrets.sh` の仕事です。

## CSRF は Cookie とヘッダのダブルサブミットで、ログイン・サインアップ・リフレッシュ・メール確認だけ免除する

`csrf_token` Cookie は HttpOnly ではないので、ブラウザの JavaScript から値を読めます。その値を、そのまま `x-csrf-token` ヘッダに載せます。

```javascript
headers: { "x-csrf-token": getCookie("csrf_token") }
```

`POST` / `PUT` / `PATCH` / `DELETE` で、パスが `/api` で始まるリクエストは、ヘッダと Cookie の一致、署名、期限内であることを要求します。署名の比較は `hmac.compare_digest` です。ヘッダが無い、または Cookie と一致しない場合は 403 です。署名が有効でも期限切れなら 419 です。

免除するのは次だけです。

- `POST /api/auth/signup`
- `POST /api/auth/token`
- `POST /api/auth/refresh`
- `GET /api/auth/confirm`

Cookie の `SameSite` は既定 `lax`（`COOKIE_SAMESITE`）です。`Secure` は既定オフで、`COOKIE_SECURE=1` のときだけ付きます。CSRF の署名鍵 `CSRF_SECRET` も、未設定なら起動時に失敗します。

## これは学習用の実装で、本番の認証基盤として依存させるものではない

秘密鍵の保管、盗まれたトークンの扱い、パスワード再設定、メール到達、レート制限、監査は揃っていません。他のアプリケーションの認証基盤として依存させないでください。公開してよいのは、設計を説明でき、テストが通り、秘密鍵を含まない状態だけです。`secret/`、`*.pem`、`.env` はコミットしません。

## 既知の範囲

確認メールはログの URL で代用しています。URL に確認トークンが含まれるので、この学習用のログは秘密として扱ってください。`SMTP_HOST` があるときだけ、標準ライブラリの SMTP で送信を試みます。未設定でも signup から confirm まで動きます。SMTP サーバは依存パッケージにしていません。任意の環境変数は `SMTP_HOST`、`SMTP_PORT`（既定 587）、`SMTP_TLS`（既定 `1`）、`SMTP_USERNAME`、`SMTP_PASSWORD`、`MAIL_FROM`、`APP_URL`（確認 URL のオリジン。既定 `http://127.0.0.1:8000`）です。

鍵ローテーションの運用手順は、JWKS が複数の公開鍵を返せるところまでです。`JWT_USE_KEYS_DIR=1` かつ `JWT_PUBLIC_KEYS_DIR` を置くと、そのディレクトリの公開鍵 PEM を JWKS に足します。署名に使う秘密鍵は 1 本です。ディレクトリの監視や、古い鍵を外す手順はありません。

監査や脅威分析はしていません。

## 起動方法

Python 3.11 以上を使います。リポジトリのルートで、次の順に実行します。

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
./scripts/bootstrap_dev_secrets.sh
uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

先に `scripts/bootstrap_dev_secrets.sh` を実行します。`secret/dev_priv.pem`（権限 600）と `secret/dev_pub.pem`（権限 644）を openssl で作ります。`.env` が無いときだけ、`SECRET_KEY` と `CSRF_SECRET` を暗号論的乱数で作り、次のキーを書きます。

- `JWT_PRIVATE_KEY_PATH`
- `JWT_PUBLIC_KEY_PATH`
- `SECRET_KEY`
- `CSRF_SECRET`
- `ACCESS_TOKEN_EXPIRE_MINUTES=15`
- `REFRESH_TOKEN_EXPIRE_DAYS=7`
- `DATABASE_URL`（sqlite の async URL）

`.env` が既にあるときは上書きしません。スクリプトを再度実行すると RSA 鍵ファイルは作り直します。コミットするのは値を空にした `.env.example` だけです。

起動時にテーブルが無ければ作成します。別ポートで起動するときは `APP_URL` をそのオリジンに合わせると、ログの確認 URL が一致します。

## curl で一通り動かす

サーバログの `confirmation url for ...` が confirm の URL です。

```bash
curl -sS -X POST http://127.0.0.1:8000/api/auth/signup \
  -H 'content-type: application/json' \
  -d '{"email":"learner@example.com","password":"password123","name":"Learner"}'

# 上のログに出た URL を、トークンごと開く
curl -sS 'http://127.0.0.1:8000/api/auth/confirm?token=ログに出たトークン'

curl -sS -c cookies.txt -X POST http://127.0.0.1:8000/api/auth/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d 'username=learner@example.com&password=password123'

curl -sS -b cookies.txt http://127.0.0.1:8000/api/auth/me

curl -sS -b cookies.txt -c cookies.txt -X POST http://127.0.0.1:8000/api/auth/refresh

CSRF=$(awk '$6 == "csrf_token" { print $7 }' cookies.txt)
curl -sS -b cookies.txt -c cookies.txt -X POST http://127.0.0.1:8000/api/auth/logout \
  -H "x-csrf-token: ${CSRF}"
```

`username` にはメールアドレスを入れます。logout では、Cookie ファイルに保存した `csrf_token` の値を `x-csrf-token` に載せます。refresh のあと CSRF Cookie は新しい値になるので、logout の前に取り直します。

公開鍵は `curl -sS http://127.0.0.1:8000/jwks` で見られます。アクセス JWT のヘッダ `kid` が、この JWK Set の `kid` と対応します。

## テスト

リポジトリのルートで実行します。

```bash
pytest -q
```

テストは一時的な RSA 鍵をプロセス内で作り、PEM 文字列を環境変数で渡します。秘密鍵ファイルはリポジトリに置きません。DB はテスト内の sqlite メモリです。
