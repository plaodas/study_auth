#!/usr/bin/env bash
# Create local JWT keys and, only when missing, a gitignored .env.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SECRET_DIR="$ROOT_DIR/secret"
ENV_FILE="$ROOT_DIR/.env"

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required to generate the dev RSA key pair" >&2
  exit 1
fi

mkdir -p "$SECRET_DIR"
umask 077

openssl genpkey -algorithm RSA -out "$SECRET_DIR/dev_priv.pem" -pkeyopt rsa_keygen_bits:2048
openssl rsa -in "$SECRET_DIR/dev_priv.pem" -pubout -out "$SECRET_DIR/dev_pub.pem"
chmod 600 "$SECRET_DIR/dev_priv.pem"
chmod 644 "$SECRET_DIR/dev_pub.pem"

generate_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 32 | tr '+/' '-_' | tr -d '\n='
  else
    python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32), end="")
PY
  fi
}

if [ -f "$ENV_FILE" ]; then
  echo "Keeping existing $ENV_FILE"
else
  secret_key="$(generate_secret)"
  csrf_secret="$(generate_secret)"
  umask 077
  cat > "$ENV_FILE" <<EOF
JWT_PRIVATE_KEY_PATH=${SECRET_DIR}/dev_priv.pem
JWT_PUBLIC_KEY_PATH=${SECRET_DIR}/dev_pub.pem
SECRET_KEY=${secret_key}
CSRF_SECRET=${csrf_secret}
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7
DATABASE_URL=sqlite+aiosqlite:///${ROOT_DIR}/study_auth.db
EOF
  chmod 600 "$ENV_FILE"
  echo "Wrote $ENV_FILE"
fi

echo "Wrote $SECRET_DIR/dev_priv.pem (600) and $SECRET_DIR/dev_pub.pem (644)"
