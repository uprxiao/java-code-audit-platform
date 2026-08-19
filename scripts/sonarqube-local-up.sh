#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
DEPLOY_DIR="$PROJECT_ROOT/deploy/sonarqube"
ENV_FILE="$DEPLOY_DIR/.env"
STATE_DIR="$DEPLOY_DIR/.state"
CREDENTIALS_FILE="$STATE_DIR/credentials.env"
COMPOSE_FILE="$DEPLOY_DIR/compose.yaml"

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Required command is missing: $1" >&2
    exit 1
  }
}

for command_name in docker curl openssl python3; do
  require_command "$command_name"
done

docker info >/dev/null 2>&1 || {
  echo "Docker is not running." >&2
  exit 1
}

mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

if [[ ! -f "$ENV_FILE" ]]; then
  umask 077
  db_password="$(openssl rand -hex 32)"
  printf 'SONAR_WEB_PORT=19000\nSONAR_DB_PASSWORD=%s\n' "$db_password" > "$ENV_FILE"
  unset db_password
fi
chmod 600 "$ENV_FILE"

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

base_url="http://127.0.0.1:${SONAR_WEB_PORT:-19000}"

echo "Starting the isolated SonarQube service at $base_url ..."
# Public images need no registry credentials. An empty temporary Docker config
# avoids a broken desktop credential helper from blocking an otherwise public pull.
temporary_docker_config="$(mktemp -d)"
cleanup_temporary_docker_config() {
  rm -r -- "$temporary_docker_config"
}
trap cleanup_temporary_docker_config EXIT
if command -v docker-compose >/dev/null 2>&1; then
  DOCKER_CONFIG="$temporary_docker_config" docker-compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" pull
else
  # Linux installations commonly expose Compose only as a Docker CLI plugin.
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" pull
fi
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d

deadline=$((SECONDS + 900))
status=""
while (( SECONDS < deadline )); do
  response="$(curl --silent --show-error --max-time 5 "$base_url/api/system/status" 2>/dev/null || true)"
  status="$(printf '%s' "$response" | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("status", ""))
except Exception:
    print("")')"
  if [[ "$status" == "UP" ]]; then
    break
  fi
  sleep 5
done

if [[ "$status" != "UP" ]]; then
  echo "SonarQube did not become ready in 15 minutes. Recent logs:" >&2
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" logs --tail=200 sonarqube >&2
  exit 1
fi

if [[ ! -f "$CREDENTIALS_FILE" ]]; then
  umask 077
  admin_password="$(openssl rand -base64 36 | tr -d '\n' | tr '/+' '_-')"

  curl --silent --show-error --fail --request POST \
    --user 'admin:admin' \
    --data-urlencode 'login=admin' \
    --data-urlencode 'previousPassword=admin' \
    --data-urlencode "password=$admin_password" \
    "$base_url/api/users/change_password" >/dev/null

  token_response="$(printf 'user = "admin:%s"\n' "$admin_password" | \
    curl --silent --show-error --fail --request POST --config - \
    --data-urlencode 'name=java-code-audit-platform-local' \
    --data-urlencode 'type=USER_TOKEN' \
    "$base_url/api/user_tokens/generate")"
  analysis_token="$(printf '%s' "$token_response" | python3 -c 'import json,sys
value=json.load(sys.stdin).get("token")
if not value:
    raise SystemExit("SonarQube did not return an analysis token")
print(value)')"

  printf 'SONAR_HOST_URL=%q\nSONAR_ADMIN_PASSWORD=%q\nSONAR_TOKEN=%q\n' \
    "$base_url" "$admin_password" "$analysis_token" > "$CREDENTIALS_FILE"
  chmod 600 "$CREDENTIALS_FILE"
  unset admin_password analysis_token token_response
fi

# shellcheck disable=SC1090
source "$CREDENTIALS_FILE"
auth_status="$(printf 'user = "%s:"\n' "$SONAR_TOKEN" | \
  curl --silent --show-error --fail --config - "$SONAR_HOST_URL/api/authentication/validate")"
valid="$(printf '%s' "$auth_status" | python3 -c 'import json,sys; print(str(json.load(sys.stdin).get("valid", False)).lower())')"
if [[ "$valid" != "true" ]]; then
  echo "Stored SonarQube token is no longer valid. Restore the credentials or reset the local instance with --volumes before reinitializing it." >&2
  exit 1
fi

version_response="$(curl --silent --show-error --fail "$base_url/api/system/status")"
version="$(printf '%s' "$version_response" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("version", "unknown"))')"
echo "SonarQube is UP: $base_url (version $version)"
echo "Credentials are stored locally with mode 600 in deploy/sonarqube/.state/."
