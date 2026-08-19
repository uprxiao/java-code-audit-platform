#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
DEPLOY_DIR="$PROJECT_ROOT/deploy/sonarqube"

if [[ ! -f "$DEPLOY_DIR/.env" ]]; then
  echo "No local SonarQube environment exists."
  exit 0
fi

docker compose --env-file "$DEPLOY_DIR/.env" -f "$DEPLOY_DIR/compose.yaml" down "$@"

if [[ " ${*:-} " == *" --volumes "* ]]; then
  echo "SonarQube and PostgreSQL volumes were deleted. Local credentials can now be removed from deploy/sonarqube/.state/."
else
  echo "SonarQube stopped. Data volumes were retained."
fi
