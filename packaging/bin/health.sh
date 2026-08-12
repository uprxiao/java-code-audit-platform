#!/usr/bin/env bash
set -euo pipefail

PORT="${AUDIT_PORT:-8080}"
BASE_URL="${AUDIT_BASE_URL:-http://127.0.0.1:${PORT}}"
curl --fail --silent --show-error "${BASE_URL}/api/v1/health"
printf '\n'
