#!/usr/bin/env bash
#
# End-to-end test for vault-plugin-secrets-ghp.
#
# Builds the plugin, brings up a mock ghp admin API plus both Vault and OpenBao,
# then drives the identical lifecycle against each engine to prove the same
# binary works on both:
#   configure -> role -> creds (mint) -> revoke.
#
# Select engines with ENGINES (default "vault openbao"), e.g. ENGINES=openbao.
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${ROOT_DIR}/test/docker-compose.yml"
COMPOSE="docker compose -f ${COMPOSE_FILE}"
BINARY="vault-plugin-secrets-ghp"

ADMIN_TOKEN="ghpsvc_seed"
MOUNT="ghp"
ENGINES="${ENGINES:-vault openbao}"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m==> %s\033[0m\n' "$*"; }

cleanup() { blue "Tearing down containers"; ${COMPOSE} down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT
fail() { red "FAIL: $*"; exit 1; }

wait_for() {
  local desc="$1"; shift
  local i=0
  until "$@" >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -ge "${WAIT_RETRIES:-90}" ] && fail "timed out waiting for ${desc}"
    sleep 2
  done
  green "ready: ${desc}"
}

jq_field() { python3 -c "import sys,json;print(json.load(sys.stdin)$1)"; }

run_engine() {
  local engine="$1" container="$2" cli="$3"
  blue "[${engine}] exercising the plugin"
  ex() { ${COMPOSE} exec -T "${container}" "${cli}" "$@"; }

  local sha; sha="$(sha256sum "${ROOT_DIR}/dist/${BINARY}" | awk '{print $1}')"
  ex plugin register -sha256="${sha}" secret "${BINARY}" >/dev/null || true
  ex secrets disable "${MOUNT}" >/dev/null 2>&1 || true
  ex secrets enable -path="${MOUNT}" "${BINARY}" >/dev/null
  green "[${engine}] plugin registered and mounted"

  # The plugin runs inside the engine container, so it reaches ghp by name.
  ex write "${MOUNT}/config" base_url="http://ghp:3000" admin_token="${ADMIN_TOKEN}" >/dev/null
  green "[${engine}] configured"

  # --- role + dynamic creds ---
  ex write "${MOUNT}/roles/agent" token_type="agent" installation_id=4242 \
    scopes="contents:read,pull_requests:write" ttl=1h max_ttl=24h >/dev/null
  local json id lease tok
  json="$(ex read -format=json "${MOUNT}/creds/agent")"
  id="$(printf '%s' "${json}" | jq_field '["data"]["token_id"]')"
  lease="$(printf '%s' "${json}" | jq_field '["lease_id"]')"
  tok="$(printf '%s' "${json}" | jq_field '["data"]["token"]')"
  [ -n "${id}" ] || fail "[${engine}] no dynamic token id returned"
  [ -n "${tok}" ] || fail "[${engine}] dynamic creds returned empty token value"
  green "[${engine}] dynamic token id=${id} issued (lease ${lease})"

  # revoke -> token deleted from ghp (idempotent: a second revoke is a no-op)
  ex lease revoke "${lease}" >/dev/null
  green "[${engine}] revoked lease ${lease}"

  green "[${engine}] PASSED"
}

blue "Building plugin for linux/amd64"
OS=linux ARCH=amd64 PLUGIN_DIR="${ROOT_DIR}/dist" make -C "${ROOT_DIR}" build

blue "Starting Docker stack (ghp + vault + openbao)"
${COMPOSE} up -d --build

wait_for "ghp" curl -fsS "http://127.0.0.1:3000/healthz"

for engine in ${ENGINES}; do
  case "${engine}" in
    vault)   wait_for "vault"   ${COMPOSE} exec -T vault   vault status -address=http://127.0.0.1:8200; run_engine vault vault vault ;;
    openbao) wait_for "openbao" ${COMPOSE} exec -T openbao bao   status -address=http://127.0.0.1:8200; run_engine openbao openbao bao ;;
    *) fail "unknown engine: ${engine}" ;;
  esac
done

green "ALL END-TO-END CHECKS PASSED (${ENGINES})"
