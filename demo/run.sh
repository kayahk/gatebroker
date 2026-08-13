#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Brings the demo up and runs the end-to-end checks. Safe to re-run.
#
#   ./run.sh          bring up, wait for readiness, run the checks
#   ./run.sh up       bring up and leave it running
#   ./run.sh down     tear down, including volumes
#   ./run.sh logs     follow logs
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

compose() { docker compose "$@"; }

case "${1:-check}" in
  down)
    compose --profile smoke down --volumes --remove-orphans
    exit 0
    ;;
  logs)
    compose logs --follow
    exit 0
    ;;
  up|check)
    ;;
  *)
    echo "usage: $0 [check|up|down|logs]" >&2
    exit 2
    ;;
esac

./tls/generate-certs.sh

echo
echo "Building and starting the demo. First run pulls images and may take a few minutes."
compose up --build --detach --wait gatebroker

echo
echo "Stack is ready:"
echo "  broker     http://localhost:8080/healthz"

# Tokens name `keycloak` as their issuer, so every party has to reach Keycloak by
# that name. Containers do it through Compose DNS; a browser or the gabro CLI on
# this machine needs a hosts entry. Say so plainly rather than leaving the user at
# an opaque browser error.
if getent hosts keycloak >/dev/null 2>&1 || ping -c 1 -t 1 keycloak >/dev/null 2>&1; then
  echo "  identity   https://keycloak:8443   (admin/admin, realm gatebroker-demo)"
else
  echo "  identity   not reachable from this machine yet"
  echo
  echo "  The end-to-end checks below need nothing further: they run inside the"
  echo "  network, where 'keycloak' already resolves."
  echo
  echo "  To open the admin console or use the gabro CLI, map the name once:"
  echo "      echo '127.0.0.1 keycloak' | sudo tee -a /etc/hosts"
  echo "  then visit https://keycloak:8443 (admin/admin)."
fi

if [ "${1:-check}" = "up" ]; then
  echo
  echo "Left running. Run './run.sh check' for the end-to-end checks, './run.sh down' to stop."
  exit 0
fi

echo
compose run --build --rm smoke
