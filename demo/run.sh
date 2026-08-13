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

# Bound the wait. Without a timeout a container whose health check never passes leaves
# compose sitting at "Waiting" forever with no indication of what is wrong, so report
# the failing check instead of hanging.
if ! compose up --build --detach --wait --wait-timeout 300 gatebroker; then
  echo
  echo "The stack did not become healthy. Last health check output per container:" >&2
  for container in $(compose ps --all --quiet); do
    name=$(docker inspect --format '{{.Name}}' "${container}" | sed 's|^/||')
    state=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${container}")
    echo >&2
    echo "--- ${name} (${state})" >&2
    docker inspect --format '{{if .State.Health}}{{range .State.Health.Log}}{{.Output}}{{end}}{{end}}' "${container}" 2>/dev/null | tail -20 >&2
  done
  echo >&2
  echo "Container logs: ./run.sh logs    Start over: ./run.sh down && ./run.sh" >&2
  exit 1
fi

echo
echo "Stack is ready. Nothing else to configure:"
echo "  identity   https://localhost:8443/admin  (admin/admin, realm gatebroker-demo)"
echo "  broker     http://localhost:8080/healthz"

if [ "${1:-check}" = "up" ]; then
  echo
  echo "Left running. Run './run.sh check' for the end-to-end checks, './run.sh down' to stop."
  exit 0
fi

echo
compose run --build --rm smoke
