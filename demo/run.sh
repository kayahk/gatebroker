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

# A running container keeps the certificate it read at startup, so material reissued
# underneath it leaves services presenting a chain that no longer matches the CA on
# disk. Rather than track provenance -- which missed the case where only the leaf
# changed -- ask the running service what it is actually presenting and check that it
# verifies. This is the failure itself, so nothing can slip past it. The mismatch is
# otherwise thoroughly confusing: a health check failing on certificate verification
# while every file on disk looks perfectly consistent.
serves_a_verifiable_chain() {
  echo | openssl s_client -connect localhost:8443 -CAfile tls/ca.pem 2>/dev/null \
    | grep -q "Verify return code: 0"
}

# Compose pins one project name, so a stack started from another checkout of this
# repository is the same project. Its containers keep the paths of the directory that
# created them, which shows up as certificates that inexplicably fail to verify against
# the files sitting right here. Name the situation instead.
running_tls_source() {
  container="$(compose ps --all --quiet keycloak 2>/dev/null | head -1)"
  [ -n "${container}" ] || return 0
  docker inspect --format \
    '{{range .Mounts}}{{if eq .Destination "/etc/tls"}}{{.Source}}{{end}}{{end}}' \
    "${container}" 2>/dev/null
}

foreign="$(running_tls_source)"
if [ -n "${foreign}" ] && [ "${foreign}" != "${PWD}/tls" ]; then
  echo "A demo stack from a different checkout is already running:" >&2
  echo "  it is using ${foreign}" >&2
  echo "  this one is ${PWD}/tls" >&2
  echo >&2
  echo "Both share the compose project name, so only one can run at a time." >&2
  echo "Take it over with:  ./run.sh down && ./run.sh" >&2
  exit 1
fi

if serves_a_verifiable_chain; then
  echo "The running identity provider presents a chain that matches the local CA."
elif compose ps --status running --quiet keycloak 2>/dev/null | grep -q .; then
  # Tear down rather than recreate. `up --force-recreate <service>` does not recreate
  # that service's dependencies, so the identity provider would keep serving the
  # certificate it loaded at startup and the mismatch would survive.
  echo "The running stack presents a certificate that no longer matches the local CA."
  echo "Restarting it from scratch so every service loads the current material."
  compose --profile smoke down --remove-orphans
fi

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
