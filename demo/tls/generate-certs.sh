#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Issues a throwaway CA and two server certificates for the demo.
#
# The broker refuses a plaintext identity provider or upstream gateway, and that is
# not a rule worth bending for a demo: a plaintext JWKS fetch would let anything on
# the path substitute signing keys, which is a complete bypass. So the demo runs
# real TLS with its own CA, and the broker is told to trust exactly that CA.
#
# The key-identifier extensions are not decoration: RFC 5280 expects a CA-issued
# certificate to carry an Authority Key Identifier, and newer OpenSSL releases refuse
# a chain without one. Omitting them fails only on the strictest client, which is a
# miserable way to find out.
#
# These certificates are worthless outside the demo network. They are regenerated
# whenever they are missing and are never committed.
set -euo pipefail

directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
days=90

if [ -f "${directory}/ca.pem" ] && [ -f "${directory}/keycloak.pem" ] && [ -f "${directory}/litellm.pem" ]; then
  echo "TLS material already present in ${directory}; delete *.pem and *.key to reissue."
  exit 0
fi

echo "Issuing a demo CA and server certificates in ${directory}"

openssl req -x509 -newkey rsa:2048 -nodes -days "${days}" \
  -keyout "${directory}/ca.key" -out "${directory}/ca.pem" \
  -subj "/CN=GateBroker demo CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" 2>/dev/null

issue() {
  local name="$1"
  openssl req -newkey rsa:2048 -nodes \
    -keyout "${directory}/${name}.key" -out "${directory}/${name}.csr" \
    -subj "/CN=${name}" 2>/dev/null
  openssl x509 -req -in "${directory}/${name}.csr" \
    -CA "${directory}/ca.pem" -CAkey "${directory}/ca.key" -CAcreateserial \
    -out "${directory}/${name}.pem" -days "${days}" -sha256 \
    -extfile <(printf 'subjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n' "${name}") 2>/dev/null
  rm -f "${directory}/${name}.csr"
  # Keycloak and LiteLLM both run unprivileged and need to read their own key.
  chmod 0644 "${directory}/${name}.key"
}

issue keycloak
issue litellm

rm -f "${directory}/.srl" "${directory}/ca.srl"
echo "Done. CA fingerprint:"
openssl x509 -in "${directory}/ca.pem" -noout -fingerprint -sha256
