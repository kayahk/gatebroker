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
# Existing material is checked rather than trusted. Reusing whatever happens to be on
# disk is how a stale certificate from an older version of this script survives an
# upgrade and then fails somewhere far away -- a health check that never passes, with
# nothing obviously wrong. Anything that does not meet every requirement below is
# reissued.
#
# The key-identifier extensions are among those requirements for a concrete reason:
# RFC 5280 expects a CA-issued certificate to carry an Authority Key Identifier, and
# newer OpenSSL releases reject a chain without one. Omitting them fails only on the
# strictest client, which is a miserable way to find out.
#
# These certificates are worthless outside the demo network and are never committed.
set -euo pipefail

directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
days=90
names=(keycloak litellm)
# Reissue rather than let a certificate expire mid-demo.
remaining_seconds=$((7 * 24 * 60 * 60))

has_extension() {
  openssl x509 -in "$1" -noout -text 2>/dev/null | grep -q "$2"
}

usable() {
  local name
  [ -f "${directory}/ca.pem" ] && [ -f "${directory}/ca.key" ] || return 1
  # A CA without a Subject Key Identifier cannot anchor a chain that strict clients
  # will accept, so material from before that was added must be replaced.
  # `-text` rather than `-ext`: macOS ships LibreSSL, which has no `-ext` flag.
  has_extension "${directory}/ca.pem" "X509v3 Subject Key Identifier" || return 1
  openssl x509 -in "${directory}/ca.pem" -noout -checkend "${remaining_seconds}" >/dev/null 2>&1 || return 1

  for name in "${names[@]}"; do
    [ -f "${directory}/${name}.pem" ] && [ -f "${directory}/${name}.key" ] || return 1
    has_extension "${directory}/${name}.pem" "X509v3 Authority Key Identifier" || return 1
    # Every service is addressed as localhost, because the demo shares one network
    # namespace. A certificate without that name is unusable here.
    has_extension "${directory}/${name}.pem" "DNS:localhost" || return 1
    openssl x509 -in "${directory}/${name}.pem" -noout -checkend "${remaining_seconds}" >/dev/null 2>&1 || return 1
    # Guards against a leaf left over from a previous, different CA.
    openssl verify -CAfile "${directory}/ca.pem" "${directory}/${name}.pem" >/dev/null 2>&1 || return 1
  done
  return 0
}

if usable; then
  echo "Reusing the demo TLS material in ${directory} (verified against the CA)."
  exit 0
fi

if [ -f "${directory}/ca.pem" ]; then
  echo "The demo TLS material is missing, expiring, or predates a required change; reissuing."
else
  echo "Issuing a demo CA and server certificates in ${directory}"
fi
rm -f "${directory}"/*.pem "${directory}"/*.key "${directory}"/*.srl "${directory}"/*.csr

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

for name in "${names[@]}"; do
  issue "${name}"
done

rm -f "${directory}"/*.srl

if ! usable; then
  echo "Reissued material still fails validation; refusing to continue." >&2
  exit 1
fi

echo "Issued. CA fingerprint:"
openssl x509 -in "${directory}/ca.pem" -noout -fingerprint -sha256
