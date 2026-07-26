#!/bin/sh
# Generates the demo CA + a single multi-SAN leaf certificate host_proxy.py
# uses to terminate TLS locally for every host it needs to MITM: the
# fake-response task target (example.com by default) and, opt-in, any real
# credential-inject model backend (e.g. api.openai.com) for anyone doing the
# cloud-migration bonus in AGENTS_NET_THE_HARD_WAY.md. The local-provider
# tier (Ollama) needs NO entry here at all -- it's plain HTTP, genuinely
# relayed with no TLS termination.
#
# One cert with multiple exact SAN entries is used instead of a wildcard
# (e.g. "*.example.com") because wildcards only match one subdomain label
# and never the bare apex -- "*.example.com" would NOT cover "example.com"
# itself. Since this is our own demo CA (not a public one bound by
# CA/Browser Forum wildcard rules), listing exact hostnames as SANs is
# simpler and fully general for any host you add.
#
# - certs/agent-ca.pem / agent-ca.key -- the demo root CA. Mount agent-ca.pem
#   into the sandbox as /var/run/agent-ca.pem to fulfill the Trust Contract.
# - certs/agent-mitm.pem / agent-mitm.key -- the one leaf cert host_proxy.py
#   loads, covering every host in $HOSTS via SAN.
#
# Run this once before starting host_proxy.py. Pass additional hostnames as
# arguments to add more hosts to the cert's SAN list, e.g. to also enable the
# cloud-migration bonus:
#   ./gen_certs.sh api.openai.com
set -e

DIR="$(cd "$(dirname "$0")" && pwd)/certs"
mkdir -p "$DIR"

HOSTS="example.com $*"
SAN=""
for host in $HOSTS; do
  SAN="${SAN}DNS:$host,"
done
SAN="${SAN%,}"

openssl genrsa -out "$DIR/agent-ca.key" 2048
openssl req -x509 -new -nodes -key "$DIR/agent-ca.key" -sha256 -days 3650 \
  -subj "/O=agents.net demo/CN=agents.net Demo Root CA" \
  -out "$DIR/agent-ca.pem"

openssl genrsa -out "$DIR/agent-mitm.key" 2048
openssl req -new -key "$DIR/agent-mitm.key" \
  -subj "/CN=agents.net demo MITM cert" \
  -out "$DIR/agent-mitm.csr"

cat > "$DIR/agent-mitm.ext" <<EOF
subjectAltName = $SAN
EOF

openssl x509 -req -in "$DIR/agent-mitm.csr" \
  -CA "$DIR/agent-ca.pem" -CAkey "$DIR/agent-ca.key" -CAcreateserial \
  -out "$DIR/agent-mitm.pem" -days 825 -sha256 \
  -extfile "$DIR/agent-mitm.ext"

rm -f "$DIR/agent-mitm.csr" "$DIR/agent-mitm.ext"

echo "Generated:"
echo "  $DIR/agent-ca.pem (mount as /var/run/agent-ca.pem in the sandbox)"
echo "  $DIR/agent-mitm.pem / agent-mitm.key (used by host_proxy.py, SAN: $HOSTS)"
