#!/usr/bin/env bash
# Copyright 2026 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# End-to-end Kubernetes test for gVisor (runsc) sandboxes with kube-net-driver,
# kube-netstack (L2 isolated veth capture), kube-pep (mTLS HTTP/2 CONNECT +
# connect-udp + RFC 8484 DoH), and kube-inbound.
#
# Validates unmodified applications inside gVisor Sentry with zero HTTP_PROXY,
# zero --host-uds, and zero sidecars:
#   - RuntimeClass: gvisor (runsc with --platform=systrap only)
#   - Confinement: host veth peer moved into an isolated empty netns (no host route)
#   - Outbound: unmodified DNS/TCP/UDP -> eth0 -> AF_PACKET -> kube-netstack
#     -> kube-net-driver -> mandatory mTLS HTTP/2 -> kube-pep
#   - Inbound: kube-inbound watches ResourceClaim.status -> mandatory mTLS
#     CONNECT <podUID>:8080 -> kube-net-driver -> kube-netstack DialInbound
#     -> eth0 -> standard HTTP server inside gVisor Sentry.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-agents-net-gvisor-e2e}"
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-kindest/node:v1.36.1}"
PYTHON_IMAGE="${PYTHON_IMAGE:-python:3.14-slim}"
NS="${GVISOR_NAMESPACE:-agents-net-gvisor}"
GVISOR_RELEASE="${GVISOR_RELEASE:-latest}"

ARCH="$(uname -m)"
CACHE_DIR="${GVISOR_CACHE_DIR:-${HOME}/.cache/agents.net/gvisor-${ARCH}-${GVISOR_RELEASE}}"

DRIVER_IMAGE="kind.local/kube-net-driver:gvisor"
STACK_IMAGE="kind.local/kube-netstack:gvisor"
INBOUND_IMAGE="kind.local/kube-inbound:gvisor"
PEP_IMAGE="kind.local/kube-pep:gvisor"

TMPDIR="$(mktemp -d)"
KUBECONFIG="${TMPDIR}/kubeconfig"
KUBE_CONTEXT="kind-${KIND_CLUSTER_NAME}"
CREATED_CLUSTER="false"

k() {
  kubectl --kubeconfig "${KUBECONFIG}" --context "${KUBE_CONTEXT}" "$@"
}

cleanup() {
  local rc=$?
  if [ "${rc}" -ne 0 ] && [ "${CREATED_CLUSTER}" = "true" ]; then
    echo "=== gVisor E2E failed (rc=${rc}); dumping diagnostics ===" >&2
    k -n kube-system logs -l app.kubernetes.io/name=kube-net-driver --all-containers --tail=60 >&2 || true
    k -n "${NS}" get pods,resourceclaims,svc -o wide >&2 || true
    k -n "${NS}" describe pod gvisor-agent >&2 || true
    k -n "${NS}" logs pod/gvisor-agent >&2 || true
    k -n "${NS}" logs deploy/kube-pep --tail=40 >&2 || true
    k -n "${NS}" logs deploy/kube-inbound --tail=40 >&2 || true
  fi
  if [ "${CREATED_CLUSTER}" = "true" ]; then
    kind delete cluster --name "${KIND_CLUSTER_NAME}" >/dev/null 2>&1 || true
  fi
  rm -rf "${TMPDIR}"
  exit "${rc}"
}
trap cleanup EXIT

echo "=== 1. Download & verify gVisor (runsc + containerd-shim-runsc-v1) for ${ARCH} ==="
mkdir -p "${CACHE_DIR}"
if [ ! -x "${CACHE_DIR}/runsc" ] || [ ! -x "${CACHE_DIR}/containerd-shim-runsc-v1" ]; then
  GVISOR_URL="https://storage.googleapis.com/gvisor/releases/release/${GVISOR_RELEASE}/${ARCH}"
  curl -fsSL --retry 3 -o "${TMPDIR}/gvisor.tar.bz2" "${GVISOR_URL}/gvisor.tar.bz2"
  curl -fsSL --retry 3 -o "${TMPDIR}/gvisor.tar.bz2.sha512" "${GVISOR_URL}/gvisor.tar.bz2.sha512"
  (cd "${TMPDIR}" && sha512sum -c gvisor.tar.bz2.sha512)
  tar -xjf "${TMPDIR}/gvisor.tar.bz2" -C "${CACHE_DIR}"
  chmod a+rx "${CACHE_DIR}/runsc" "${CACHE_DIR}/containerd-shim-runsc-v1"
fi
"${CACHE_DIR}/runsc" --version

echo "=== 2. Build kube-net-driver, kube-netstack, kube-inbound, and kube-pep images ==="
docker build --load -t "${DRIVER_IMAGE}" -f "${REPO_ROOT}/Dockerfile.kube-net-driver" "${REPO_ROOT}"
docker build --load -t "${STACK_IMAGE}" -f "${REPO_ROOT}/Dockerfile.kube-netstack" "${REPO_ROOT}"
docker build --load -t "${INBOUND_IMAGE}" -f "${REPO_ROOT}/Dockerfile.kube-inbound" "${REPO_ROOT}"
docker build --load -t "${PEP_IMAGE}" -f "${REPO_ROOT}/Dockerfile.kube-pep" "${REPO_ROOT}"

echo "=== 3. Create disposable kind cluster (${KIND_CLUSTER_NAME}, ${KIND_NODE_IMAGE}) with NRI + runsc ==="
cat > "${TMPDIR}/kind-config.yaml" <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
containerdConfigPatches:
  - |-
    [plugins."io.containerd.nri.v1.nri"]
      disable = false
    [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]
      runtime_type = "io.containerd.runsc.v1"
      [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc.options]
        TypeUrl = "io.containerd.runsc.v1.options"
        ConfigPath = "/etc/containerd/runsc.toml"
EOF

kind delete cluster --name "${KIND_CLUSTER_NAME}" >/dev/null 2>&1 || true
kind create cluster \
  --name "${KIND_CLUSTER_NAME}" \
  --image "${KIND_NODE_IMAGE}" \
  --config "${TMPDIR}/kind-config.yaml" \
  --kubeconfig "${KUBECONFIG}" \
  --wait 120s
CREATED_CLUSTER="true"

NODE_CONTAINER="${KIND_CLUSTER_NAME}-control-plane"
echo "=== 4. Install gVisor binaries & runsc.toml into ${NODE_CONTAINER} ==="
docker cp "${CACHE_DIR}/runsc" "${NODE_CONTAINER}:/usr/local/bin/runsc"
docker cp "${CACHE_DIR}/containerd-shim-runsc-v1" "${NODE_CONTAINER}:/usr/local/bin/containerd-shim-runsc-v1"
if [ -d "${CACHE_DIR}/gvisor-bin" ]; then
  docker cp "${CACHE_DIR}/gvisor-bin" "${NODE_CONTAINER}:/usr/local/bin/gvisor-bin"
fi
docker exec -i "${NODE_CONTAINER}" bash -euo pipefail -c '
chmod a+rx /usr/local/bin/runsc /usr/local/bin/containerd-shim-runsc-v1
if [ -d /usr/local/bin/gvisor-bin ]; then
  chmod -R a+rX /usr/local/bin/gvisor-bin
fi
cat > /etc/containerd/runsc.toml <<EOF
[runsc_config]
  platform = "systrap"
EOF
systemctl restart containerd
'

echo "=== 5. Load images & register RuntimeClass gvisor ==="
kind load docker-image --name "${KIND_CLUSTER_NAME}" "${DRIVER_IMAGE}" "${STACK_IMAGE}" "${INBOUND_IMAGE}" "${PEP_IMAGE}"
if docker image inspect "${PYTHON_IMAGE}" >/dev/null 2>&1; then
  kind load docker-image --name "${KIND_CLUSTER_NAME}" "${PYTHON_IMAGE}"
fi

cat <<EOF | k apply -f -
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
EOF

echo "=== 6. Generate ephemeral mTLS PKI & install kube-net-driver ==="
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "${TMPDIR}/ca.key" -out "${TMPDIR}/ca.crt" -days 1 \
  -subj "/CN=agents-net-gvisor-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

gen_cert() {
  local name="$1" cn="$2" san="$3" eku="$4"
  cat > "${TMPDIR}/${name}.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=${eku}
subjectAltName=${san}
EOF
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "${TMPDIR}/${name}.key" -out "${TMPDIR}/${name}.csr" \
    -subj "/CN=${cn}" 2>/dev/null
  openssl x509 -req -in "${TMPDIR}/${name}.csr" \
    -CA "${TMPDIR}/ca.crt" -CAkey "${TMPDIR}/ca.key" -CAcreateserial \
    -out "${TMPDIR}/${name}.crt" -days 1 -extfile "${TMPDIR}/${name}.ext" 2>/dev/null
}

NODE_IP_ADDR="$(k get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')"
gen_cert "pep" "kube-pep.${NS}.svc.cluster.local" \
  "DNS:kube-pep.${NS}.svc.cluster.local,DNS:kube-pep.${NS}.svc,DNS:kube-pep" \
  "serverAuth"
gen_cert "client" "kube-net-driver-gvisor-client" \
  "DNS:kube-net-driver-gvisor-client" \
  "clientAuth"
gen_cert "bridge" "kube-net-driver.kube-system.svc" \
  "DNS:kube-net-driver.kube-system.svc,IP:${NODE_IP_ADDR}" \
  "serverAuth"
gen_cert "gateway-client" "kube-inbound" \
  "DNS:kube-inbound" \
  "clientAuth"
gen_cert "echo" "echo.${NS}.svc.cluster.local" \
  "DNS:echo.${NS}.svc.cluster.local,DNS:echo.${NS}.svc" \
  "serverAuth"

k -n kube-system create configmap gvisor-ca --from-file=ca.crt="${TMPDIR}/ca.crt"
k -n kube-system create secret tls gvisor-driver-client-tls --cert="${TMPDIR}/client.crt" --key="${TMPDIR}/client.key"
k -n kube-system create secret tls gvisor-bridge-tls --cert="${TMPDIR}/bridge.crt" --key="${TMPDIR}/bridge.key"

sed -e "s|image: ghcr.io/aojea/agents.net/kube-net-driver:latest|image: ${DRIVER_IMAGE}|g" \
    -e "s|image: ghcr.io/aojea/agents.net/kube-netstack:latest|image: ${STACK_IMAGE}|g" \
  "${REPO_ROOT}/install.yaml" | k apply -f -

k -n kube-system patch daemonset kube-net-driver --type=strategic --patch '
spec:
  template:
    spec:
      containers:
        - name: kube-net-driver
          args:
            - --driver-name=dra.agents.net
            - --socket-root=/run/dra-agents-net/pods
            - --checkpoint-path=/run/dra-agents-net/state.db
            - --kubelet-root-dir=/var/lib/kubelet
            - --metrics-addr=:9102
            - --host-tun-socket=/run/hosttun/worker.sock
            - --ingress-addr=:15080
            - --ingress-tls-cert=/etc/dra-agents-net/ingress/tls.crt
            - --ingress-tls-key=/etc/dra-agents-net/ingress/tls.key
            - --ingress-client-ca=/etc/dra-agents-net/ca/ca.crt
            - --ingress-allowed-client-san=kube-inbound
            - --ingress-server-name=kube-net-driver.kube-system.svc
          volumeMounts:
            - name: gvisor-client-tls
              mountPath: /etc/dra-agents-net/client
              readOnly: true
            - name: gvisor-bridge-tls
              mountPath: /etc/dra-agents-net/ingress
              readOnly: true
            - name: gvisor-ca
              mountPath: /etc/dra-agents-net/ca
              readOnly: true
      volumes:
        - name: gvisor-client-tls
          secret:
            secretName: gvisor-driver-client-tls
        - name: gvisor-bridge-tls
          secret:
            secretName: gvisor-bridge-tls
        - name: gvisor-ca
          configMap:
            name: gvisor-ca
'
k -n kube-system rollout status daemonset/kube-net-driver --timeout=120s

echo "=== 7. Deploy echo target, kube-pep (TCP + UDP + DoH), and kube-inbound in ${NS} ==="
k create namespace "${NS}"
k -n "${NS}" create configmap gvisor-ca --from-file=ca.crt="${TMPDIR}/ca.crt"
k -n "${NS}" create secret tls pep-tls --cert="${TMPDIR}/pep.crt" --key="${TMPDIR}/pep.key"
k -n "${NS}" create secret tls gateway-client-tls --cert="${TMPDIR}/gateway-client.crt" --key="${TMPDIR}/gateway-client.key"
k -n "${NS}" create secret tls echo-tls --cert="${TMPDIR}/echo.crt" --key="${TMPDIR}/echo.key"

cat <<EOF | k apply -f -
apiVersion: v1
kind: Service
metadata:
  name: echo
  namespace: ${NS}
spec:
  selector:
    app: echo
  ports:
    - name: https
      port: 8443
      targetPort: 8443
    - name: udp-echo
      port: 8444
      targetPort: 8444
      protocol: UDP
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: echo
  namespace: ${NS}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: echo
  template:
    metadata:
      labels:
        app: echo
    spec:
      containers:
        - name: echo
          image: ${PYTHON_IMAGE}
          imagePullPolicy: IfNotPresent
          command:
            - python3
            - -c
            - |
              import http.server, json, socket, ssl, threading
              def udp_echo():
                  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                  s.bind(("0.0.0.0", 8444))
                  while True:
                      data, addr = s.recvfrom(65535)
                      s.sendto(data, addr)
              threading.Thread(target=udp_echo, daemon=True).start()
              class H(http.server.BaseHTTPRequestHandler):
                  def do_GET(self):
                      body = json.dumps({"ok": True, "path": self.path}).encode()
                      self.send_response(200)
                      self.send_header("Content-Type", "application/json")
                      self.send_header("Content-Length", str(len(body)))
                      self.end_headers()
                      self.wfile.write(body)
                  def log_message(self, *args):
                      pass
              srv = http.server.ThreadingHTTPServer(("0.0.0.0", 8443), H)
              ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
              ctx.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
              srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
              srv.serve_forever()
          ports:
            - containerPort: 8443
            - containerPort: 8444
              protocol: UDP
          volumeMounts:
            - name: tls
              mountPath: /tls
              readOnly: true
      volumes:
        - name: tls
          secret:
            secretName: echo-tls
EOF

ECHO_IP="$(k -n "${NS}" get svc echo -o jsonpath='{.spec.clusterIP}')"
if [[ "${ECHO_IP}" == *:* ]]; then
  ECHO_CIDR="${ECHO_IP}/128"
else
  ECHO_CIDR="${ECHO_IP}/32"
fi

cat > "${TMPDIR}/policy.json" <<EOF
{
  "agents_net_policy": 1,
  "version": "gvisor-v1",
  "sandbox": "gvisor-agent",
  "default": "deny",
  "features": {
    "h2": true,
    "udp": true,
    "doh": true
  },
  "rules": [
    {
      "id": "allow-echo-https",
      "name": "echo.${NS}.svc.cluster.local",
      "ports": [8443],
      "transports": ["tcp"]
    },
    {
      "id": "allow-echo-udp",
      "name": "echo.${NS}.svc.cluster.local",
      "ports": [8444],
      "transports": ["udp"]
    }
  ],
  "resolved_addresses": [
    {
      "cidr": "${ECHO_CIDR}",
      "ports": [8443, 8444]
    }
  ]
}
EOF
k -n "${NS}" create configmap pep-policy --from-file=policy.json="${TMPDIR}/policy.json"

cat <<EOF | k apply -f -
apiVersion: v1
kind: Service
metadata:
  name: kube-pep
  namespace: ${NS}
spec:
  selector:
    app: kube-pep
  ports:
    - name: https
      port: 8443
      targetPort: 8443
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kube-pep
  namespace: ${NS}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: kube-pep
  template:
    metadata:
      labels:
        app: kube-pep
    spec:
      containers:
        - name: kube-pep
          image: ${PEP_IMAGE}
          imagePullPolicy: IfNotPresent
          env:
            - name: GODEBUG
              value: http2xconnect=1
          args:
            - -listen=tcp://0.0.0.0:8443
            - -h2
            - -policy=/etc/agents-net/policy.json
            - -generation=gvisor-gen-1
            - -tls-cert=/tls/tls.crt
            - -tls-key=/tls/tls.key
            - -tls-client-ca=/ca/ca.crt
          ports:
            - containerPort: 8443
          volumeMounts:
            - name: policy
              mountPath: /etc/agents-net
              readOnly: true
            - name: tls
              mountPath: /tls
              readOnly: true
            - name: ca
              mountPath: /ca
              readOnly: true
      volumes:
        - name: policy
          configMap:
            name: pep-policy
        - name: tls
          secret:
            secretName: pep-tls
        - name: ca
          configMap:
            name: gvisor-ca
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kube-inbound
  namespace: ${NS}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ${NS}-kube-inbound
rules:
  - apiGroups: ["resource.k8s.io"]
    resources: ["resourceclaims"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ${NS}-kube-inbound
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: ${NS}-kube-inbound
subjects:
  - kind: ServiceAccount
    name: kube-inbound
    namespace: ${NS}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kube-inbound
  namespace: ${NS}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: kube-inbound
  template:
    metadata:
      labels:
        app: kube-inbound
    spec:
      serviceAccountName: kube-inbound
      containers:
        - name: kube-inbound
          image: ${INBOUND_IMAGE}
          imagePullPolicy: IfNotPresent
          args:
            - --listen-addr=:8080
            - --bridge-ca=/ca/ca.crt
            - --bridge-client-cert=/tls/tls.crt
            - --bridge-client-key=/tls/tls.key
          ports:
            - containerPort: 8080
          volumeMounts:
            - name: ca
              mountPath: /ca
              readOnly: true
            - name: tls
              mountPath: /tls
              readOnly: true
          readinessProbe:
            httpGet:
              path: /healthz
              port: 8080
            periodSeconds: 2
      volumes:
        - name: ca
          configMap:
            name: gvisor-ca
        - name: tls
          secret:
            secretName: gateway-client-tls
---
apiVersion: v1
kind: Service
metadata:
  name: kube-inbound
  namespace: ${NS}
spec:
  selector:
    app: kube-inbound
  ports:
    - name: http
      port: 80
      targetPort: 8080
EOF

k -n "${NS}" rollout status deployment/echo --timeout=90s
k -n "${NS}" rollout status deployment/kube-pep --timeout=90s
k -n "${NS}" rollout status deployment/kube-inbound --timeout=90s

echo "=== 8. Deploy gVisor DeviceClass + ResourceClaimTemplate + RuntimeClass: gvisor Pod ==="
cat <<EOF | k apply -f -
apiVersion: resource.k8s.io/v1
kind: DeviceClass
metadata:
  name: dra.agents.net-gvisor
spec:
  selectors:
    - cel:
        expression: device.driver == "dra.agents.net"
  config:
    - opaque:
        driver: dra.agents.net
        parameters:
          apiVersion: dra.agents.net/v1alpha1
          kind: DriverConfig
          confinementMode: NetworkPolicyDenyAll
          nicBlockMode: DropAll
          dns:
            mode: DoH
          policyEnforcementPoint:
            url: https://kube-pep.${NS}.svc.cluster.local:8443
            tls:
              serverName: kube-pep.${NS}.svc.cluster.local
              caCertificateRefs:
                - type: HostPath
                  hostPath: /etc/dra-agents-net/ca/ca.crt
            auth:
              type: MTLS
              mtls:
                certDir: /etc/dra-agents-net/client
---
apiVersion: resource.k8s.io/v1
kind: ResourceClaimTemplate
metadata:
  name: gvisor-agents-net
  namespace: ${NS}
spec:
  spec:
    devices:
      requests:
        - name: agents-net
          exactly:
            deviceClassName: dra.agents.net-gvisor
            allocationMode: ExactCount
            count: 1
      config:
        - requests: ["agents-net"]
          opaque:
            driver: dra.agents.net
            parameters:
              apiVersion: dra.agents.net/v1alpha1
              kind: DriverConfig
              ingressPorts:
                - port: 8080
                  protocol: TCP
              caTrust:
                mode: InjectEnv
                bundleMode: AppendSystemRoots
                sources:
                  - type: ConfigMap
                    configMapRef:
                      name: gvisor-ca
                      key: ca.crt
---
apiVersion: v1
kind: Pod
metadata:
  name: gvisor-agent
  namespace: ${NS}
spec:
  runtimeClassName: gvisor
  automountServiceAccountToken: false
  terminationGracePeriodSeconds: 1
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
  resourceClaims:
    - name: agents-net
      resourceClaimTemplateName: gvisor-agents-net
  containers:
    - name: agent
      image: ${PYTHON_IMAGE}
      imagePullPolicy: IfNotPresent
      command:
        - python3
        - -c
        - |
          import http.server

          class H(http.server.BaseHTTPRequestHandler):
              def do_GET(self):
                  body = f"gvisor-ingress-ok:{self.path}".encode()
                  self.send_response(200)
                  self.send_header("Content-Type", "text/plain")
                  self.send_header("Content-Length", str(len(body)))
                  self.end_headers()
                  self.wfile.write(body)
              def log_message(self, *args):
                  pass

          http.server.ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
      resources:
        claims:
          - name: agents-net
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
EOF

k -n "${NS}" wait --for=condition=Ready pod/gvisor-agent --timeout=120s

echo "=== 9. Verify gVisor kernel, confinement, and transparent DNS/TCP/UDP via kube-netstack ==="
k -n "${NS}" exec -i gvisor-agent -- env NS="${NS}" ECHO_IP="${ECHO_IP}" python3 - <<'PY'
import ipaddress, os, socket, urllib.request

ns = os.environ["NS"]
echo_ip = os.environ["ECHO_IP"]
echo_fqdn = f"echo.{ns}.svc.cluster.local"
pool = ipaddress.ip_network("198.18.0.0/15")

# 1. Confirm gVisor Sentry kernel, zero proxy env vars, and DoH resolv.conf.
with open("/proc/version") as f:
    ver = f.read().strip()
print("Pod /proc/version:", ver)
assert "gvisor" in ver.lower(), f"expected gVisor Sentry kernel, got: {ver}"
for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "AGENTS_NET_EGRESS_SOCKET", "AGENTS_NET_INGRESS_SOCKET"):
    assert not os.environ.get(var), f"unexpected env var {var}={os.environ.get(var)!r}"
with open("/etc/resolv.conf") as f:
    resolv = f.read()
assert "nameserver 198.19.255.253" in resolv, f"unexpected resolv.conf:\n{resolv}"
assert f"search {ns}.svc.cluster.local" in resolv, f"missing search domain in resolv.conf:\n{resolv}"
print("PASS gVisor Sentry verified with zero proxy env vars and DoH resolv.conf")

# 2. Direct TCP to echo ClusterIP must fail closed (host veth isolated; kube-pep rejects literal IP).
try:
    s = socket.create_connection((echo_ip, 8443), timeout=3)
    s.close()
    raise SystemExit("FAIL: direct TCP to echo ClusterIP succeeded from gVisor Pod")
except OSError as e:
    print("PASS direct TCP to echo ClusterIP blocked:", e)

# 3. Short Kubernetes Service name resolves through search list + DoH into synthetic pool.
resolved_ip = socket.gethostbyname("echo")
assert ipaddress.ip_address(resolved_ip) in pool, f"expected synthetic IP in {pool}, got {resolved_ip}"
print(f"PASS gVisor DoH resolved short name 'echo' -> {resolved_ip}")

# 4. Non-existent domain returns real NXDOMAIN from kube-pep.
try:
    bad = socket.gethostbyname("doesnotexist.example")
    raise SystemExit(f"FAIL: doesnotexist.example resolved to {bad}")
except socket.gaierror as e:
    print("PASS gVisor DoH returned NXDOMAIN for doesnotexist.example:", e)

# 5. Unmodified HTTPS client connects via echo FQDN -> kube-netstack -> mTLS H2 -> kube-pep.
with urllib.request.urlopen(f"https://{echo_fqdn}:8443/gvisor-tcp", timeout=10) as resp:
    body = resp.read()
    assert resp.status == 200 and b'"/gvisor-tcp"' in body, (resp.status, body)
print("PASS gVisor unmodified HTTPS client reached echo via kube-netstack -> kube-pep")

# 6. Denied host fails closed at kube-pep.
try:
    socket.create_connection(("blocked.example", 443), timeout=3)
    raise SystemExit("FAIL: blocked.example unexpectedly connected")
except OSError as e:
    print("PASS gVisor blocked.example denied:", e)

# 7. Unmodified UDP socket reaches echo:8444 via connect-udp.
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.settimeout(5)
u.sendto(b"gvisor-udp-ok", (echo_fqdn, 8444))
data, _ = u.recvfrom(4096)
u.close()
assert data == b"gvisor-udp-ok", f"UDP echo mismatch: {data!r}"
print("PASS gVisor unmodified UDP socket echoed payload via kube-netstack -> kube-pep")
PY

echo "=== 10. Verify IP-less inbound via kube-inbound -> mTLS CONNECT -> kube-netstack DialInbound -> gVisor ==="
cat <<EOF | k apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: inbound-tester
  namespace: ${NS}
spec:
  restartPolicy: Never
  containers:
    - name: tester
      image: ${PYTHON_IMAGE}
      imagePullPolicy: IfNotPresent
      command: ["python3", "-c", "import time; time.sleep(120)"]
EOF
k -n "${NS}" wait --for=condition=Ready pod/inbound-tester --timeout=60s

k -n "${NS}" exec -i inbound-tester -- env NS="${NS}" python3 - <<'PY'
import os, time, urllib.error, urllib.request

ns = os.environ["NS"]
url = f"http://kube-inbound.{ns}.svc.cluster.local/agents/{ns}/gvisor-agent/hello-gvisor"
last_err = None
for _ in range(25):
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            body = resp.read().decode()
            assert resp.status == 200 and body == "gvisor-ingress-ok:/hello-gvisor", (resp.status, body)
            print("PASS kube-inbound -> mTLS CONNECT -> kube-netstack DialInbound -> gVisor:", body)
            last_err = None
            break
    except Exception as e:
        last_err = e
        time.sleep(0.5)
if last_err is not None:
    raise SystemExit(f"FAIL: inbound into gVisor failed: {last_err}")

# Unpinned port 9999 must be rejected with 403.
try:
    urllib.request.urlopen(f"http://kube-inbound.{ns}.svc.cluster.local/agents/{ns}/gvisor-agent:9999/nope", timeout=5)
    raise SystemExit("FAIL: unpinned port 9999 unexpectedly succeeded")
except urllib.error.HTTPError as e:
    assert e.code == 403, f"want 403 for unpinned port, got {e.code}"
    print("PASS kube-inbound rejected unpinned port 9999 with HTTP 403")
PY

echo "=== 11. Verify kube-pep JSONL audit log for gVisor TCP, UDP, and DoH flows ==="
PEP_LOGS="$(k -n "${NS}" logs deploy/kube-pep)"
python3 - "${PEP_LOGS}" "${ECHO_IP}" <<'PY'
import json, sys
echo_ip = sys.argv[2]
records = [json.loads(l) for l in sys.argv[1].splitlines() if l.strip().startswith("{")]
assert any(r.get("decision") == "allow" and r.get("transport") == "tcp" and r.get("wire") == "h2" and r.get("peer") == "kube-net-driver-gvisor-client" for r in records), records
assert any(r.get("decision") == "allow" and r.get("transport") == "udp" and r.get("wire") == "h2" and r.get("peer") == "kube-net-driver-gvisor-client" for r in records), records
assert any(r.get("decision") == "allow" and r.get("transport") == "dns" and r.get("wire") == "h2" and r.get("peer") == "kube-net-driver-gvisor-client" for r in records), records
assert any(r.get("decision") == "block" and r.get("transport") == "dns" and r.get("destination") == "doesnotexist.example" for r in records), records
assert any(r.get("decision") == "block" and r.get("transport") == "dns" and r.get("destination") == "blocked.example" for r in records), records
assert any(r.get("decision") == "block" and r.get("transport") == "tcp" and echo_ip in r.get("destination", "") for r in records), records
print("PASS kube-pep JSONL audit verified gVisor mTLS H2 TCP, UDP, and DoH allow/block records")
PY

echo "=== 12. Delete gVisor Pod and verify ResourceClaim GC + immediate ingress revocation ==="
k -n "${NS}" delete pod gvisor-agent --wait=true
for _ in $(seq 1 20); do
  COUNT="$(k -n "${NS}" get resourceclaims -o name | wc -l | tr -d ' ')"
  if [ "${COUNT}" = "0" ]; then
    break
  fi
  sleep 0.5
done
[ "$(k -n "${NS}" get resourceclaims -o name | wc -l | tr -d ' ')" = "0" ] || { echo "FAIL: ResourceClaim not GC'd" >&2; exit 1; }

k -n "${NS}" exec -i inbound-tester -- env NS="${NS}" python3 - <<'PY'
import os, urllib.error, urllib.request
ns = os.environ["NS"]
try:
    urllib.request.urlopen(f"http://kube-inbound.{ns}.svc.cluster.local/agents/{ns}/gvisor-agent/after-delete", timeout=5)
    raise SystemExit("FAIL: ingress still reachable after gVisor Pod deletion")
except urllib.error.HTTPError as e:
    assert e.code == 404, f"want 404 after delete, got {e.code}"
    print("PASS gVisor ingress immediately revoked after Pod deletion (HTTP 404)")
PY

echo "=== ALL GVISOR E2E TESTS PASSED ==="
