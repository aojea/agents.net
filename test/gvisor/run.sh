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
# kube-pep (mTLS HTTP/2 CONNECT + connect-udp + RFC 8484 DoH), and kube-inbound.
#
# Because containerd invokes NRI RunPodSandbox after CRI RunPodSandbox starts the
# gVisor Sentry (which snapshots Pod netns interfaces at startup and owns an
# internal 127.0.0.1 loopback), this suite validates the production gVisor model
# available on stock Kubernetes today:
#   - RuntimeClass: gvisor (runsc with --host-uds=all and --platform=systrap)
#   - Confinement: eth0 routes flushed + tc clsact DROP (no direct egress)
#   - Outbound: host-UDS egress.sock -> kube-net-driver -> mandatory mTLS HTTP/2
#     -> kube-pep (TCP CONNECT allow/deny, RFC 9298 connect-udp, RFC 8484 DoH
#     NOERROR + NXDOMAIN)
#   - Inbound: kube-inbound watches ResourceClaim.status -> mandatory mTLS
#     CONNECT <podUID>:8080 -> kube-net-driver -> host-UDS ingress.sock ->
#     server inside gVisor Sentry (plus unpinned port 403 & post-delete 404).
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
  host-uds = "all"
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
          adapterMode: ExplicitProxy
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
          import os, socket, threading

          # Serve agents.net ingress.sock over host-UDS inside gVisor Sentry:
          # accepts "CONNECT 127.0.0.1:8080 HTTP/1.1" from kube-net-driver and
          # responds directly over the established stream.
          sock_path = os.environ["AGENTS_NET_INGRESS_SOCKET"]
          if os.path.exists(sock_path):
              os.unlink(sock_path)
          srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
          srv.bind(sock_path)
          os.chmod(sock_path, 0o666)
          srv.listen(32)

          def handle(conn):
              try:
                  buf = b""
                  while b"\r\n\r\n" not in buf:
                      chunk = conn.recv(4096)
                      if not chunk:
                          return
                      buf += chunk
                  head, rest = buf.split(b"\r\n\r\n", 1)
                  first = head.decode().splitlines()[0]
                  if not first.startswith("CONNECT 127.0.0.1:8080 "):
                      conn.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                      return
                  conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                  req = rest
                  while b"\r\n\r\n" not in req:
                      chunk = conn.recv(4096)
                      if not chunk:
                          return
                      req += chunk
                  req_line = req.decode(errors="replace").splitlines()[0]
                  path = req_line.split(" ")[1] if len(req_line.split(" ")) >= 2 else "/"
                  body = f"gvisor-ingress-ok:{path}".encode()
                  resp = (
                      b"HTTP/1.1 200 OK\r\n"
                      b"Content-Type: text/plain\r\n"
                      + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                      + body
                  )
                  conn.sendall(resp)
              finally:
                  conn.close()

          while True:
              c, _ = srv.accept()
              threading.Thread(target=handle, args=(c,), daemon=True).start()
      resources:
        claims:
          - name: agents-net
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
EOF

k -n "${NS}" wait --for=condition=Ready pod/gvisor-agent --timeout=120s

echo "=== 9. Verify gVisor kernel, confinement, outbound TCP/UDP/DoH over host-UDS ==="
k -n "${NS}" exec -i gvisor-agent -- env NS="${NS}" ECHO_IP="${ECHO_IP}" python3 - <<'PY'
import json, os, socket, ssl, struct

ns = os.environ["NS"]
echo_ip = os.environ["ECHO_IP"]
echo_host = f"echo.{ns}.svc.cluster.local"
egress_sock = os.environ["AGENTS_NET_EGRESS_SOCKET"]
ingress_sock = os.environ["AGENTS_NET_INGRESS_SOCKET"]

# 1. Confirm we are actually running inside gVisor Sentry.
with open("/proc/version") as f:
    ver = f.read().strip()
print("Pod /proc/version:", ver)
assert "gvisor" in ver.lower(), f"expected gVisor Sentry kernel, got: {ver}"
assert os.path.exists(egress_sock), f"missing {egress_sock}"
assert os.path.exists(ingress_sock), f"missing {ingress_sock}"

# 2. Direct TCP to echo ClusterIP must fail closed (eth0 blocked in Pod netns).
try:
    s = socket.create_connection((echo_ip, 8443), timeout=2)
    s.close()
    raise SystemExit("FAIL: direct TCP to echo ClusterIP succeeded from gVisor Pod")
except OSError as e:
    print("PASS direct TCP from gVisor Pod blocked:", e)

def dial_egress():
    u = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    u.settimeout(10)
    u.connect(egress_sock)
    return u

def read_http_head(s):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    head, rest = buf.split(b"\r\n\r\n", 1)
    return head.decode(), rest

# 3. Outbound TCP CONNECT over host-UDS egress.sock -> mTLS H2 -> kube-pep -> echo HTTPS.
import http.client
u = dial_egress()
u.sendall(f"CONNECT {echo_host}:8443 HTTP/1.1\r\nHost: {echo_host}:8443\r\n\r\n".encode())
head, rest = read_http_head(u)
assert head.startswith("HTTP/1.1 200"), f"CONNECT allowed failed: {head!r}"
tls_ctx = ssl.create_default_context(cafile=os.environ["SSL_CERT_FILE"])
tls_sock = tls_ctx.wrap_socket(u, server_hostname=echo_host)
tls_sock.sendall(f"GET /gvisor-tcp HTTP/1.1\r\nHost: {echo_host}\r\nConnection: close\r\n\r\n".encode())
hresp = http.client.HTTPResponse(tls_sock)
hresp.begin()
body = hresp.read()
tls_sock.close()
assert hresp.status == 200 and b'"/gvisor-tcp"' in body, (hresp.status, body)
print("PASS gVisor outbound TCP CONNECT via host-UDS -> kube-pep succeeded")

# 4. Denied TCP host fails closed with 403 at kube-pep.
u = dial_egress()
u.sendall(b"CONNECT blocked.example:443 HTTP/1.1\r\nHost: blocked.example:443\r\n\r\n")
head, _ = read_http_head(u)
u.close()
assert head.startswith("HTTP/1.1 403"), f"expected 403 for blocked.example, got: {head!r}"
print("PASS gVisor outbound denied host rejected:", head.splitlines()[0])

# 5. Outbound UDP (RFC 9298 connect-udp) over host-UDS egress.sock -> mTLS H2 -> kube-pep.
def encode_varint(n):
    if n < 64:
        return bytes([n])
    raise ValueError(n)

u = dial_egress()
u.sendall(
    f"GET /.well-known/masque/udp/{echo_host}/8444/ HTTP/1.1\r\n"
    f"Host: boundary\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n".encode()
)
head, rest = read_http_head(u)
assert head.startswith("HTTP/1.1 101"), f"connect-udp upgrade failed: {head!r}"
payload = b"gvisor-udp-ok"
# Capsule: type=0 (DATAGRAM), length=1+len(payload), context_id=0, payload
capsule = encode_varint(0) + encode_varint(1 + len(payload)) + encode_varint(0) + payload
u.sendall(capsule)
data = rest
while len(data) < len(capsule):
    chunk = u.recv(4096)
    if not chunk:
        break
    data += chunk
u.close()
assert data[:len(capsule)] == capsule, f"UDP capsule echo mismatch: {data!r} != {capsule!r}"
print("PASS gVisor outbound UDP connect-udp via host-UDS -> kube-pep echoed:", payload.decode())

# 6. Outbound RFC 8484 DoH over host-UDS egress.sock -> mTLS H2 -> kube-pep (NOERROR + NXDOMAIN).
def build_dns_query(name):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.strip(".").split(".")) + b"\x00"
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)

def doh_query(name):
    wire = build_dns_query(name)
    u = dial_egress()
    req = (
        f"POST /dns-query HTTP/1.1\r\nHost: boundary\r\n"
        f"Content-Type: application/dns-message\r\nAccept: application/dns-message\r\n"
        f"Content-Length: {len(wire)}\r\nConnection: close\r\n\r\n"
    ).encode() + wire
    u.sendall(req)
    hresp = http.client.HTTPResponse(u)
    hresp.begin()
    body = hresp.read()
    u.close()
    assert hresp.status == 200, f"DoH failed for {name}: {hresp.status}"
    flags = struct.unpack("!H", body[2:4])[0]
    return flags & 0x000F

rcode_ok = doh_query(echo_host)
assert rcode_ok == 0, f"DoH {echo_host} rcode={rcode_ok}, want 0 (NOERROR)"
rcode_nx = doh_query("doesnotexist.example")
assert rcode_nx == 3, f"DoH doesnotexist.example rcode={rcode_nx}, want 3 (NXDOMAIN)"
print("PASS gVisor outbound RFC 8484 DoH returned NOERROR for echo and real NXDOMAIN for doesnotexist.example")
PY

echo "=== 10. Verify IP-less inbound via kube-inbound -> mTLS CONNECT -> host-UDS ingress.sock inside gVisor ==="
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
            print("PASS kube-inbound -> mTLS CONNECT -> gVisor host-UDS ingress.sock:", body)
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
python3 - "${PEP_LOGS}" <<'PY'
import json, sys
records = [json.loads(l) for l in sys.argv[1].splitlines() if l.strip().startswith("{")]
assert any(r.get("decision") == "allow" and r.get("transport") == "tcp" and r.get("wire") == "h2" and r.get("peer") == "kube-net-driver-gvisor-client" for r in records), records
assert any(r.get("decision") == "allow" and r.get("transport") == "udp" and r.get("wire") == "h2" and r.get("peer") == "kube-net-driver-gvisor-client" for r in records), records
assert any(r.get("decision") == "allow" and r.get("transport") == "dns" and r.get("wire") == "h2" and r.get("peer") == "kube-net-driver-gvisor-client" for r in records), records
assert any(r.get("decision") == "block" and r.get("transport") == "dns" and r.get("destination") == "doesnotexist.example" for r in records), records
assert any(r.get("decision") == "block" and r.get("destination") == "blocked.example:443" for r in records), records
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
