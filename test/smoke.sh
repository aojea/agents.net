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
# End-to-end Kubernetes smoke test for kube-net-driver (driver: dra.agents.net)
# using agents.net's reference PEP (cmd/kube-pep) and inbound gateway (cmd/kube-inbound).
#
# Verifies:
#   1. Single-manifest installation via install.yaml (kube-system)
#   2. DRA DRAConsumableCapacity ResourceSlice publication & /healthz readiness
#   3. Standard Pod + ResourceClaimTemplate attachment (zero custom workload CRDs)
#   4. Confinement & HostTun (default, zero sidecar, zero Pod caps):
#      - Route flush + pure-netlink tc clsact DROP blocks eth0
#      - Persistent tun0 inside Pod netns handled by separate unprivileged
#        kube-netstack container over emptyDir SCM_RIGHTS socket
#        (UID/GID 65534, zero Linux capabilities, NoNewPrivs=1, Seccomp BPF,
#        zero K8s SA token or host mounts, automatic recovery on SIGKILL)
#      - /etc/resolv.conf replaced via NRI pointing to 198.19.255.253 (198.18.0.0/15)
#      - No HTTP_PROXY env vars, no egress.sock, and no /dev/net/tun in container
#   5. Transparent egress via real cmd/kube-pep (mTLS + HTTP/2 CONNECT + DoH):
#      - Unmodified HTTPS client reaches allowed host with injected SSL_CERT_FILE
#      - Unmodified UDP client reaches allowed UDP host over RFC 9298 connect-udp
#      - Denied host and literal IP fail closed at kube-pep
#      - Unmapped synthetic IP (198.18.9.9) fails closed locally before hitting PEP
#      - kube-pep JSONL audit log records verified mTLS peer + allow/deny
#   6. Option 3 Ingress discovery via ResourceClaim.status.devices[].data +
#      external LoadBalancer attraction via cloud-provider-kind:
#      - Typed dra.agents.net/v1alpha1 DeviceStatus publishes routable <nodeIP>:15080,
#        protocol=http-connect, target=<podUID>, and pinned ports
#      - AGENT_INGRESS_PORT is injected into the workload container
#      - kube-inbound watches ResourceClaims behind a
#        type: LoadBalancer Service provisioned by cloud-provider-kind
#      - Host curl to http://<LoadBalancer-IP> reaches Pod loopback :8080
#        (both path and header routing) and rejects unpinned :9999 with 403
#   7. Pod deletion garbage-collects ResourceClaim and revokes ingress immediately
#      (LoadBalancer returns 404; node bridge returns 404)
#
# Usage:
#   # Create a disposable kind v1.36 cluster, run smoke test, and tear it down:
#   ./test/smoke.sh
#
#   # Or run against an existing kind cluster (cleans up only agents-net-smoke ns):
#   USE_EXISTING_CLUSTER=true KIND_CLUSTER_NAME=agent-sandbox \
#     KUBECONFIG=/path/to/kubeconfig KUBE_CONTEXT=kind-agent-sandbox \
#     ./test/smoke.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

USE_EXISTING_CLUSTER="${USE_EXISTING_CLUSTER:-false}"
USE_CLOUD_PROVIDER_KIND="${USE_CLOUD_PROVIDER_KIND:-auto}"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-dra-agents-net-smoke}"
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-kindest/node:v1.36.1}"
PYTHON_IMAGE="${PYTHON_IMAGE:-python:3.14-slim}"
NS="${SMOKE_NAMESPACE:-agents-net-smoke}"

DRIVER_IMAGE="kind.local/kube-net-driver:smoke"
STACK_IMAGE="kind.local/kube-netstack:smoke"
INBOUND_IMAGE="kind.local/kube-inbound:smoke"
PEP_IMAGE="kind.local/kube-pep:smoke"

TMPDIR="$(mktemp -d)"
CREATED_CLUSTER="false"
CPK_PID=""

KUBECTL_ARGS=()
if [ -n "${KUBECONFIG:-}" ]; then
  KUBECTL_ARGS+=(--kubeconfig "${KUBECONFIG}")
fi
if [ -n "${KUBE_CONTEXT:-}" ]; then
  KUBECTL_ARGS+=(--context "${KUBE_CONTEXT}")
fi
k() {
  kubectl "${KUBECTL_ARGS[@]}" "$@"
}

cleanup() {
  local rc=$?
  if [ "${rc}" -ne 0 ]; then
    echo "=== Smoke test failed (rc=${rc}); dumping diagnostics ===" >&2
    k -n kube-system logs -l app.kubernetes.io/name=kube-net-driver --all-containers --tail=60 >&2 || true
    k -n "${NS}" get pods,resourceclaims,svc -o wide >&2 || true
    k -n "${NS}" logs deploy/kube-pep --tail=40 >&2 || true
    k -n "${NS}" logs deploy/kube-inbound --tail=40 >&2 || true
    if [ -f "${TMPDIR}/cloud-provider-kind.log" ]; then
      tail -n 40 "${TMPDIR}/cloud-provider-kind.log" >&2 || true
    fi
  fi
  if [ "${CREATED_CLUSTER}" = "true" ]; then
    k -n "${NS}" delete svc kube-inbound --ignore-not-found >/dev/null 2>&1 || true
    sleep 2
    if [ -n "${CPK_PID}" ]; then
      kill "${CPK_PID}" >/dev/null 2>&1 || true
      wait "${CPK_PID}" >/dev/null 2>&1 || true
    fi
    kind delete cluster --name "${KIND_CLUSTER_NAME}" >/dev/null 2>&1 || true
  else
    # Delete LoadBalancer Service first while cloud-provider-kind is still running so
    # it removes its Envoy LB container cleanly before we stop cloud-provider-kind.
    k -n "${NS}" delete svc kube-inbound --ignore-not-found --wait=true >/dev/null 2>&1 || true
    k delete deviceclass dra.agents.net-smoke dra.agents.net-smoke-doh --ignore-not-found >/dev/null 2>&1 || true
    k delete clusterrolebinding "${NS}-kube-inbound" --ignore-not-found >/dev/null 2>&1 || true
    k delete clusterrole "${NS}-kube-inbound" --ignore-not-found >/dev/null 2>&1 || true
    k -n kube-system delete secret smoke-driver-client-tls smoke-bridge-tls --ignore-not-found >/dev/null 2>&1 || true
    k -n kube-system delete configmap smoke-ca --ignore-not-found >/dev/null 2>&1 || true
    k delete namespace "${NS}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    if [ -n "${CPK_PID}" ]; then
      sleep 2
      kill "${CPK_PID}" >/dev/null 2>&1 || true
      wait "${CPK_PID}" >/dev/null 2>&1 || true
    fi
  fi
  rm -rf "${TMPDIR}"
  exit "${rc}"
}
trap cleanup EXIT

echo "=== 1. Build kube-net-driver, kube-netstack, kube-inbound, and kube-pep images ==="
docker build --load -t "${DRIVER_IMAGE}" -f "${REPO_ROOT}/Dockerfile.kube-net-driver" "${REPO_ROOT}"
docker build --load -t "${STACK_IMAGE}" -f "${REPO_ROOT}/Dockerfile.kube-netstack" "${REPO_ROOT}"
docker build --load -t "${INBOUND_IMAGE}" -f "${REPO_ROOT}/Dockerfile.kube-inbound" "${REPO_ROOT}"
docker build --load -t "${PEP_IMAGE}" -f "${REPO_ROOT}/Dockerfile.kube-pep" "${REPO_ROOT}"

if [ "${USE_EXISTING_CLUSTER}" != "true" ]; then
  echo "=== 2. Create disposable kind cluster (${KIND_CLUSTER_NAME}, ${KIND_NODE_IMAGE}) with NRI enabled ==="
  cat > "${TMPDIR}/kind-config.yaml" <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
containerdConfigPatches:
  - |-
    [plugins."io.containerd.nri.v1.nri"]
      disable = false
EOF
  KUBECONFIG="${TMPDIR}/kubeconfig"
  KUBE_CONTEXT="kind-${KIND_CLUSTER_NAME}"
  KUBECTL_ARGS=(--kubeconfig "${KUBECONFIG}" --context "${KUBE_CONTEXT}")
  kind create cluster \
    --name "${KIND_CLUSTER_NAME}" \
    --image "${KIND_NODE_IMAGE}" \
    --config "${TMPDIR}/kind-config.yaml" \
    --kubeconfig "${KUBECONFIG}" \
    --wait 120s
  CREATED_CLUSTER="true"
else
  echo "=== 2. Using existing kind cluster (${KIND_CLUSTER_NAME}) ==="
fi

echo "=== 3. Load images into kind cluster ==="
kind load docker-image --name "${KIND_CLUSTER_NAME}" "${DRIVER_IMAGE}" "${STACK_IMAGE}" "${INBOUND_IMAGE}" "${PEP_IMAGE}"

RUN_CPK="false"
if [ "${USE_CLOUD_PROVIDER_KIND}" = "true" ] || { [ "${USE_CLOUD_PROVIDER_KIND}" = "auto" ] && command -v cloud-provider-kind >/dev/null 2>&1; }; then
  RUN_CPK="true"
  if ! pgrep -x cloud-provider-kind >/dev/null 2>&1; then
    echo "=== 3b. Start cloud-provider-kind for LoadBalancer ingress testing ==="
    CPK_FLAGS=(--gateway-channel=disabled --enable-default-ingress=false)
    cloud-provider-kind "${CPK_FLAGS[@]}" >"${TMPDIR}/cloud-provider-kind.log" 2>&1 &
    CPK_PID=$!
    sleep 2
  else
    echo "=== 3b. Using already-running cloud-provider-kind ==="
  fi
fi

echo "=== 4. Generate ephemeral PKI for mandatory mTLS (egress PEP + ingress bridge) ==="
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "${TMPDIR}/ca.key" -out "${TMPDIR}/ca.crt" -days 1 \
  -subj "/CN=agents-net-smoke-ca" \
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
gen_cert "client" "kube-net-driver-smoke-client" \
  "DNS:kube-net-driver-smoke-client" \
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

echo "=== 5. Install install.yaml into kube-system (with mounted mTLS certs) ==="
k -n kube-system delete secret smoke-driver-client-tls smoke-bridge-tls --ignore-not-found >/dev/null 2>&1 || true
k -n kube-system delete configmap smoke-ca --ignore-not-found >/dev/null 2>&1 || true
k -n kube-system create configmap smoke-ca --from-file=ca.crt="${TMPDIR}/ca.crt"
k -n kube-system create secret tls smoke-driver-client-tls --cert="${TMPDIR}/client.crt" --key="${TMPDIR}/client.key"
k -n kube-system create secret tls smoke-bridge-tls --cert="${TMPDIR}/bridge.crt" --key="${TMPDIR}/bridge.key"

sed -e "s|image: ghcr.io/aojea/agents.net/kube-net-driver:latest|image: ${DRIVER_IMAGE}|g" \
    -e "s|image: ghcr.io/aojea/agents.net/kube-netstack:latest|image: ${STACK_IMAGE}|g" \
  "${REPO_ROOT}/install.yaml" | k apply -f -

# Mount node mTLS client cert (egress PEP) and mTLS bridge server cert/client CA (ingress)
# directly onto the kube-net-driver container ONLY so kube-netstack sees zero mTLS keys
# and kube-net-driver needs ZERO Kubernetes Secret RBAC.
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
            - name: smoke-client-tls
              mountPath: /etc/dra-agents-net/client
              readOnly: true
            - name: smoke-bridge-tls
              mountPath: /etc/dra-agents-net/ingress
              readOnly: true
            - name: smoke-ca
              mountPath: /etc/dra-agents-net/ca
              readOnly: true
      volumes:
        - name: smoke-client-tls
          secret:
            secretName: smoke-driver-client-tls
        - name: smoke-bridge-tls
          secret:
            secretName: smoke-bridge-tls
        - name: smoke-ca
          configMap:
            name: smoke-ca
'
k -n kube-system rollout status daemonset/kube-net-driver --timeout=120s
k get deviceclass dra.agents.net
k get resourceslices --field-selector=spec.driver=dra.agents.net

echo "=== 6. Deploy echo target & reference kube-pep in ${NS} ==="
k delete namespace "${NS}" --ignore-not-found --wait=true >/dev/null 2>&1 || true
k create namespace "${NS}"

k -n "${NS}" create configmap smoke-ca --from-file=ca.crt="${TMPDIR}/ca.crt"
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
                      body = json.dumps({"ok": True, "path": self.path, "host": self.headers.get("Host")}).encode()
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
echo "echo Service ClusterIP=${ECHO_IP} (allowed resolved_addresses CIDR=${ECHO_CIDR})"

cat > "${TMPDIR}/policy.json" <<EOF
{
  "agents_net_policy": 1,
  "version": "smoke-v1",
  "sandbox": "smoke-agent",
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
            - -generation=smoke-gen-1
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
            name: smoke-ca
EOF

k -n "${NS}" rollout status deployment/echo --timeout=90s
k -n "${NS}" rollout status deployment/kube-pep --timeout=90s

echo "=== 7. Deploy smoke DeviceClass (admin PEP + mTLS) + ResourceClaimTemplate + isolated Pod ==="
cat <<EOF | k apply -f -
apiVersion: resource.k8s.io/v1
kind: DeviceClass
metadata:
  name: dra.agents.net-smoke
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
          custom:
            suite: smoke
---
apiVersion: resource.k8s.io/v1
kind: ResourceClaimTemplate
metadata:
  name: smoke-agents-net
  namespace: ${NS}
spec:
  spec:
    devices:
      requests:
        - name: agents-net
          exactly:
            deviceClassName: dra.agents.net-smoke
            allocationMode: ExactCount
            count: 1
      config:
        - requests: ["agents-net"]
          opaque:
            driver: dra.agents.net
            parameters:
              apiVersion: dra.agents.net/v1alpha1
              kind: DriverConfig
              caTrust:
                mode: InjectEnv
                bundleMode: AppendSystemRoots
                sources:
                  - type: ConfigMap
                    configMapRef:
                      name: smoke-ca
                      key: ca.crt
              ingressPorts:
                - port: 8080
                  protocol: TCP
                - port: 9000
                  endPort: 9002
                  protocol: TCP
---
apiVersion: v1
kind: Pod
metadata:
  name: smoke-agent
  namespace: ${NS}
spec:
  automountServiceAccountToken: false
  terminationGracePeriodSeconds: 1
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
  resourceClaims:
    - name: agents-net
      resourceClaimTemplateName: smoke-agents-net
  containers:
    - name: agent
      image: ${PYTHON_IMAGE}
      imagePullPolicy: IfNotPresent
      command:
        - python3
        - -c
        - |
          import http.server, os, threading
          port = int(os.environ.get("AGENT_INGRESS_PORT", "8080"))
          def make_handler(label):
              class H(http.server.BaseHTTPRequestHandler):
                  def do_GET(self):
                      body = f"{label}:{self.path}".encode()
                      self.send_response(200)
                      self.send_header("Content-Length", str(len(body)))
                      self.end_headers()
                      self.wfile.write(body)
                  def log_message(self, *args):
                      pass
              return H
          threading.Thread(
              target=http.server.ThreadingHTTPServer(("127.0.0.1", 9001), make_handler("smoke-range-9001")).serve_forever,
              daemon=True,
          ).start()
          http.server.ThreadingHTTPServer(("127.0.0.1", port), make_handler("smoke-ingress-ok")).serve_forever()
      resources:
        claims:
          - name: agents-net
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
EOF

k -n "${NS}" wait --for=condition=Ready pod/smoke-agent --timeout=90s
POD_UID="$(k -n "${NS}" get pod smoke-agent -o jsonpath='{.metadata.uid}')"
CLAIM_NAME="$(k -n "${NS}" get resourceclaim -o jsonpath='{.items[0].metadata.name}')"
echo "smoke-agent PodUID=${POD_UID} ResourceClaim=${CLAIM_NAME}"

echo "=== 8. Assert HostTun default confinement, transparent TCP/UDP egress, VirtualDNS fail-closed, and zero sidecar ==="
k -n "${NS}" exec -i smoke-agent -- env ECHO_IP="${ECHO_IP}" NS="${NS}" python3 - <<'PY'
import ipaddress, json, os, socket, urllib.error, urllib.request

# 1. Verify HostTun defaults: AGENT_INGRESS_PORT and CA env vars injected; NO proxy env vars, NO egress.sock, NO /dev/net/tun.
assert os.environ.get("AGENT_INGRESS_PORT") == "8080", f"AGENT_INGRESS_PORT={os.environ.get('AGENT_INGRESS_PORT')!r}"
assert os.environ.get("AGENT_CA_CERT") == "/var/run/agent-ca.pem", f"AGENT_CA_CERT={os.environ.get('AGENT_CA_CERT')!r}"
assert os.environ.get("SSL_CERT_FILE") == "/var/run/agent-ca.pem", f"SSL_CERT_FILE={os.environ.get('SSL_CERT_FILE')!r}"
assert not os.environ.get("HTTP_PROXY") and not os.environ.get("HTTPS_PROXY"), "HostTun must not inject HTTP_PROXY/HTTPS_PROXY"
assert not os.path.exists("/run/agents.net/egress.sock"), "HostTun must not mount egress.sock into container"
assert not os.path.exists("/dev/net/tun"), "HostTun must not expose /dev/net/tun into container"

# 2. Verify NRI replaced /etc/resolv.conf with the HostTun virtual DNS resolver (no search/ndots:5 trap).
with open("/etc/resolv.conf") as f:
    resolv = f.read()
assert resolv == "nameserver 198.19.255.253\n", f"unexpected /etc/resolv.conf: {resolv!r}"
print("PASS HostTun /etc/resolv.conf replaced cleanly:", resolv.strip())

# 3. Verify all non-loopback routes belong exclusively to tun0 (eth0 routes flushed).
with open("/proc/net/route") as f:
    ifaces = {ln.split()[0] for ln in f.readlines()[1:] if ln.strip()}
assert ifaces == {"tun0"}, f"expected routes only on tun0, got: {ifaces}"
print("PASS non-loopback routes owned exclusively by tun0")

# 4. Verify DNS resolves into RFC 2544 synthetic pool 198.18.0.0/15 (not CGNAT 100.64.0.0/10).
echo_host = f"echo.{os.environ['NS']}.svc.cluster.local"
resolved_ip = socket.gethostbyname(echo_host)
assert ipaddress.ip_address(resolved_ip) in ipaddress.ip_network("198.18.0.0/15"), f"unexpected synthetic IP: {resolved_ip}"
print(f"PASS VirtualDNS resolved {echo_host} -> {resolved_ip} (198.18.0.0/15)")

# 5. Unmodified HTTPS client (zero proxy env vars) succeeds transparently through connect-proxy PEP.
url = f"https://{echo_host}:8443/smoke-ok"
with urllib.request.urlopen(url, timeout=10) as resp:
    data = json.loads(resp.read().decode())
    assert resp.status == 200 and data["ok"] is True and data["path"] == "/smoke-ok", data
    print("PASS HostTun transparent HTTPS via connect-proxy:", data)

# 6. Denied host fails closed transparently at connect-proxy.
try:
    urllib.request.urlopen("https://blocked.example:443/", timeout=5)
    raise SystemExit("FAIL: blocked.example unexpectedly succeeded")
except (urllib.error.URLError, OSError) as e:
    print("PASS HostTun denied blocked.example:", e)

# 7. Literal IP dial to echo ClusterIP fails closed (connect-proxy policy allows hostname only, not IP literal).
try:
    socket.create_connection((os.environ["ECHO_IP"], 8443), timeout=5).close()
    raise SystemExit("FAIL: literal IP to echo ClusterIP succeeded")
except OSError as e:
    print("PASS HostTun denied literal IP to echo ClusterIP:", e)

# 8. Unmapped synthetic IP in 198.18.0.0/15 fails closed locally in Forwarder without reaching PEP.
try:
    socket.create_connection(("198.18.9.9", 443), timeout=5).close()
    raise SystemExit("FAIL: unmapped synthetic IP 198.18.9.9 succeeded")
except OSError as e:
    print("PASS HostTun failed closed on unmapped synthetic IP 198.18.9.9:", e)

# 9. Unmodified UDP socket succeeds transparently over RFC 9298 connect-udp -> connect-proxy -h2.
payload = b"udp-h2-smoke-ok"
udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_sock.settimeout(10)
udp_sock.sendto(payload, (echo_host, 8444))
echoed, _ = udp_sock.recvfrom(4096)
udp_sock.close()
assert echoed == payload, f"UDP echo mismatch: got={echoed!r} want={payload!r}"
print("PASS HostTun transparent UDP over RFC 9298 connect-udp echoed:", echoed.decode())
PY

if docker inspect "${KIND_CLUSTER_NAME}-control-plane" >/dev/null 2>&1; then
  echo "=== 8b. Assert two-container kube-netstack privilege separation, seccomp, zero-secret mounts & crash recovery ==="
  OLD_STACK_PID="$(docker exec "${KIND_CLUSTER_NAME}-control-plane" bash -euo pipefail -c '
    parent_pid=""
    stack_pid=""
    for p in /proc/[0-9]*; do
      pid="${p#/proc/}"
      cmd="$(tr "\0" " " < "${p}/cmdline" 2>/dev/null || true)"
      if [[ "${cmd}" == "/kube-netstack --socket="* ]]; then
        stack_pid="${pid}"
      elif [[ "${cmd}" == "/kube-net-driver "* ]]; then
        parent_pid="${pid}"
      fi
    done
    if [ -z "${parent_pid}" ] || [ -z "${stack_pid}" ]; then
      echo "FAIL: could not locate parent (${parent_pid}) or stack container (${stack_pid}) processes" >&2
      exit 1
    fi
    for tstatus in "/proc/${stack_pid}/task/"*/status; do
      status="$(cat "${tstatus}")"
      for pat in \
        "^Uid:[[:space:]]+65534[[:space:]]+65534[[:space:]]+65534[[:space:]]+65534$" \
        "^Gid:[[:space:]]+65534[[:space:]]+65534[[:space:]]+65534[[:space:]]+65534$" \
        "^CapEff:[[:space:]]+0000000000000000$" \
        "^CapPrm:[[:space:]]+0000000000000000$" \
        "^CapInh:[[:space:]]+0000000000000000$" \
        "^CapAmb:[[:space:]]+0000000000000000$" \
        "^NoNewPrivs:[[:space:]]+1$" \
        "^Seccomp:[[:space:]]+2$"; do
        if ! grep -qE "${pat}" <<<"${status}"; then
          echo "FAIL: stack thread ${tstatus} failed check ${pat}" >&2
          grep -E "^(Uid|Gid|Cap|NoNewPrivs|Seccomp):" <<<"${status}" >&2 || true
          exit 1
        fi
      done
    done
    # Verify kube-netstack runs in its own mount namespace with zero K8s SA token,
    # zero host netns/NRI mounts, and zero mTLS private key mounts.
    if [ -e "/proc/${stack_pid}/root/var/run/secrets/kubernetes.io/serviceaccount" ]; then
      echo "FAIL: kube-netstack container unexpectedly has Kubernetes ServiceAccount token mounted" >&2
      exit 1
    fi
    if grep -qE " (/var/run/netns|/var/run/nri|/etc/dra-agents-net|/var/lib/kubelet) " "/proc/${stack_pid}/mountinfo"; then
      echo "FAIL: kube-netstack container unexpectedly mounted privileged host/secret paths" >&2
      exit 1
    fi
    # Verify parent holds zero open /dev/net/tun descriptors after SCM_RIGHTS handoff.
    if ls -l "/proc/${parent_pid}/fd" 2>/dev/null | grep -q "/dev/net/tun"; then
      echo "FAIL: parent kube-net-driver still holds an open /dev/net/tun FD" >&2
      exit 1
    fi
    echo "PASS unprivileged kube-netstack container PID=${stack_pid} (all threads uid=65534, Cap=0, NoNewPrivs=1, Seccomp=2, zero SA token/host mounts, zero tunFD in parent)" >&2
    echo "${stack_pid}"
  ')"

  # Kill the kube-netstack container directly; verify kubelet restarts it and
  # kube-net-driver automatically reconnects and recovers persistent tun0.
  docker exec "${KIND_CLUSTER_NAME}-control-plane" kill -9 "${OLD_STACK_PID}"
  NEW_STACK_PID=""
  for _ in $(seq 1 100); do
    NEW_STACK_PID="$(docker exec "${KIND_CLUSTER_NAME}-control-plane" bash -c '
      for p in /proc/[0-9]*; do
        pid="${p#/proc/}"
        cmd="$(tr "\0" " " < "${p}/cmdline" 2>/dev/null || true)"
        if [[ "${cmd}" == "/kube-netstack --socket="* ]]; then
          echo "${pid}"
          exit 0
        fi
      done
    ' || true)"
    if [ -n "${NEW_STACK_PID}" ] && [ "${NEW_STACK_PID}" != "${OLD_STACK_PID}" ]; then
      break
    fi
    sleep 0.2
  done
  if [ -z "${NEW_STACK_PID}" ] || [ "${NEW_STACK_PID}" = "${OLD_STACK_PID}" ]; then
    echo "FAIL: kube-netstack container did not restart after SIGKILL (old=${OLD_STACK_PID} new=${NEW_STACK_PID})" >&2
    exit 1
  fi
  echo "PASS kube-netstack container restarted by kubelet after SIGKILL: ${OLD_STACK_PID} -> ${NEW_STACK_PID}"

  k -n "${NS}" exec -i smoke-agent -- env NS="${NS}" python3 - <<'PY'
import json, os, time, urllib.request
echo_host = f"echo.{os.environ['NS']}.svc.cluster.local"
last_err = None
for _ in range(25):
    try:
        with urllib.request.urlopen(f"https://{echo_host}:8443/after-stack-kill", timeout=5) as resp:
            data = json.loads(resp.read().decode())
            assert resp.status == 200 and data["ok"] is True and data["path"] == "/after-stack-kill", data
            print("PASS HostTun transparent HTTPS recovered after kube-netstack SIGKILL:", data)
            last_err = None
            break
    except Exception as e:
        last_err = e
        time.sleep(0.2)
if last_err is not None:
    raise SystemExit(f"FAIL: transparent HTTPS did not recover after stack restart: {last_err}")
PY
fi

echo "=== 8c. Assert HostTun DoH DNS mode (resolv.conf search/ndots:5, short K8s Service name, and real NXDOMAIN) ==="
cat <<EOF | k apply -f -
apiVersion: resource.k8s.io/v1
kind: DeviceClass
metadata:
  name: dra.agents.net-smoke-doh
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
  name: smoke-agents-net-doh
  namespace: ${NS}
spec:
  spec:
    devices:
      requests:
        - name: agents-net
          exactly:
            deviceClassName: dra.agents.net-smoke-doh
            allocationMode: ExactCount
            count: 1
      config:
        - requests: ["agents-net"]
          opaque:
            driver: dra.agents.net
            parameters:
              apiVersion: dra.agents.net/v1alpha1
              kind: DriverConfig
              caTrust:
                mode: InjectEnv
                bundleMode: AppendSystemRoots
                sources:
                  - type: ConfigMap
                    configMapRef:
                      name: smoke-ca
                      key: ca.crt
---
apiVersion: v1
kind: Pod
metadata:
  name: smoke-agent-doh
  namespace: ${NS}
spec:
  automountServiceAccountToken: false
  terminationGracePeriodSeconds: 1
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
  resourceClaims:
    - name: agents-net
      resourceClaimTemplateName: smoke-agents-net-doh
  containers:
    - name: agent
      image: ${PYTHON_IMAGE}
      imagePullPolicy: IfNotPresent
      command: ["python3", "-c", "import time; time.sleep(300)"]
      resources:
        claims:
          - name: agents-net
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
EOF
k -n "${NS}" wait --for=condition=Ready pod/smoke-agent-doh --timeout=90s
k -n "${NS}" exec -i smoke-agent-doh -- env NS="${NS}" python3 - <<'PY'
import ipaddress, json, os, socket, ssl, urllib.request

ns = os.environ["NS"]
with open("/etc/resolv.conf") as f:
    resolv = f.read()
assert "nameserver 198.19.255.253\n" in resolv, resolv
assert f"search {ns}.svc.cluster.local svc.cluster.local cluster.local\n" in resolv, resolv
assert "options ndots:5\n" in resolv, resolv
print("PASS DoH /etc/resolv.conf preserves Kubernetes search list + ndots:5")

# 1. Bare short Kubernetes Service name "echo" resolves via search expansion + DoH into 198.18.0.0/15.
short_ip = socket.gethostbyname("echo")
assert ipaddress.ip_address(short_ip) in ipaddress.ip_network("198.18.0.0/15"), f"short name resolved to non-synthetic IP: {short_ip}"
print(f"PASS DoH short K8s Service name 'echo' resolved via search list -> {short_ip} (198.18.0.0/15)")

# 2. Connecting via short name's synthetic IP reaches echo.NS.svc.cluster.local transparently.
ctx = ssl.create_default_context(cafile=os.environ["SSL_CERT_FILE"])
raw = socket.create_connection((short_ip, 8443), timeout=10)
tls_sock = ctx.wrap_socket(raw, server_hostname=f"echo.{ns}.svc.cluster.local")
tls_sock.sendall(f"GET /doh-short HTTP/1.1\r\nHost: echo.{ns}.svc.cluster.local\r\nConnection: close\r\n\r\n".encode())
chunks = []
while True:
    c = tls_sock.recv(4096)
    if not c:
        break
    chunks.append(c)
tls_sock.close()
resp_text = b"".join(chunks).decode()
assert "200 OK" in resp_text and '"/doh-short"' in resp_text, resp_text
print("PASS DoH short name transparent HTTPS via kube-pep succeeded")

# 3. FQDN with < 5 dots (echo.NS.svc.cluster.local has 4 dots < ndots:5) triggers search
#    attempts that receive real NXDOMAIN before succeeding on the FQDN itself.
fqdn = f"echo.{ns}.svc.cluster.local"
with urllib.request.urlopen(f"https://{fqdn}:8443/doh-fqdn", timeout=10) as resp:
    data = json.loads(resp.read().decode())
    assert resp.status == 200 and data["ok"] is True and data["path"] == "/doh-fqdn", data
    print("PASS DoH FQDN traversed search NXDOMAIN cleanly:", data)

# 4. Non-existent / disallowed domain fails at DNS resolution time (NXDOMAIN -> socket.gaierror)
#    rather than returning a synthetic IP.
try:
    ip = socket.gethostbyname("doesnotexist.example")
    raise SystemExit(f"FAIL: doesnotexist.example unexpectedly resolved to {ip}")
except socket.gaierror as e:
    print("PASS DoH returned real NXDOMAIN for doesnotexist.example:", e)
PY
k -n "${NS}" delete pod smoke-agent-doh --wait=true >/dev/null
k delete deviceclass dra.agents.net-smoke-doh --ignore-not-found >/dev/null

echo "=== 9. Verify kube-pep JSONL audit log recorded mTLS peer + h2 TCP, UDP & DNS allow + deny (and zero unmapped synthetic IPs) ==="
PEP_LOGS="$(k -n "${NS}" logs deploy/kube-pep)"
echo "${PEP_LOGS}"
python3 - "${PEP_LOGS}" <<'PY'
import json, sys
records = []
for line in sys.argv[1].splitlines():
    line = line.strip()
    if line.startswith("{"):
        records.append(json.loads(line))
tcp_allows = [r for r in records if r.get("decision") == "allow" and r.get("transport") == "tcp" and r.get("peer") == "kube-net-driver-smoke-client" and r.get("wire") == "h2"]
udp_allows = [r for r in records if r.get("decision") == "allow" and r.get("transport") == "udp" and r.get("peer") == "kube-net-driver-smoke-client" and r.get("wire") == "h2"]
dns_allows = [r for r in records if r.get("decision") == "allow" and r.get("transport") == "dns" and r.get("peer") == "kube-net-driver-smoke-client" and r.get("wire") == "h2"]
dns_blocks = [r for r in records if r.get("decision") == "block" and r.get("transport") == "dns" and r.get("destination") == "doesnotexist.example" and r.get("reason") == "not-on-allowlist"]
blocks = [r for r in records if r.get("decision") == "block" and r.get("destination") == "blocked.example:443" and r.get("reason") == "not-on-allowlist"]
synthetic_leaks = [r for r in records if "198.18.9.9" in str(r.get("destination", ""))]
assert tcp_allows, f"missing TCP allow audit record with mTLS peer & h2: {records}"
assert udp_allows, f"missing UDP allow audit record with mTLS peer & h2: {records}"
assert dns_allows, f"missing DNS DoH allow audit record with mTLS peer & h2: {records}"
assert dns_blocks, f"missing DNS DoH block audit record for doesnotexist.example: {records}"
assert blocks, f"missing block audit record for blocked.example:443: {records}"
assert not synthetic_leaks, f"unmapped synthetic IP leaked to PEP: {synthetic_leaks}"
print(f"PASS kube-pep audit: {len(tcp_allows)} TCP allow(s), {len(udp_allows)} UDP allow(s), {len(dns_allows)} DNS allow(s), {len(dns_blocks)} DNS block(s) (mTLS peer + h2), {len(blocks)} TCP block(s), 0 synthetic IP leaks")
PY

echo "=== 10. Assert Option 3 Ingress discovery via ResourceClaim.status.devices[].data ==="
CLAIM_STATUS_JSON=""
for _ in $(seq 1 20); do
  CLAIM_STATUS_JSON="$(k -n "${NS}" get resourceclaim "${CLAIM_NAME}" -o jsonpath='{.status.devices[0].data}')"
  if [ -n "${CLAIM_STATUS_JSON}" ]; then
    break
  fi
  sleep 0.5
done
echo "ResourceClaim.status.devices[0].data=${CLAIM_STATUS_JSON}"

INGRESS_ENDPOINT="$(python3 - "${CLAIM_STATUS_JSON}" "${POD_UID}" <<'PY'
import json, sys
data = json.loads(sys.argv[1])
pod_uid = sys.argv[2]
assert data["apiVersion"] == "dra.agents.net/v1alpha1", data
assert data["kind"] == "DeviceStatus", data
assert data["podUID"] == pod_uid, data
assert data.get("sandboxID"), data
ing = data.get("ingress")
assert ing is not None, f"missing ingress in DeviceStatus: {data}"
assert ing["protocol"] == "http-connect", ing
assert ing["target"] == pod_uid, ing
assert ing["tls"] is True, ing
assert ing.get("serverName") == "kube-net-driver.kube-system.svc", ing
assert ing["endpoint"] and not ing["endpoint"].startswith(":"), ing
assert any(p["port"] == 8080 and p["protocol"] == "TCP" for p in ing["ports"]), ing
assert any(p["port"] == 9000 and p.get("endPort") == 9002 and p["protocol"] == "TCP" for p in ing["ports"]), ing
print(ing["endpoint"])
PY
)"
echo "Discovered ingress bridge endpoint=${INGRESS_ENDPOINT} target=${POD_UID}"

echo "=== 11. Deploy kube-inbound behind LoadBalancer (cloud-provider-kind) & verify external ingress ==="
GW_SVC_TYPE="ClusterIP"
if [ "${RUN_CPK}" = "true" ]; then
  GW_SVC_TYPE="LoadBalancer"
fi
cat <<EOF | k apply -f -
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
            name: smoke-ca
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
  type: ${GW_SVC_TYPE}
  selector:
    app: kube-inbound
  ports:
    - name: http
      port: 80
      targetPort: 8080
EOF
k -n "${NS}" rollout status deployment/kube-inbound --timeout=60s

LB_IP=""
if [ "${RUN_CPK}" = "true" ]; then
  for _ in $(seq 1 30); do
    LB_IP="$(k -n "${NS}" get svc kube-inbound -o jsonpath='{.status.loadBalancer.ingress[0].ip}')"
    if [ -n "${LB_IP}" ]; then
      break
    fi
    sleep 1
  done
  if [ -z "${LB_IP}" ]; then
    echo "FAIL: cloud-provider-kind did not assign an external LoadBalancer IP" >&2
    exit 1
  fi
  echo "cloud-provider-kind assigned LoadBalancer IP=${LB_IP}"

  # Wait briefly for Envoy LB endpoints to converge, then test directly from the HOST!
  LB_BODY=""
  for _ in $(seq 1 20); do
    if LB_BODY="$(curl -sf --max-time 5 "http://${LB_IP}/agents/${NS}/smoke-agent/hello-via-lb" 2>/dev/null)"; then
      break
    fi
    sleep 1
  done
  if [ "${LB_BODY}" != "smoke-ingress-ok:/hello-via-lb" ]; then
    echo "FAIL: external LoadBalancer path route returned '${LB_BODY}', want 'smoke-ingress-ok:/hello-via-lb'" >&2
    exit 1
  fi
  echo "PASS host -> cloud-provider-kind LoadBalancer (${LB_IP}) path route -> Pod loopback :8080: ${LB_BODY}"

  HDR_BODY="$(curl -sf --max-time 5 -H "X-Agents-Net-Namespace: ${NS}" -H "X-Agents-Net-Pod: smoke-agent" "http://${LB_IP}/hello-via-headers")"
  if [ "${HDR_BODY}" != "smoke-ingress-ok:/hello-via-headers" ]; then
    echo "FAIL: external LoadBalancer header route returned '${HDR_BODY}'" >&2
    exit 1
  fi
  echo "PASS host -> cloud-provider-kind LoadBalancer (${LB_IP}) header route -> Pod loopback :8080: ${HDR_BODY}"

  RANGE_BODY="$(curl -sf --max-time 5 "http://${LB_IP}/agents/${NS}/smoke-agent:9001/hello-range")"
  if [ "${RANGE_BODY}" != "smoke-range-9001:/hello-range" ]; then
    echo "FAIL: external LoadBalancer range port :9001 returned '${RANGE_BODY}', want 'smoke-range-9001:/hello-range'" >&2
    exit 1
  fi
  echo "PASS host -> cloud-provider-kind LoadBalancer (${LB_IP}) port range :9001 -> Pod loopback :9001: ${RANGE_BODY}"

  DENY_HEADERS="$(curl -sS --max-time 5 -D - -o /dev/null "http://${LB_IP}/agents/${NS}/smoke-agent:9999/nope")"
  if ! grep -q '^HTTP/.* 403 ' <<<"${DENY_HEADERS}" || ! grep -qi 'Proxy-Status:.*port-not-permitted' <<<"${DENY_HEADERS}"; then
    echo "FAIL: external LoadBalancer unpinned port :9999 headers: ${DENY_HEADERS}" >&2
    exit 1
  fi
  echo "PASS host -> cloud-provider-kind LoadBalancer (${LB_IP}) unpinned port :9999 rejected: HTTP 403 + Proxy-Status"
fi

cat <<EOF | k apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: ingress-caller
  namespace: ${NS}
spec:
  restartPolicy: Never
  containers:
    - name: caller
      image: ${PYTHON_IMAGE}
      imagePullPolicy: IfNotPresent
      command:
        - python3
        - -c
        - "import time; time.sleep(300)"
      volumeMounts:
        - name: ca
          mountPath: /ca
          readOnly: true
        - name: tls
          mountPath: /tls
          readOnly: true
  volumes:
    - name: ca
      configMap:
        name: smoke-ca
    - name: tls
      secret:
        secretName: gateway-client-tls
EOF
k -n "${NS}" wait --for=condition=Ready pod/ingress-caller --timeout=60s

k -n "${NS}" exec -i ingress-caller -- env INGRESS_ENDPOINT="${INGRESS_ENDPOINT}" POD_UID="${POD_UID}" python3 - <<'PY'
import os, socket, ssl

ep = os.environ["INGRESS_ENDPOINT"]
pod_uid = os.environ["POD_UID"]
if ep.startswith("["):
    host, port = ep[1:].rsplit("]:", 1)
else:
    host, port = ep.rsplit(":", 1)
port = int(port)

# 0. Plaintext or non-mTLS client MUST be rejected by the mandatory mTLS bridge.
raw = socket.create_connection((host, port), timeout=5)
raw.settimeout(5)
raw.sendall(f"CONNECT {pod_uid}:8080 HTTP/1.1\r\nHost: {pod_uid}:8080\r\n\r\n".encode())
plain_resp = raw.recv(1024)
raw.close()
assert not plain_resp.startswith(b"HTTP/1.1 200"), f"plaintext client unexpectedly succeeded: {plain_resp!r}"
print("PASS mandatory mTLS bridge rejected plaintext client")

tls_ctx = ssl.create_default_context(cafile="/ca/ca.crt")
tls_ctx.load_cert_chain("/tls/tls.crt", "/tls/tls.key")

def connect_tunnel(target_port):
    raw_sock = socket.create_connection((host, port), timeout=5)
    s = tls_ctx.wrap_socket(raw_sock, server_hostname="kube-net-driver.kube-system.svc")
    req = f"CONNECT {pod_uid}:{target_port} HTTP/1.1\r\nHost: {pod_uid}:{target_port}\r\n\r\n"
    s.sendall(req.encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    head, rest = buf.split(b"\r\n\r\n", 1)
    return s, head.decode(), rest

# 1. Pinned port 8080 must succeed over mTLS and reach smoke-agent's loopback HTTP server
s, head, rest = connect_tunnel(8080)
assert head.startswith("HTTP/1.1 200"), f"expected 200 OK, got: {head!r}"
s.sendall(b"GET /hello-ingress HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
body = rest
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    body += chunk
s.close()
text = body.decode()
assert "200 OK" in text and "smoke-ingress-ok:/hello-ingress" in text, f"unexpected ingress body: {text!r}"
print("PASS direct mTLS node ingress bridge :8080 delivered HTTP 200:", text.splitlines()[-1])

# 2. Pinned range port 9001 must succeed via direct mTLS node bridge too
s, head, rest = connect_tunnel(9001)
assert head.startswith("HTTP/1.1 200"), f"expected 200 OK on range port 9001, got: {head!r}"
s.sendall(b"GET /hello-range HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
body = rest
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    body += chunk
s.close()
text = body.decode()
assert "200 OK" in text and "smoke-range-9001:/hello-range" in text, f"unexpected range ingress body: {text!r}"
print("PASS direct mTLS node ingress bridge range port :9001 delivered HTTP 200:", text.splitlines()[-1])

# 3. Unpinned port 9999 must be rejected with 403 + RFC 9209 Proxy-Status at the node bridge too
s, head, _ = connect_tunnel(9999)
s.close()
assert head.startswith("HTTP/1.1 403") and "Proxy-Status:" in head and "port-not-permitted" in head, f"expected 403 with Proxy-Status port-not-permitted, got: {head!r}"
assert "Boundary-Reason:" not in head, f"unexpected legacy Boundary-Reason header: {head!r}"
print("PASS direct mTLS node ingress bridge unpinned port :9999 rejected:", head.splitlines()[0])
PY

echo "=== 12. Delete smoke-agent and verify ResourceClaim GC + immediate ingress revocation ==="
k -n "${NS}" delete pod smoke-agent --wait=true
for _ in $(seq 1 20); do
  COUNT="$(k -n "${NS}" get resourceclaims -o name | wc -l | tr -d ' ')"
  if [ "${COUNT}" = "0" ]; then
    break
  fi
  sleep 0.5
done
COUNT="$(k -n "${NS}" get resourceclaims -o name | wc -l | tr -d ' ')"
if [ "${COUNT}" != "0" ]; then
  echo "FAIL: expected 0 ResourceClaims after Pod deletion, got ${COUNT}" >&2
  exit 1
fi
echo "PASS Pod-owned ResourceClaim garbage-collected"

if [ -n "${LB_IP}" ]; then
  REVOKED_HEADERS="$(curl -sS --max-time 5 -D - -o /dev/null "http://${LB_IP}/agents/${NS}/smoke-agent/after-delete")"
  if ! grep -q '^HTTP/.* 404 ' <<<"${REVOKED_HEADERS}" || ! grep -qi 'Proxy-Status:' <<<"${REVOKED_HEADERS}"; then
    echo "FAIL: external LoadBalancer after delete headers: ${REVOKED_HEADERS}" >&2
    exit 1
  fi
  echo "PASS host -> cloud-provider-kind LoadBalancer (${LB_IP}) revoked after delete: HTTP 404 + Proxy-Status"
fi

k -n "${NS}" exec -i ingress-caller -- env INGRESS_ENDPOINT="${INGRESS_ENDPOINT}" POD_UID="${POD_UID}" python3 - <<'PY'
import os, socket, ssl
ep = os.environ["INGRESS_ENDPOINT"]
pod_uid = os.environ["POD_UID"]
if ep.startswith("["):
    host, port = ep[1:].rsplit("]:", 1)
else:
    host, port = ep.rsplit(":", 1)
tls_ctx = ssl.create_default_context(cafile="/ca/ca.crt")
tls_ctx.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
raw_sock = socket.create_connection((host, int(port)), timeout=5)
s = tls_ctx.wrap_socket(raw_sock, server_hostname="kube-net-driver.kube-system.svc")
s.sendall(f"CONNECT {pod_uid}:8080 HTTP/1.1\r\nHost: {pod_uid}:8080\r\n\r\n".encode())
resp = s.recv(4096).decode()
s.close()
assert resp.startswith("HTTP/1.1 404 ") and "Proxy-Status:" in resp, f"expected 404 with Proxy-Status after delete, got: {resp!r}"
print("PASS ingress revoked after Pod deletion:", resp.splitlines()[0])
PY

echo "=== ALL SMOKE TESTS PASSED ==="
