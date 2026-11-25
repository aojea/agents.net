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
# End-to-end Kubernetes smoke test for dra-agents-net (driver: dra.agents.net)
# using agents.net's own reference PEP boundary (sdk/cmd/connect-proxy).
#
# Verifies:
#   1. Single-manifest installation via kubernetes/install.yaml (kube-system)
#   2. DRA DRAConsumableCapacity ResourceSlice publication & /healthz readiness
#   3. Standard Pod + ResourceClaimTemplate attachment (zero custom workload CRDs)
#   4. Confinement: route flush + pure-netlink tc clsact DROP blocks direct TCP
#   5. Egress via real sdk/cmd/connect-proxy (mTLS + HTTP/2 CONNECT + policy.md):
#      - Allowed HTTPS host succeeds with injected SSL_CERT_FILE + HTTPS_PROXY
#      - Denied host fails with 403 Forbidden
#      - connect-proxy JSONL audit log records verified mTLS peer + allow/deny
#   6. Option 3 Ingress discovery via ResourceClaim.status.devices[].data +
#      external LoadBalancer attraction via cloud-provider-kind:
#      - Typed dra.agents.net/v1alpha1 DeviceStatus publishes routable <nodeIP>:15080,
#        protocol=http-connect, target=<podUID>, and pinned ports
#      - AGENT_INGRESS_PORT is injected into the workload container
#      - agents-net-ingress-gateway watches ResourceClaims behind a
#        type: LoadBalancer Service provisioned by cloud-provider-kind
#      - Host curl to http://<LoadBalancer-IP> reaches Pod loopback :8080
#        (both path and header routing) and rejects unpinned :9999 with 403
#   7. Pod deletion garbage-collects ResourceClaim and revokes ingress immediately
#      (LoadBalancer returns 404; node bridge returns 404)
#
# Usage:
#   # Create a disposable kind v1.36 cluster, run smoke test, and tear it down:
#   ./kubernetes/test/smoke.sh
#
#   # Or run against an existing kind cluster (cleans up only agents-net-smoke ns):
#   USE_EXISTING_CLUSTER=true KIND_CLUSTER_NAME=agent-sandbox \
#     KUBECONFIG=/path/to/kubeconfig KUBE_CONTEXT=kind-agent-sandbox \
#     ./kubernetes/test/smoke.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KUBE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${KUBE_DIR}/.." && pwd)"

USE_EXISTING_CLUSTER="${USE_EXISTING_CLUSTER:-false}"
USE_CLOUD_PROVIDER_KIND="${USE_CLOUD_PROVIDER_KIND:-auto}"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-dra-agents-net-smoke}"
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-kindest/node:v1.36.1}"
PYTHON_IMAGE="${PYTHON_IMAGE:-python:3.14-slim}"
NS="${SMOKE_NAMESPACE:-agents-net-smoke}"

DRIVER_IMAGE="kind.local/dra-agents-net:smoke"
GATEWAY_IMAGE="kind.local/agents-net-ingress-gateway:smoke"
PEP_IMAGE="kind.local/agents-net-connect-proxy:smoke"

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
    k -n kube-system logs -l app.kubernetes.io/name=dra-agents-net --tail=60 >&2 || true
    k -n "${NS}" get pods,resourceclaims,svc -o wide >&2 || true
    k -n "${NS}" logs deploy/connect-proxy --tail=40 >&2 || true
    k -n "${NS}" logs deploy/agents-net-ingress-gateway --tail=40 >&2 || true
    if [ -f "${TMPDIR}/cloud-provider-kind.log" ]; then
      tail -n 40 "${TMPDIR}/cloud-provider-kind.log" >&2 || true
    fi
  fi
  if [ "${CREATED_CLUSTER}" = "true" ]; then
    k -n "${NS}" delete svc agents-net-ingress-gateway --ignore-not-found >/dev/null 2>&1 || true
    sleep 2
    if [ -n "${CPK_PID}" ]; then
      kill "${CPK_PID}" >/dev/null 2>&1 || true
      wait "${CPK_PID}" >/dev/null 2>&1 || true
    fi
    kind delete cluster --name "${KIND_CLUSTER_NAME}" >/dev/null 2>&1 || true
  else
    # Delete LoadBalancer Service first while cloud-provider-kind is still running so
    # it removes its Envoy LB container cleanly before we stop cloud-provider-kind.
    k -n "${NS}" delete svc agents-net-ingress-gateway --ignore-not-found --wait=true >/dev/null 2>&1 || true
    k delete clusterrolebinding "${NS}-ingress-gateway" --ignore-not-found >/dev/null 2>&1 || true
    k delete clusterrole "${NS}-ingress-gateway" --ignore-not-found >/dev/null 2>&1 || true
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

echo "=== 1. Build dra-agents-net, agents-net-ingress-gateway, and sdk/cmd/connect-proxy images ==="
docker build --load -t "${DRIVER_IMAGE}" -f "${KUBE_DIR}/Dockerfile" "${KUBE_DIR}"
docker build --load -t "${GATEWAY_IMAGE}" -f "${KUBE_DIR}/Dockerfile.ingress-gateway" "${KUBE_DIR}"
docker build --load -t "${PEP_IMAGE}" -f "${SCRIPT_DIR}/Dockerfile.connect-proxy" "${REPO_ROOT}/sdk"

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
kind load docker-image --name "${KIND_CLUSTER_NAME}" "${DRIVER_IMAGE}" "${GATEWAY_IMAGE}" "${PEP_IMAGE}"

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

echo "=== 4. Install kubernetes/install.yaml into kube-system ==="
sed "s|image: ghcr.io/aojea/agents.net/dra-agents-net:latest|image: ${DRIVER_IMAGE}|g" \
  "${KUBE_DIR}/install.yaml" | k apply -f -
if [ "${USE_EXISTING_CLUSTER}" = "true" ]; then
  k -n kube-system rollout restart daemonset/dra-agents-net
fi
k -n kube-system rollout status daemonset/dra-agents-net --timeout=120s
k get deviceclass dra.agents.net
k get resourceslices --field-selector=spec.driver=dra.agents.net

echo "=== 5. Generate ephemeral PKI for connect-proxy mTLS + echo HTTPS ==="
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

gen_cert "pep" "connect-proxy.${NS}.svc.cluster.local" \
  "DNS:connect-proxy.${NS}.svc.cluster.local,DNS:connect-proxy.${NS}.svc,DNS:connect-proxy" \
  "serverAuth"
gen_cert "client" "dra-agents-net-smoke-client" \
  "DNS:dra-agents-net-smoke-client" \
  "clientAuth"
gen_cert "echo" "echo.${NS}.svc.cluster.local" \
  "DNS:echo.${NS}.svc.cluster.local,DNS:echo.${NS}.svc" \
  "serverAuth"

echo "=== 6. Deploy echo target & agents.net reference connect-proxy PEP in ${NS} ==="
k delete namespace "${NS}" --ignore-not-found --wait=true >/dev/null 2>&1 || true
k create namespace "${NS}"

k -n "${NS}" create configmap smoke-ca --from-file=ca.crt="${TMPDIR}/ca.crt"
k -n "${NS}" create secret tls pep-tls --cert="${TMPDIR}/pep.crt" --key="${TMPDIR}/pep.key"
k -n "${NS}" create secret tls driver-client-tls --cert="${TMPDIR}/client.crt" --key="${TMPDIR}/client.key"
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
              import http.server, json, ssl
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
    "udp": true
  },
  "rules": [
    {
      "id": "allow-echo-https",
      "name": "echo.${NS}.svc.cluster.local",
      "ports": [8443],
      "transports": ["tcp"]
    }
  ],
  "resolved_addresses": [
    {
      "cidr": "${ECHO_CIDR}",
      "ports": [8443]
    }
  ]
}
EOF
k -n "${NS}" create configmap pep-policy --from-file=policy.json="${TMPDIR}/policy.json"

cat <<EOF | k apply -f -
apiVersion: v1
kind: Service
metadata:
  name: connect-proxy
  namespace: ${NS}
spec:
  selector:
    app: connect-proxy
  ports:
    - name: https
      port: 8443
      targetPort: 8443
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: connect-proxy
  namespace: ${NS}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: connect-proxy
  template:
    metadata:
      labels:
        app: connect-proxy
    spec:
      containers:
        - name: connect-proxy
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
k -n "${NS}" rollout status deployment/connect-proxy --timeout=90s

echo "=== 7. Deploy ResourceClaimTemplate + isolated Pod (egress + pinned ingress :8080) ==="
cat <<EOF | k apply -f -
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
            deviceClassName: dra.agents.net
            allocationMode: ExactCount
            count: 1
      config:
        - requests: ["agents-net"]
          opaque:
            driver: dra.agents.net
            parameters:
              apiVersion: dra.agents.net/v1alpha1
              kind: DriverConfig
              confinementMode: NetworkPolicyDenyAll
              policyEnforcementPoint:
                url: https://connect-proxy.${NS}.svc.cluster.local:8443
                tls:
                  serverName: connect-proxy.${NS}.svc.cluster.local
                  caCertificateRefs:
                    - type: ConfigMap
                      configMapRef:
                        name: smoke-ca
                        key: ca.crt
                auth:
                  type: MTLS
                  mtls:
                    secretRef:
                      name: driver-client-tls
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
              custom:
                suite: smoke
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
          import http.server, os
          port = int(os.environ.get("AGENT_INGRESS_PORT", "8080"))
          class H(http.server.BaseHTTPRequestHandler):
              def do_GET(self):
                  body = f"smoke-ingress-ok:{self.path}".encode()
                  self.send_response(200)
                  self.send_header("Content-Length", str(len(body)))
                  self.end_headers()
                  self.wfile.write(body)
              def log_message(self, *args):
                  pass
          http.server.ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
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

echo "=== 8. Assert egress confinement, connect-proxy mTLS/H2 allow & deny, and AGENT_INGRESS_PORT ==="
k -n "${NS}" exec -i smoke-agent -- env ECHO_IP="${ECHO_IP}" NS="${NS}" python3 - <<'PY'
import json, os, socket, urllib.error, urllib.request

# 1. Verify AGENT_INGRESS_PORT injected by NRI CreateContainer
assert os.environ.get("AGENT_INGRESS_PORT") == "8080", f"AGENT_INGRESS_PORT={os.environ.get('AGENT_INGRESS_PORT')!r}"
assert os.environ.get("HTTPS_PROXY") == "http://127.0.0.1:15001", f"HTTPS_PROXY={os.environ.get('HTTPS_PROXY')!r}"
assert os.environ.get("SSL_CERT_FILE") == "/var/run/agent-ca.pem", f"SSL_CERT_FILE={os.environ.get('SSL_CERT_FILE')!r}"

# 2. Verify non-loopback routes were flushed
with open("/proc/net/route") as f:
    routes = [ln.strip() for ln in f.readlines()[1:] if ln.strip()]
assert len(routes) == 0, f"expected empty /proc/net/route, got: {routes}"

# 3. Direct TCP bypass to echo ClusterIP must fail
try:
    socket.create_connection((os.environ["ECHO_IP"], 8443), timeout=2).close()
    raise SystemExit("FAIL: direct TCP to echo ClusterIP succeeded")
except OSError as e:
    print("PASS direct TCP blocked:", e)

# 4. Allowed HTTPS via connect-proxy (mTLS + HTTP/2 CONNECT + injected CA)
url = f"https://echo.{os.environ['NS']}.svc.cluster.local:8443/smoke-ok"
with urllib.request.urlopen(url, timeout=10) as resp:
    data = json.loads(resp.read().decode())
    assert resp.status == 200 and data["ok"] is True and data["path"] == "/smoke-ok", data
    print("PASS connect-proxy allowed HTTPS:", data)

# 5. Denied host via connect-proxy policy must return 403
try:
    urllib.request.urlopen("https://blocked.example/nope", timeout=10)
    raise SystemExit("FAIL: blocked.example unexpectedly succeeded")
except urllib.error.URLError as e:
    assert "403" in str(e), f"expected 403 Forbidden, got: {e}"
    print("PASS connect-proxy denied blocked.example:", e)
PY

echo "=== 9. Verify connect-proxy JSONL audit log recorded mTLS peer + allow & deny ==="
PEP_LOGS="$(k -n "${NS}" logs deploy/connect-proxy)"
echo "${PEP_LOGS}"
python3 - "${PEP_LOGS}" <<'PY'
import json, sys
records = []
for line in sys.argv[1].splitlines():
    line = line.strip()
    if line.startswith("{"):
        records.append(json.loads(line))
allows = [r for r in records if r.get("decision") == "allow" and r.get("peer") == "dra-agents-net-smoke-client" and r.get("wire") == "h2"]
blocks = [r for r in records if r.get("decision") == "block" and r.get("destination") == "blocked.example:443" and r.get("reason") == "not-on-allowlist"]
assert allows, f"missing allow audit record with mTLS peer & h2: {records}"
assert blocks, f"missing block audit record for blocked.example:443: {records}"
print(f"PASS connect-proxy audit: {len(allows)} allow(s) (mTLS peer + h2), {len(blocks)} block(s)")
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
assert ing["endpoint"] and not ing["endpoint"].startswith(":"), ing
assert any(p["port"] == 8080 and p["protocol"] == "TCP" for p in ing["ports"]), ing
print(ing["endpoint"])
PY
)"
echo "Discovered ingress bridge endpoint=${INGRESS_ENDPOINT} target=${POD_UID}"

echo "=== 11. Deploy agents-net-ingress-gateway behind LoadBalancer (cloud-provider-kind) & verify external ingress ==="
GW_SVC_TYPE="ClusterIP"
if [ "${RUN_CPK}" = "true" ]; then
  GW_SVC_TYPE="LoadBalancer"
fi
cat <<EOF | k apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: agents-net-ingress-gateway
  namespace: ${NS}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ${NS}-ingress-gateway
rules:
  - apiGroups: ["resource.k8s.io"]
    resources: ["resourceclaims"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ${NS}-ingress-gateway
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: ${NS}-ingress-gateway
subjects:
  - kind: ServiceAccount
    name: agents-net-ingress-gateway
    namespace: ${NS}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agents-net-ingress-gateway
  namespace: ${NS}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: agents-net-ingress-gateway
  template:
    metadata:
      labels:
        app: agents-net-ingress-gateway
    spec:
      serviceAccountName: agents-net-ingress-gateway
      containers:
        - name: gateway
          image: ${GATEWAY_IMAGE}
          imagePullPolicy: IfNotPresent
          args:
            - --listen-addr=:8080
          ports:
            - containerPort: 8080
          readinessProbe:
            httpGet:
              path: /healthz
              port: 8080
            periodSeconds: 2
---
apiVersion: v1
kind: Service
metadata:
  name: agents-net-ingress-gateway
  namespace: ${NS}
spec:
  type: ${GW_SVC_TYPE}
  selector:
    app: agents-net-ingress-gateway
  ports:
    - name: http
      port: 80
      targetPort: 8080
EOF
k -n "${NS}" rollout status deployment/agents-net-ingress-gateway --timeout=60s

LB_IP=""
if [ "${RUN_CPK}" = "true" ]; then
  for _ in $(seq 1 30); do
    LB_IP="$(k -n "${NS}" get svc agents-net-ingress-gateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}')"
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

  DENY_CODE="$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' "http://${LB_IP}/agents/${NS}/smoke-agent:9999/nope")"
  if [ "${DENY_CODE}" != "403" ]; then
    echo "FAIL: external LoadBalancer unpinned port :9999 returned HTTP ${DENY_CODE}, want 403" >&2
    exit 1
  fi
  echo "PASS host -> cloud-provider-kind LoadBalancer (${LB_IP}) unpinned port :9999 rejected: HTTP 403"
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
EOF
k -n "${NS}" wait --for=condition=Ready pod/ingress-caller --timeout=60s

k -n "${NS}" exec -i ingress-caller -- env INGRESS_ENDPOINT="${INGRESS_ENDPOINT}" POD_UID="${POD_UID}" python3 - <<'PY'
import os, socket

ep = os.environ["INGRESS_ENDPOINT"]
pod_uid = os.environ["POD_UID"]
if ep.startswith("["):
    host, port = ep[1:].rsplit("]:", 1)
else:
    host, port = ep.rsplit(":", 1)
port = int(port)

def connect_tunnel(target_port):
    s = socket.create_connection((host, port), timeout=5)
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

# 1. Pinned port 8080 must succeed and reach smoke-agent's loopback HTTP server
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
print("PASS direct node ingress bridge :8080 delivered HTTP 200:", text.splitlines()[-1])

# 2. Unpinned port 9999 must be rejected with 403 ingress-port-denied at the node bridge too
s, head, _ = connect_tunnel(9999)
s.close()
assert head.startswith("HTTP/1.1 403") and "ingress-port-denied" in head, f"expected 403 ingress-port-denied, got: {head!r}"
print("PASS direct node ingress bridge unpinned port :9999 rejected:", head.splitlines()[0])
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
  REVOKED_CODE="$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' "http://${LB_IP}/agents/${NS}/smoke-agent/after-delete")"
  if [ "${REVOKED_CODE}" != "404" ]; then
    echo "FAIL: external LoadBalancer after delete returned HTTP ${REVOKED_CODE}, want 404" >&2
    exit 1
  fi
  echo "PASS host -> cloud-provider-kind LoadBalancer (${LB_IP}) revoked after delete: HTTP 404"
fi

k -n "${NS}" exec -i ingress-caller -- env INGRESS_ENDPOINT="${INGRESS_ENDPOINT}" POD_UID="${POD_UID}" python3 - <<'PY'
import os, socket
ep = os.environ["INGRESS_ENDPOINT"]
pod_uid = os.environ["POD_UID"]
if ep.startswith("["):
    host, port = ep[1:].rsplit("]:", 1)
else:
    host, port = ep.rsplit(":", 1)
s = socket.create_connection((host, int(port)), timeout=5)
s.sendall(f"CONNECT {pod_uid}:8080 HTTP/1.1\r\nHost: {pod_uid}:8080\r\n\r\n".encode())
resp = s.recv(4096).decode()
s.close()
assert resp.startswith("HTTP/1.1 404") or resp.startswith("HTTP/1.1 403"), f"expected 404/403 after delete, got: {resp!r}"
print("PASS ingress revoked after Pod deletion:", resp.splitlines()[0])
PY

echo "=== ALL SMOKE TESTS PASSED ==="
