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
# End-to-end interoperability suite validating unmodified Envoy Proxy as BOTH
# Tier 2 Outbound PEP (mTLS HTTP/2 CONNECT + connect-udp + RFC 8484 DoH) and
# Tier 2 Inbound Gateway (mTLS HTTP CONNECT tunneling into pkg/ingress.Server).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${REPO_ROOT}"
echo "=== Running Envoy PEP + Inbound E2E interop suite (ENVOY_IMAGE=${ENVOY_IMAGE:-envoyproxy/envoy:v1.36.2}) ==="
go test -tags=envoy_e2e -v -count=1 -timeout=180s ./test/envoy
