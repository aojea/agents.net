// Copyright 2026 The Kubernetes Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package apis

import "testing"

func TestIngressPortContains(t *testing.T) {
	tests := []struct {
		name  string
		spec  IngressPort
		port  int32
		proto IngressProtocol
		want  bool
	}{
		{
			name:  "single port default protocol matches TCP",
			spec:  IngressPort{Port: 8080},
			port:  8080,
			proto: IngressProtocolTCP,
			want:  true,
		},
		{
			name:  "single port rejects adjacent port",
			spec:  IngressPort{Port: 8080},
			port:  8081,
			proto: IngressProtocolTCP,
			want:  false,
		},
		{
			name:  "inclusive range matches bounds and interior",
			spec:  IngressPort{Port: 9000, EndPort: 9005, Protocol: IngressProtocolTCP},
			port:  9003,
			proto: IngressProtocolTCP,
			want:  true,
		},
		{
			name:  "inclusive range matches upper bound",
			spec:  IngressPort{Port: 9000, EndPort: 9005},
			port:  9005,
			proto: "",
			want:  true,
		},
		{
			name:  "inclusive range rejects out-of-bounds",
			spec:  IngressPort{Port: 9000, EndPort: 9005},
			port:  9006,
			proto: IngressProtocolTCP,
			want:  false,
		},
		{
			name:  "protocol mismatch rejected",
			spec:  IngressPort{Port: 5353, Protocol: IngressProtocol("UDP")},
			port:  5353,
			proto: IngressProtocolTCP,
			want:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.spec.Contains(tc.port, tc.proto); got != tc.want {
				t.Fatalf("%+v.Contains(%d, %q) = %v, want %v", tc.spec, tc.port, tc.proto, got, tc.want)
			}
		})
	}
}

func TestFormatProxyStatus(t *testing.T) {
	tests := []struct {
		member string
		status int
		reason string
		want   string
	}{
		{
			member: "dra-agents-net-ingress",
			status: 403,
			reason: "port-not-permitted",
			want:   "dra-agents-net-ingress; error=http_request_denied; reason=port-not-permitted",
		},
		{
			member: "dra-agents-net-ingress",
			status: 404,
			reason: "sandbox-revoked",
			want:   "dra-agents-net-ingress; error=destination_not_found; reason=sandbox-revoked",
		},
		{
			member: "dra-agents-net",
			status: 503,
			reason: "busy",
			want:   "dra-agents-net; error=connection_limit_reached; reason=busy",
		},
		{
			member: "dra-agents-net",
			status: 503,
			reason: "upstream-unconfigured",
			want:   "dra-agents-net; error=proxy_configuration_error; reason=upstream-unconfigured",
		},
		{
			member: "dra-agents-net",
			status: 505,
			reason: "unsupported-version",
			want:   "dra-agents-net; error=http_protocol_error; reason=unsupported-version",
		},
		{
			member: "dra-agents-net",
			status: 400,
			reason: "bad\r\n;inject",
			want:   "dra-agents-net; error=http_request_error; reason=badinject",
		},
	}

	for _, tc := range tests {
		if got := FormatProxyStatus(tc.member, tc.status, tc.reason); got != tc.want {
			t.Fatalf("FormatProxyStatus(%q, %d, %q) = %q, want %q", tc.member, tc.status, tc.reason, got, tc.want)
		}
	}
}
