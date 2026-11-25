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

package proxyenv

import (
	"strings"
	"testing"
)

func TestExplicitProxyEnvAndNonClobberingMerge(t *testing.T) {
	vars, javaOpts := ExplicitProxyEnv("/run/agents.net/egress.sock", 15001, []string{".internal.corp"})

	wantURL := "http://127.0.0.1:15001"
	for _, key := range []string{
		"AGENTS_NET_PROXY_URL",
		"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
		"http_proxy", "https_proxy", "all_proxy",
		"npm_config_proxy", "npm_config_https_proxy", "GRPC_PROXY_EXP",
	} {
		if vars[key] != wantURL {
			t.Fatalf("%s = %q, want %q", key, vars[key], wantURL)
		}
	}
	if vars["NODE_USE_ENV_PROXY"] != "1" {
		t.Fatalf("NODE_USE_ENV_PROXY = %q, want 1", vars["NODE_USE_ENV_PROXY"])
	}
	if vars["NO_PROXY"] != "localhost,127.0.0.1,::1,.internal.corp" || vars["no_proxy"] != vars["NO_PROXY"] {
		t.Fatalf("NO_PROXY = %q / no_proxy = %q", vars["NO_PROXY"], vars["no_proxy"])
	}
	if !strings.Contains(javaOpts, "-Dhttp.nonProxyHosts=localhost|127.0.0.1|[::1]|*.internal.corp") {
		t.Fatalf("unexpected javaOpts = %q", javaOpts)
	}

	// Merge preserves existing user overrides (NO_PROXY) and appends to JAVA_TOOL_OPTIONS.
	existing := []string{
		"NO_PROXY=custom.local",
		"JAVA_TOOL_OPTIONS=-Xmx512m",
	}
	merged := MergeNonClobbering(existing, vars, javaOpts)
	got := make(map[string]string, len(merged))
	for _, e := range merged {
		got[e.Key] = e.Value
	}
	if _, overwritten := got["NO_PROXY"]; overwritten {
		t.Fatalf("expected user-defined NO_PROXY not to be overwritten")
	}
	if _, overwrittenLower := got["no_proxy"]; overwrittenLower {
		t.Fatalf("expected no_proxy skipped when user already set NO_PROXY")
	}
	if !strings.HasPrefix(got["JAVA_TOOL_OPTIONS"], "-Xmx512m -Dhttp.proxyHost=127.0.0.1") {
		t.Fatalf("expected JAVA_TOOL_OPTIONS appended, got %q", got["JAVA_TOOL_OPTIONS"])
	}

	// Lowercase http_proxy also suppresses uppercase HTTP_PROXY injection.
	mergedLower := MergeNonClobbering([]string{"http_proxy=http://custom:3128"}, vars, "")
	for _, e := range mergedLower {
		if e.Key == "HTTP_PROXY" || e.Key == "http_proxy" {
			t.Fatalf("unexpected injection of %q when http_proxy already set", e.Key)
		}
	}
}
