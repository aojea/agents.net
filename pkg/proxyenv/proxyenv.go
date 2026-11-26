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

// Package proxyenv computes the full matrix of agents.net and language-specific
// proxy environment variables for ExplicitProxy mode and merges them cleanly
// into container environments without clobbering user-supplied values.
package proxyenv

import (
	"fmt"
	"slices"
	"strings"
)

const defaultLoopbackHost = "127.0.0.1"

// EnvEntry is a deterministic key/value environment variable pair for NRI ContainerAdjustment.
type EnvEntry struct {
	Key   string
	Value string
}

// ExplicitProxyEnv returns the language-agnostic and runtime-specific proxy
// environment variables pointing at the Pod-loopback HTTP proxy listener
// (http://127.0.0.1:<port>) plus the agents.net UDS path, along with the
// JAVA_TOOL_OPTIONS JVM proxy flags to append safely.
func ExplicitProxyEnv(egressSocketPath string, port int32, extraNoProxy []string) (vars map[string]string, javaOpts string) {
	proxyURL := fmt.Sprintf("http://%s:%d", defaultLoopbackHost, port)
	noProxyList := buildNoProxyList(extraNoProxy)
	noProxyCSV := strings.Join(noProxyList, ",")

	vars = map[string]string{
		// agents.net native discovery
		"AGENTS_NET_EGRESS_SOCKET": egressSocketPath,
		"AGENTS_NET_PROXY_URL":     proxyURL,
		// Standard uppercase (Go, Python, Rust, npm, CLI tools)
		"HTTP_PROXY":  proxyURL,
		"HTTPS_PROXY": proxyURL,
		"ALL_PROXY":   proxyURL,
		"NO_PROXY":    noProxyCSV,
		// Standard lowercase (curl, wget, apt, git, legacy Unix libraries)
		"http_proxy":  proxyURL,
		"https_proxy": proxyURL,
		"all_proxy":   proxyURL,
		"no_proxy":    noProxyCSV,
		// Node.js 22+ native fetch/undici and npm/yarn
		"NODE_USE_ENV_PROXY":     "1",
		"npm_config_proxy":       proxyURL,
		"npm_config_https_proxy": proxyURL,
		// gRPC HTTP CONNECT proxy support
		"GRPC_PROXY_EXP": proxyURL,
	}

	javaNonProxy := strings.Join(toJavaNonProxyHosts(noProxyList), "|")
	javaOpts = fmt.Sprintf(
		"-Dhttp.proxyHost=%s -Dhttp.proxyPort=%d -Dhttps.proxyHost=%s -Dhttps.proxyPort=%d -Dhttp.nonProxyHosts=%s",
		defaultLoopbackHost, port, defaultLoopbackHost, port, javaNonProxy,
	)
	return vars, javaOpts
}

// MergeNonClobbering merges desired environment variables into existingEnv (each
// formatted as "KEY=VALUE" as returned by NRI Container.GetEnv()), skipping any key
// already set by the container author (including case variants of standard proxy
// variables like http_proxy/HTTP_PROXY) and appending javaToolOpts to
// JAVA_TOOL_OPTIONS if present. Output is sorted deterministically by key.
func MergeNonClobbering(existingEnv []string, desired map[string]string, javaToolOpts string) []EnvEntry {
	existing := make(map[string]string, len(existingEnv))
	existingLower := make(map[string]struct{}, len(existingEnv))
	for _, kv := range existingEnv {
		if k, v, ok := strings.Cut(kv, "="); ok {
			existing[k] = v
			existingLower[strings.ToLower(k)] = struct{}{}
		}
	}

	out := make([]EnvEntry, 0, len(desired)+1)
	for k, v := range desired {
		if _, alreadySet := existing[k]; alreadySet {
			continue
		}
		if isCaseInsensitiveProxyVar(k) {
			if _, caseConflict := existingLower[strings.ToLower(k)]; caseConflict {
				continue
			}
		}
		out = append(out, EnvEntry{Key: k, Value: v})
	}

	if javaToolOpts != "" {
		if prev, ok := existing["JAVA_TOOL_OPTIONS"]; ok && strings.TrimSpace(prev) != "" {
			if !strings.Contains(prev, "-Dhttp.proxyHost=") {
				out = append(out, EnvEntry{
					Key:   "JAVA_TOOL_OPTIONS",
					Value: strings.TrimSpace(prev) + " " + javaToolOpts,
				})
			}
		} else {
			out = append(out, EnvEntry{
				Key:   "JAVA_TOOL_OPTIONS",
				Value: javaToolOpts,
			})
		}
	}

	slices.SortFunc(out, func(a, b EnvEntry) int {
		return strings.Compare(a.Key, b.Key)
	})
	return out
}

func isCaseInsensitiveProxyVar(key string) bool {
	switch strings.ToLower(key) {
	case "http_proxy", "https_proxy", "all_proxy", "no_proxy":
		return true
	default:
		return false
	}
}

func buildNoProxyList(extra []string) []string {
	base := []string{"localhost", "127.0.0.1", "::1"}
	seen := map[string]struct{}{
		"localhost": {},
		"127.0.0.1": {},
		"::1":       {},
	}
	for _, entry := range extra {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" || strings.ContainsAny(trimmed, " \t\r\n\"'|") {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		base = append(base, trimmed)
	}
	return base
}

// toJavaNonProxyHosts converts NO_PROXY entries into Java's pipe-separated wildcard syntax
// (for example ".svc.cluster.local" becomes "*.svc.cluster.local").
func toJavaNonProxyHosts(entries []string) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e == "::1" {
			out = append(out, "[::1]")
			continue
		}
		if strings.HasPrefix(e, ".") {
			out = append(out, "*"+e)
			continue
		}
		out = append(out, e)
	}
	return out
}
