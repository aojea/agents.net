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

package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func buildDoHTestQuery(t *testing.T, name string, qtype dnsmessage.Type) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 42, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatalf("StartQuestions: %v", err)
	}
	if err := b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(name),
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatalf("Question: %v", err)
	}
	raw, err := b.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return raw
}

func TestConnectProxyDoHPolicyAndNXDOMAIN(t *testing.T) {
	rawPolicy := []byte(`{
		"agents_net_policy": 1,
		"version": "doh-test",
		"sandbox": "test-sb",
		"default": "deny",
		"features": {"h2": true, "doh": true},
		"rules": [
			{"id": "allow-echo", "name": "echo.agents.svc.cluster.local", "ports": [8443]},
			{"id": "allow-wildcard-svc", "suffix": "agents.svc.cluster.local", "ports": [8443]}
		],
		"resolved_addresses": [
			{"cidr": "10.96.0.0/16", "ports": [8443]}
		]
	}`)
	p, err := loadDescriptor(rawPolicy, "gen-doh")
	if err != nil {
		t.Fatalf("loadDescriptor: %v", err)
	}
	prevPolicy := current.Swap(p)
	defer current.Store(prevPolicy)

	var upstreamLookups atomic.Int32
	prevLookup := lookupNetIP
	lookupNetIP = func(_ context.Context, _, host string) ([]netip.Addr, error) {
		upstreamLookups.Add(1)
		if host == "echo.agents.svc.cluster.local" {
			return []netip.Addr{netip.MustParseAddr("10.96.1.10")}, nil
		}
		return nil, &net.DNSError{Name: host, IsNotFound: true}
	}
	defer func() { lookupNetIP = prevLookup }()

	handler := serveH2(session{peer: "test-peer", id: "1"})
	queryDoH := func(t *testing.T, name string, qtype dnsmessage.Type) (int, dnsmessage.RCode, []netip.Addr) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(buildDoHTestQuery(t, name, qtype)))
		req.Header.Set("Content-Type", dohMediaType)
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != http.StatusOK {
			return rec.Code, 0, nil
		}
		var parser dnsmessage.Parser
		hdr, err := parser.Start(rec.Body.Bytes())
		if err != nil {
			t.Fatalf("parse DoH DNS reply: %v", err)
		}
		_ = parser.SkipAllQuestions()
		var addrs []netip.Addr
		for {
			ah, err := parser.AnswerHeader()
			if err == dnsmessage.ErrSectionDone {
				break
			}
			if err != nil {
				t.Fatalf("AnswerHeader: %v", err)
			}
			if ah.Type == dnsmessage.TypeA {
				ar, _ := parser.AResource()
				addrs = append(addrs, netip.AddrFrom4(ar.A))
			} else {
				_ = parser.SkipAnswer()
			}
		}
		return rec.Code, hdr.RCode, addrs
	}

	// 1. Disallowed name returns NXDOMAIN without ever invoking upstream DNS (blocks DNS exfiltration).
	code, rcode, addrs := queryDoH(t, "secret.attacker.example.", dnsmessage.TypeA)
	if code != http.StatusOK || rcode != dnsmessage.RCodeNameError || len(addrs) != 0 {
		t.Fatalf("disallowed query = (%d, %v, %v), want (200, NXDOMAIN, [])", code, rcode, addrs)
	}
	if upstreamLookups.Load() != 0 {
		t.Fatalf("disallowed query triggered %d upstream DNS lookups, want 0", upstreamLookups.Load())
	}

	// 2. Allowed name that resolves returns NOERROR + address.
	code, rcode, addrs = queryDoH(t, "echo.agents.svc.cluster.local.", dnsmessage.TypeA)
	if code != http.StatusOK || rcode != dnsmessage.RCodeSuccess || len(addrs) != 1 || addrs[0].String() != "10.96.1.10" {
		t.Fatalf("allowed query = (%d, %v, %v), want (200, NOERROR, [10.96.1.10])", code, rcode, addrs)
	}

	// 3. Allowed suffix name that does not exist in upstream DNS returns real NXDOMAIN.
	code, rcode, addrs = queryDoH(t, "missing.agents.svc.cluster.local.", dnsmessage.TypeA)
	if code != http.StatusOK || rcode != dnsmessage.RCodeNameError || len(addrs) != 0 {
		t.Fatalf("nonexistent allowed-suffix query = (%d, %v, %v), want (200, NXDOMAIN, [])", code, rcode, addrs)
	}

	// 4. Policy with features.doh=false rejects POST /dns-query with 405.
	pOff, err := loadDescriptor([]byte(`{"agents_net_policy":1,"version":"v1","sandbox":"sb","default":"deny","features":{"h2":true}}`), "g")
	if err != nil {
		t.Fatalf("loadDescriptor doh=false: %v", err)
	}
	current.Store(pOff)
	code, _, _ = queryDoH(t, "echo.agents.svc.cluster.local.", dnsmessage.TypeA)
	if code != http.StatusMethodNotAllowed {
		t.Fatalf("doh=false status = %d, want 405", code)
	}
}
