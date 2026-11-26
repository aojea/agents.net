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

package tun2connect

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func buildTestDNSQuery(t *testing.T, id uint16, name string, qtype dnsmessage.Type) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
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

func buildTestUpstreamReply(t *testing.T, query []byte, rcode dnsmessage.RCode, addrs []netip.Addr) []byte {
	t.Helper()
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil {
		t.Fatalf("parse query: %v", err)
	}
	q, err := p.Question()
	if err != nil {
		t.Fatalf("parse question: %v", err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 hdr.ID,
		Response:           true,
		RecursionDesired:   hdr.RecursionDesired,
		RecursionAvailable: true,
		RCode:              rcode,
	})
	_ = b.StartQuestions()
	_ = b.Question(q)
	if rcode == dnsmessage.RCodeSuccess && len(addrs) > 0 {
		_ = b.StartAnswers()
		rh := dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: q.Class, TTL: 60}
		for _, a := range addrs {
			if q.Type == dnsmessage.TypeA && a.Is4() {
				_ = b.AResource(rh, dnsmessage.AResource{A: a.As4()})
			}
			if q.Type == dnsmessage.TypeAAAA && a.Is6() {
				_ = b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: a.As16()})
			}
		}
	}
	raw, err := b.Finish()
	if err != nil {
		t.Fatalf("finish upstream reply: %v", err)
	}
	return raw
}

func parseTestDNSReply(t *testing.T, raw []byte) (dnsmessage.RCode, []netip.Addr) {
	t.Helper()
	var p dnsmessage.Parser
	hdr, err := p.Start(raw)
	if err != nil {
		t.Fatalf("parse reply: %v", err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatalf("skip questions: %v", err)
	}
	var addrs []netip.Addr
	for {
		ah, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			t.Fatalf("AnswerHeader: %v", err)
		}
		switch ah.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				t.Fatalf("AResource: %v", err)
			}
			addrs = append(addrs, netip.AddrFrom4(r.A))
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				t.Fatalf("AAAAResource: %v", err)
			}
			addrs = append(addrs, netip.AddrFrom16(r.AAAA))
		default:
			_ = p.SkipAnswer()
		}
	}
	return hdr.RCode, addrs
}

func TestDoHVirtualDNSRewriteAndNXDOMAIN(t *testing.T) {
	vdns := NewVirtualDNS()
	doh := NewDoHVirtualDNS(vdns, func(_ context.Context, query []byte) ([]byte, error) {
		var p dnsmessage.Parser
		_, _ = p.Start(query)
		q, _ := p.Question()
		switch q.Name.String() {
		case "echo.agents.svc.cluster.local.":
			if q.Type == dnsmessage.TypeA {
				return buildTestUpstreamReply(t, query, dnsmessage.RCodeSuccess, []netip.Addr{netip.MustParseAddr("10.96.0.42")}), nil
			}
			// IPv4-only service: AAAA returns NOERROR with zero answers (NODATA).
			return buildTestUpstreamReply(t, query, dnsmessage.RCodeSuccess, nil), nil
		case "dual.example.":
			if q.Type == dnsmessage.TypeAAAA {
				return buildTestUpstreamReply(t, query, dnsmessage.RCodeSuccess, []netip.Addr{netip.MustParseAddr("2001:db8::1")}), nil
			}
			return buildTestUpstreamReply(t, query, dnsmessage.RCodeSuccess, []netip.Addr{netip.MustParseAddr("93.184.216.34")}), nil
		case "blocked.example.":
			return buildTestUpstreamReply(t, query, dnsmessage.RCodeNameError, nil), nil
		case "refused.example.":
			return buildTestUpstreamReply(t, query, dnsmessage.RCodeRefused, nil), nil
		default:
			return nil, errors.New("upstream unavailable")
		}
	})

	ctx := t.Context()

	// 1. Positive A record is rewritten into 198.18.0.0/15 (never leaks real ClusterIP 10.96.0.42).
	reply, err := doh.HandleQueryContext(ctx, buildTestDNSQuery(t, 1, "echo.agents.svc.cluster.local.", dnsmessage.TypeA))
	if err != nil {
		t.Fatalf("HandleQueryContext A: %v", err)
	}
	rcode, addrs := parseTestDNSReply(t, reply)
	if rcode != dnsmessage.RCodeSuccess || len(addrs) != 1 || !v4Pool.Contains(addrs[0]) {
		t.Fatalf("A reply = (rcode=%v, addrs=%v), want NOERROR + 1 IP in 198.18.0.0/15", rcode, addrs)
	}
	if name, ok := vdns.Reverse(addrs[0]); !ok || name != "echo.agents.svc.cluster.local" {
		t.Fatalf("Reverse(%s) = (%q, %v), want echo.agents.svc.cluster.local", addrs[0], name, ok)
	}

	// 2. IPv4-only service AAAA returns NODATA (NOERROR, 0 answers) without inventing a broken synthetic v6 IP.
	reply, err = doh.HandleQueryContext(ctx, buildTestDNSQuery(t, 2, "echo.agents.svc.cluster.local.", dnsmessage.TypeAAAA))
	if err != nil {
		t.Fatalf("HandleQueryContext AAAA NODATA: %v", err)
	}
	rcode, addrs = parseTestDNSReply(t, reply)
	if rcode != dnsmessage.RCodeSuccess || len(addrs) != 0 {
		t.Fatalf("AAAA NODATA reply = (rcode=%v, addrs=%v), want NOERROR with 0 answers", rcode, addrs)
	}

	// 3. Dual-stack AAAA rewrites into 100::/64 (never leaks 2001:db8::1).
	reply, err = doh.HandleQueryContext(ctx, buildTestDNSQuery(t, 3, "dual.example.", dnsmessage.TypeAAAA))
	if err != nil {
		t.Fatalf("HandleQueryContext dual AAAA: %v", err)
	}
	rcode, addrs = parseTestDNSReply(t, reply)
	if rcode != dnsmessage.RCodeSuccess || len(addrs) != 1 || !v6Pool.Contains(addrs[0]) {
		t.Fatalf("dual AAAA reply = (rcode=%v, addrs=%v), want NOERROR + 1 IP in 100::/64", rcode, addrs)
	}

	// 4. Upstream NXDOMAIN is preserved verbatim so search lists and retries advance.
	reply, err = doh.HandleQueryContext(ctx, buildTestDNSQuery(t, 4, "blocked.example.", dnsmessage.TypeA))
	if err != nil {
		t.Fatalf("HandleQueryContext NXDOMAIN: %v", err)
	}
	rcode, addrs = parseTestDNSReply(t, reply)
	if rcode != dnsmessage.RCodeNameError || len(addrs) != 0 {
		t.Fatalf("NXDOMAIN reply = (rcode=%v, addrs=%v), want NXDOMAIN", rcode, addrs)
	}

	// 5. Upstream REFUSED is preserved verbatim.
	reply, err = doh.HandleQueryContext(ctx, buildTestDNSQuery(t, 5, "refused.example.", dnsmessage.TypeA))
	if err != nil {
		t.Fatalf("HandleQueryContext REFUSED: %v", err)
	}
	rcode, addrs = parseTestDNSReply(t, reply)
	if rcode != dnsmessage.RCodeRefused || len(addrs) != 0 {
		t.Fatalf("REFUSED reply = (rcode=%v, addrs=%v), want REFUSED", rcode, addrs)
	}

	// 6. Upstream transport failure fails closed with SERVFAIL.
	reply, err = doh.HandleQueryContext(ctx, buildTestDNSQuery(t, 6, "err.example.", dnsmessage.TypeA))
	if err != nil {
		t.Fatalf("HandleQueryContext SERVFAIL: %v", err)
	}
	rcode, addrs = parseTestDNSReply(t, reply)
	if rcode != dnsmessage.RCodeServerFailure || len(addrs) != 0 {
		t.Fatalf("SERVFAIL reply = (rcode=%v, addrs=%v), want SERVFAIL", rcode, addrs)
	}
}
