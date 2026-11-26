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
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// DoHQueryFunc forwards a raw RFC 1035 DNS wire query to an upstream RFC 8484
// DNS-over-HTTPS Policy Enforcement Point and returns the raw DNS wire reply.
type DoHQueryFunc func(ctx context.Context, query []byte) ([]byte, error)

// DoHVirtualDNS implements DNSHandler by delegating policy checks and name
// existence resolution to an upstream DoH endpoint while rewriting positive
// A/AAAA answers into synthetic addresses from the underlying VirtualDNS pool.
//
// Because upstream NXDOMAIN and REFUSED responses are preserved verbatim,
// standard stub-resolver search lists (ndots:5) and DNS-level retry/fallback
// work natively without ever exposing real cluster or upstream IP addresses to
// the sandbox.
type DoHVirtualDNS struct {
	virtual *VirtualDNS
	query   DoHQueryFunc
}

// NewDoHVirtualDNS wraps virtual with an upstream DoH resolver hook.
func NewDoHVirtualDNS(virtual *VirtualDNS, query DoHQueryFunc) *DoHVirtualDNS {
	return &DoHVirtualDNS{
		virtual: virtual,
		query:   query,
	}
}

// HandleQueryContext forwards query to the upstream DoH PEP, preserves
// non-NOERROR response codes (such as NXDOMAIN or REFUSED), and rewrites
// positive A/AAAA answers into synthetic addresses in VirtualDNS.
func (d *DoHVirtualDNS) HandleQueryContext(ctx context.Context, query []byte) ([]byte, error) {
	var qp dnsmessage.Parser
	qhdr, err := qp.Start(query)
	if err != nil {
		return nil, err
	}
	q, err := qp.Question()
	if err != nil {
		return nil, err
	}
	if d.virtual == nil || d.query == nil {
		return buildDNSResponse(qhdr, q, dnsmessage.RCodeServerFailure, netip.Addr{}, false, DefaultTTL)
	}

	rawResp, err := d.query(ctx, query)
	if err != nil {
		return buildDNSResponse(qhdr, q, dnsmessage.RCodeServerFailure, netip.Addr{}, false, d.virtual.TTL)
	}

	rcode, hasMatch, err := inspectDoHAnswer(rawResp, q.Type)
	if err != nil {
		return buildDNSResponse(qhdr, q, dnsmessage.RCodeServerFailure, netip.Addr{}, false, d.virtual.TTL)
	}
	if rcode != dnsmessage.RCodeSuccess {
		return buildDNSResponse(qhdr, q, rcode, netip.Addr{}, false, d.virtual.TTL)
	}

	// Only allocate a synthetic IP when upstream confirmed at least one record
	// matching the requested address family (preventing broken Happy Eyeballs
	// synthetic AAAA answers for IPv4-only services) and never echo non-A/AAAA
	// payloads back into the sandbox.
	if q.Class == dnsmessage.ClassINET && hasMatch {
		var (
			addr   netip.Addr
			resErr error
		)
		switch q.Type {
		case dnsmessage.TypeA:
			addr, resErr = d.virtual.Resolve4(q.Name.String())
		case dnsmessage.TypeAAAA:
			addr, resErr = d.virtual.Resolve6(q.Name.String())
		default:
			return buildDNSResponse(qhdr, q, dnsmessage.RCodeSuccess, netip.Addr{}, false, d.virtual.TTL)
		}
		if resErr != nil {
			return buildDNSResponse(qhdr, q, dnsmessage.RCodeServerFailure, netip.Addr{}, false, d.virtual.TTL)
		}
		return buildDNSResponse(qhdr, q, dnsmessage.RCodeSuccess, addr, true, d.virtual.TTL)
	}

	return buildDNSResponse(qhdr, q, dnsmessage.RCodeSuccess, netip.Addr{}, false, d.virtual.TTL)
}

func inspectDoHAnswer(raw []byte, wantType dnsmessage.Type) (dnsmessage.RCode, bool, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(raw)
	if err != nil {
		return dnsmessage.RCodeServerFailure, false, err
	}
	if !hdr.Response {
		return dnsmessage.RCodeServerFailure, false, errors.New("upstream DoH payload is not a DNS response")
	}
	if hdr.RCode != dnsmessage.RCodeSuccess {
		return hdr.RCode, false, nil
	}
	if err := p.SkipAllQuestions(); err != nil {
		return dnsmessage.RCodeServerFailure, false, err
	}
	hasMatch := false
	for {
		ah, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return dnsmessage.RCodeServerFailure, false, err
		}
		if ah.Class == dnsmessage.ClassINET && ah.Type == wantType && (wantType == dnsmessage.TypeA || wantType == dnsmessage.TypeAAAA) {
			hasMatch = true
		}
		if err := p.SkipAnswer(); err != nil {
			return dnsmessage.RCodeServerFailure, false, err
		}
	}
	return dnsmessage.RCodeSuccess, hasMatch, nil
}

func buildDNSResponse(
	qhdr dnsmessage.Header,
	q dnsmessage.Question,
	rcode dnsmessage.RCode,
	addr netip.Addr,
	includeAnswer bool,
	ttl time.Duration,
) ([]byte, error) {
	b := dnsmessage.NewBuilder(make([]byte, 0, 512), dnsmessage.Header{
		ID:                 qhdr.ID,
		Response:           true,
		OpCode:             qhdr.OpCode,
		Authoritative:      true,
		RecursionDesired:   qhdr.RecursionDesired,
		RecursionAvailable: true,
		RCode:              rcode,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if includeAnswer {
		if err := b.StartAnswers(); err != nil {
			return nil, err
		}
		rh := dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: q.Class, TTL: ttlSeconds(ttl)}
		if q.Type == dnsmessage.TypeA {
			if err := b.AResource(rh, dnsmessage.AResource{A: addr.As4()}); err != nil {
				return nil, err
			}
		} else {
			if err := b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: addr.As16()}); err != nil {
				return nil, err
			}
		}
	}
	return b.Finish()
}
