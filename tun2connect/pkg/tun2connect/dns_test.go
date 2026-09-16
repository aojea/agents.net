package tun2connect

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestResolveStableAndReverse(t *testing.T) {
	d := NewVirtualDNS()
	a1, err := d.Resolve4("API.Example.")
	if err != nil {
		t.Fatal(err)
	}
	a2, err := d.Resolve4("api.example")
	if err != nil {
		t.Fatal(err)
	}
	if a1 != a2 {
		t.Fatalf("resolution not stable: %v != %v", a1, a2)
	}
	if !v4Pool.Contains(a1) {
		t.Fatalf("%v outside synthetic pool %v", a1, v4Pool)
	}
	name, ok := d.Reverse(a1)
	if !ok || name != "api.example" {
		t.Fatalf("Reverse(%v) = %q, %v", a1, name, ok)
	}

	a6, err := d.Resolve6("api.example")
	if err != nil {
		t.Fatal(err)
	}
	if !v6Pool.Contains(a6) {
		t.Fatalf("%v outside synthetic pool %v", a6, v6Pool)
	}
	if name, ok := d.Reverse(a6); !ok || name != "api.example" {
		t.Fatalf("Reverse(%v) = %q, %v", a6, name, ok)
	}
}

func TestReverseMissForUnknownAddress(t *testing.T) {
	d := NewVirtualDNS()
	if name, ok := d.Reverse(netip.MustParseAddr("100.64.9.9")); ok {
		t.Fatalf("unexpected mapping %q for an address never handed out", name)
	}
}

// TestNameLimitEvictsWithoutReusingAddresses fills a family past its bound
// and checks that the least recently used name is forgotten, that a name
// kept alive by dialing survives, and that no address is ever handed out
// twice, so a stale guest cache misses rather than reaching another name.
func TestNameLimitEvictsWithoutReusingAddresses(t *testing.T) {
	d := NewVirtualDNS()
	handed := make(map[netip.Addr]string, maxSyntheticNames+2)
	var first, second netip.Addr
	for i := range maxSyntheticNames {
		addr, err := d.Resolve6(fmt.Sprintf("n%d.example", i))
		if err != nil {
			t.Fatalf("name %d: %v", i, err)
		}
		if previous, dup := handed[addr]; dup {
			t.Fatalf("%v handed to %q and %q", addr, previous, fmt.Sprintf("n%d.example", i))
		}
		handed[addr] = fmt.Sprintf("n%d.example", i)
		switch i {
		case 0:
			first = addr
		case 1:
			second = addr
		}
	}
	// Dialing n1 makes it recent; n0 is now the least recently used.
	if name, ok := d.Reverse(second); !ok || name != "n1.example" {
		t.Fatalf("Reverse(%v) = %q, %v", second, name, ok)
	}
	overflow, err := d.Resolve6("overflow.example")
	if err != nil {
		t.Fatalf("resolution past the bound must evict, not fail: %v", err)
	}
	if _, dup := handed[overflow]; dup {
		t.Fatalf("address %v reused after eviction", overflow)
	}
	if name, ok := d.Reverse(first); ok {
		t.Fatalf("evicted n0 still reverses to %q", name)
	}
	if name, ok := d.Reverse(second); !ok || name != "n1.example" {
		t.Fatalf("recently dialed n1 was evicted: %q, %v", name, ok)
	}
	if again, err := d.Resolve6("n0.example"); err != nil || again == first {
		t.Fatalf("re-resolved n0 = %v, %v; want a fresh address, not %v", again, err, first)
	}
	if d.v6.order.Len() != maxSyntheticNames || len(d.v6.names) != maxSyntheticNames {
		t.Fatalf("family holds %d/%d names, want %d", d.v6.order.Len(), len(d.v6.names), maxSyntheticNames)
	}
	if len(d.reverse) != maxSyntheticNames {
		t.Fatalf("reverse map holds %d entries, want %d", len(d.reverse), maxSyntheticNames)
	}
	if _, err := d.Resolve4("other-family.example"); err != nil {
		t.Fatalf("limit is per family: %v", err)
	}
}

func TestReservedTopOfPoolIsNeverAllocated(t *testing.T) {
	d := NewVirtualDNS()
	d.v4.last = v4Reserved.Addr().Prev().Prev()
	addr, err := d.Resolve4("last.example")
	if err != nil || v4Reserved.Contains(addr) {
		t.Fatalf("last free address: %v, %v", addr, err)
	}
	if _, err := d.Resolve4("reserved.example"); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("allocation entered the reserved range: %v", err)
	}
	resp, err := d.HandleQuery(buildQuery(t, "reserved.example.", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(resp)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("want SERVFAIL when exhausted, got %v", hdr.RCode)
	}
}

func buildQuery(t testing.TB, name string, qtype dnsmessage.Type) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 42, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{
		Name: dnsmessage.MustNewName(name), Type: qtype, Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatal(err)
	}
	q, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func TestHandleQueryA(t *testing.T) {
	d := NewVirtualDNS()
	resp, err := d.HandleQuery(buildQuery(t, "model.example.", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(resp)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.ID != 42 || !hdr.Response || hdr.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("bad response header: %+v", hdr)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	answers, err := p.AllAnswers()
	if err != nil {
		t.Fatal(err)
	}
	if len(answers) != 1 {
		t.Fatalf("want 1 answer, got %d", len(answers))
	}
	a := answers[0].Body.(*dnsmessage.AResource)
	got := netip.AddrFrom4(a.A)
	if name, ok := d.Reverse(got); !ok || name != "model.example" {
		t.Fatalf("answer %v does not reverse to the queried name (got %q, %v)", got, name, ok)
	}
}

func TestHandleQueryOtherTypesGetNoAnswer(t *testing.T) {
	d := NewVirtualDNS()
	resp, err := d.HandleQuery(buildQuery(t, "exfil.example.", dnsmessage.TypeTXT))
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(resp)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("want NOERROR, got %v", hdr.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	answers, err := p.AllAnswers()
	if err != nil {
		t.Fatal(err)
	}
	if len(answers) != 0 {
		t.Fatalf("TXT must not be answered, got %d answers", len(answers))
	}
}

// FuzzHandleQuery feeds arbitrary bytes to the guest-facing DNS handler.
// It must never panic; a response must echo the query ID, be a response
// to the same question, and answer A/AAAA only from the synthetic pools.
func FuzzHandleQuery(f *testing.F) {
	f.Add(buildQuery(f, "model.example.", dnsmessage.TypeA))
	f.Add(buildQuery(f, "model.example.", dnsmessage.TypeAAAA))
	f.Add(buildQuery(f, "exfil.example.", dnsmessage.TypeTXT))
	f.Add(buildQuery(f, ".", dnsmessage.TypeA))
	f.Add([]byte{})
	f.Add(make([]byte, 12))
	f.Fuzz(func(t *testing.T, query []byte) {
		d := NewVirtualDNS()
		response, err := d.HandleQuery(query)
		if err != nil {
			return
		}
		var q, r dnsmessage.Parser
		qh, err := q.Start(query)
		if err != nil {
			t.Fatalf("response %x to an unparsable query", response)
		}
		question, err := q.Question()
		if err != nil {
			t.Fatalf("response %x to a query without a question", response)
		}
		rh, err := r.Start(response)
		if err != nil || !rh.Response || rh.ID != qh.ID {
			t.Fatalf("bad response header %+v (%v) for query %+v", rh, err, qh)
		}
		echoed, err := r.Question()
		if err != nil || echoed.Name.String() != question.Name.String() || echoed.Type != question.Type {
			t.Fatalf("question not echoed: %+v vs %+v (%v)", echoed, question, err)
		}
		if err := r.SkipAllQuestions(); err != nil {
			t.Fatal(err)
		}
		answers, err := r.AllAnswers()
		if err != nil {
			t.Fatal(err)
		}
		for _, answer := range answers {
			switch body := answer.Body.(type) {
			case *dnsmessage.AResource:
				if addr := netip.AddrFrom4(body.A); !v4Pool.Contains(addr) || v4Reserved.Contains(addr) {
					t.Fatalf("A answer %v outside the synthetic pool", addr)
				}
			case *dnsmessage.AAAAResource:
				if addr := netip.AddrFrom16(body.AAAA); !v6Pool.Contains(addr) || v6Reserved.Contains(addr) {
					t.Fatalf("AAAA answer %v outside the synthetic pool", addr)
				}
			default:
				t.Fatalf("unexpected answer type %T", body)
			}
		}
	})
}
