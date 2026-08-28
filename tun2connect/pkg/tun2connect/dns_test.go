package tun2connect

import (
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

func buildQuery(t *testing.T, name string, qtype dnsmessage.Type) []byte {
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
