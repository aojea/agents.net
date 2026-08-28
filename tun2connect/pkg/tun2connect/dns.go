package tun2connect

import (
	"errors"
	"net/netip"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

// Synthetic pools. v4 is CGNAT space: link-local would be leak-proof at
// the first router (RFC 3927) but SSRF guards in HTTP clients commonly
// block 169.254/16, which would break legitimate egress. v6 is the
// discard-only prefix (RFC 6666): a flow that ever escapes through a
// stray interface is blackholed by the first conforming router instead
// of reaching a routable ULA network.
var (
	v4Pool = netip.MustParsePrefix("100.64.0.0/10")
	v6Pool = netip.MustParsePrefix("100::/64")
)

// ErrPoolExhausted is returned when a pool has no addresses left; the
// DNS codec turns it into SERVFAIL, which fails closed.
var ErrPoolExhausted = errors.New("tun2connect: synthetic address pool exhausted")

// VirtualDNS is the name-preservation contract. It never resolves
// upstream: it invents one stable synthetic address per (name, family)
// and remembers the pairing so the engine can recover the name at dial
// time. A reverse miss means the guest used an address it never asked
// for, which callers must treat as a policy event, not an error.
type VirtualDNS struct {
	mu      sync.Mutex
	next4   netip.Addr
	next6   netip.Addr
	names4  map[string]netip.Addr
	names6  map[string]netip.Addr
	reverse map[netip.Addr]string
}

func NewVirtualDNS() *VirtualDNS {
	return &VirtualDNS{
		next4:   v4Pool.Addr(),
		next6:   v6Pool.Addr(),
		names4:  make(map[string]netip.Addr),
		names6:  make(map[string]netip.Addr),
		reverse: make(map[netip.Addr]string),
	}
}

func canonical(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// Resolve4 returns the synthetic IPv4 address for name, allocating one
// if the name is new. The mapping is stable for the lifetime of the
// VirtualDNS, so guests may cache answers indefinitely.
func (d *VirtualDNS) Resolve4(name string) (netip.Addr, error) {
	return d.resolve(name, false)
}

// Resolve6 is Resolve4 for the IPv6 pool.
func (d *VirtualDNS) Resolve6(name string) (netip.Addr, error) {
	return d.resolve(name, true)
}

func (d *VirtualDNS) resolve(name string, v6 bool) (netip.Addr, error) {
	name = canonical(name)
	if name == "" {
		return netip.Addr{}, errors.New("tun2connect: empty name")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	names, next, pool := d.names4, &d.next4, v4Pool
	if v6 {
		names, next, pool = d.names6, &d.next6, v6Pool
	}
	if addr, ok := names[name]; ok {
		return addr, nil
	}
	*next = next.Next()
	if !pool.Contains(*next) {
		return netip.Addr{}, ErrPoolExhausted
	}
	names[name] = *next
	d.reverse[*next] = name
	return *next, nil
}

// Reverse recovers the name behind a synthetic address. ok=false means
// the address was never handed out by this resolver.
func (d *VirtualDNS) Reverse(addr netip.Addr) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	name, ok := d.reverse[addr.Unmap()]
	return name, ok
}

// HandleQuery answers one guest DNS query from the synthetic pools.
// A/AAAA get an invented address; every other type gets an empty
// authoritative answer, so no record type becomes a side channel.
func (d *VirtualDNS) HandleQuery(query []byte) ([]byte, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil {
		return nil, err
	}
	q, err := p.Question()
	if err != nil {
		return nil, err
	}

	rcode := dnsmessage.RCodeSuccess
	var addr netip.Addr
	answer := false
	if q.Class == dnsmessage.ClassINET {
		switch q.Type {
		case dnsmessage.TypeA:
			addr, err = d.Resolve4(q.Name.String())
			answer = err == nil
		case dnsmessage.TypeAAAA:
			addr, err = d.Resolve6(q.Name.String())
			answer = err == nil
		}
		if err != nil {
			rcode = dnsmessage.RCodeServerFailure
		}
	}

	b := dnsmessage.NewBuilder(make([]byte, 0, 512), dnsmessage.Header{
		ID:                 hdr.ID,
		Response:           true,
		OpCode:             hdr.OpCode,
		Authoritative:      true,
		RecursionDesired:   hdr.RecursionDesired,
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
	if answer {
		if err := b.StartAnswers(); err != nil {
			return nil, err
		}
		rh := dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: q.Class, TTL: 3600}
		if q.Type == dnsmessage.TypeA {
			err = b.AResource(rh, dnsmessage.AResource{A: addr.As4()})
		} else {
			err = b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: addr.As16()})
		}
		if err != nil {
			return nil, err
		}
	}
	return b.Finish()
}
