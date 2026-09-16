package tun2connect

import (
	"container/list"
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
// of reaching a routable ULA network. The top /24 (v4) and /120 (v6) of
// each pool are never handed out: adapters place their own interface and
// resolver addresses there.
var (
	v4Pool     = netip.MustParsePrefix("100.64.0.0/10")
	v6Pool     = netip.MustParsePrefix("100::/64")
	v4Reserved = netip.MustParsePrefix("100.127.255.0/24")
	v6Reserved = netip.MustParsePrefix("100::ffff:ffff:ffff:ff00/120")
)

// maxSyntheticNames bounds the names remembered per address family. The
// guest chooses the names, and in namespace mode this state lives outside
// the sandbox, so its size must not depend on guest behavior. The least
// recently resolved or dialed name is forgotten first.
const maxSyntheticNames = 1 << 16

// ErrPoolExhausted is returned when a pool has no addresses left; the
// DNS codec turns it into SERVFAIL, which fails closed.
var ErrPoolExhausted = errors.New("tun2connect: synthetic address pool exhausted")

// VirtualDNS is the name-preservation contract. It never resolves
// upstream: it invents one synthetic address per (name, family) and
// remembers the pairing so the engine can recover the name at dial time.
//
// Addresses are never reused within one VirtualDNS lifetime. When a name
// is forgotten under the memory bound, its address stays unassigned: a
// guest dialing a cached copy gets a reverse miss, the destination is
// forwarded as a literal in the synthetic range, and the boundary denies
// it. A stale cache therefore fails closed instead of reaching the name
// that would otherwise have inherited the address.
type VirtualDNS struct {
	mu      sync.Mutex
	v4, v6  family
	reverse map[netip.Addr]*list.Element
}

type family struct {
	pool, reserved netip.Prefix
	last           netip.Addr
	names          map[string]*list.Element
	order          list.List // front is most recently used
}

type binding struct {
	name string
	addr netip.Addr
}

func NewVirtualDNS() *VirtualDNS {
	return &VirtualDNS{
		v4:      family{pool: v4Pool, reserved: v4Reserved, last: v4Pool.Addr(), names: make(map[string]*list.Element)},
		v6:      family{pool: v6Pool, reserved: v6Reserved, last: v6Pool.Addr(), names: make(map[string]*list.Element)},
		reverse: make(map[netip.Addr]*list.Element),
	}
}

func canonical(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// Resolve4 returns the synthetic IPv4 address for name, allocating one
// if the name is new. The mapping holds while the name stays among the
// most recently used maxSyntheticNames names of its family.
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
	f := &d.v4
	if v6 {
		f = &d.v6
	}
	if element, ok := f.names[name]; ok {
		f.order.MoveToFront(element)
		return element.Value.(*binding).addr, nil
	}
	addr := f.last.Next()
	if !f.pool.Contains(addr) || f.reserved.Contains(addr) {
		return netip.Addr{}, ErrPoolExhausted
	}
	if f.order.Len() >= maxSyntheticNames {
		oldest := f.order.Back()
		evicted := oldest.Value.(*binding)
		delete(f.names, evicted.name)
		delete(d.reverse, evicted.addr)
		f.order.Remove(oldest)
	}
	f.last = addr
	element := f.order.PushFront(&binding{name: name, addr: addr})
	f.names[name] = element
	d.reverse[addr] = element
	return addr, nil
}

// Reverse recovers the name behind a synthetic address and marks it as
// recently used. ok=false means the address was never handed out by this
// resolver or its name has since been forgotten.
func (d *VirtualDNS) Reverse(addr netip.Addr) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	element, ok := d.reverse[addr.Unmap()]
	if !ok {
		return "", false
	}
	b := element.Value.(*binding)
	f := &d.v4
	if b.addr.Is6() {
		f = &d.v6
	}
	f.order.MoveToFront(element)
	return b.name, true
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
