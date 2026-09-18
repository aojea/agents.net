package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	"golang.org/x/net/idna"
)

// descriptor is the JSON policy descriptor (spec/draft/policy.md).
type descriptor struct {
	Schema            int              `json:"agents_net_policy"`
	Version           string           `json:"version"`
	Sandbox           string           `json:"sandbox"`
	Default           string           `json:"default"`
	Rules             []descriptorRule `json:"rules"`
	ResolvedAddresses []descriptorRule `json:"resolved_addresses"`
	Features          struct {
		UDP bool `json:"udp"`
		H2  bool `json:"h2"`
	} `json:"features"`
}

type descriptorRule struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Suffix     string   `json:"suffix"`
	Depth      int      `json:"depth"`
	IP         string   `json:"ip"`
	CIDR       string   `json:"cidr"`
	Ports      []any    `json:"ports"`
	Transports []string `json:"transports"`
	Resolve    []string `json:"resolve"`
}

// portSet is the set of ports a rule permits; any covers every port.
type portSet struct {
	any    bool
	ranges [][2]uint16
}

func (p *portSet) permits(port uint16) bool {
	if p.any {
		return true
	}
	for _, r := range p.ranges {
		if r[0] <= port && port <= r[1] {
			return true
		}
	}
	return false
}

// parsePorts reads a descriptor "ports" list: integers, "n", or "a-b".
// An absent list permits every port.
func parsePorts(values []any) (portSet, error) {
	if values == nil {
		return portSet{any: true}, nil
	}
	if len(values) == 0 {
		return portSet{}, errors.New("empty ports list")
	}
	var set portSet
	for _, value := range values {
		var text string
		switch v := value.(type) {
		case float64:
			if v != float64(int64(v)) {
				return portSet{}, fmt.Errorf("port %v is not an integer", v)
			}
			text = strconv.FormatInt(int64(v), 10)
		case string:
			text = v
		default:
			return portSet{}, fmt.Errorf("port %v has type %T", value, value)
		}
		lo, hi, isRange := strings.Cut(text, "-")
		first, err := parsePort(lo)
		if err != nil {
			return portSet{}, err
		}
		last := first
		if isRange {
			if last, err = parsePort(hi); err != nil {
				return portSet{}, err
			}
			if last < first {
				return portSet{}, fmt.Errorf("port range %q is reversed", text)
			}
		}
		set.ranges = append(set.ranges, [2]uint16{first, last})
	}
	return set, nil
}

type transportSet struct{ tcp, udp bool }

func (t transportSet) has(network string) bool {
	return network == "tcp" && t.tcp || network == "udp" && t.udp
}

func parseTransports(values []string) (transportSet, error) {
	if values == nil {
		return transportSet{tcp: true}, nil
	}
	if len(values) == 0 {
		return transportSet{}, errors.New("empty transports list")
	}
	var set transportSet
	for _, value := range values {
		switch value {
		case "tcp":
			set.tcp = true
		case "udp":
			set.udp = true
		default:
			return transportSet{}, fmt.Errorf("unknown transport %q", value)
		}
	}
	return set, nil
}

// rule is one loaded descriptor rule. Name rules carry an optional
// static resolution list; literal rules carry a prefix.
type rule struct {
	id         string
	ports      portSet
	transports transportSet
	resolve    []netip.Addr
	prefix     netip.Prefix
}

type suffixRule struct {
	suffix string
	depth  int // maximum labels before the suffix; 0 means unlimited
	rule   *rule
}

// policy is a loaded descriptor bound to one listener.
type policy struct {
	version, sandbox, generation string
	udp                          bool
	names                        map[string][]*rule
	suffixes                     []suffixRule
	wildcard                     []*rule
	literals                     []*rule
	exceptions                   []*rule
}

// current is the listener's policy; nil answers policy-unavailable.
// Handlers from an earlier test may still read it while a test replaces it.
var current atomic.Pointer[policy]

// lookupNetIP resolves permitted hostnames; tests substitute it.
var lookupNetIP = net.DefaultResolver.LookupNetIP

// pinnedResolver returns a resolver that sends every query to server,
// bypassing resolv.conf, hosts files, and search domains.
func pinnedResolver(server string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, server)
		},
	}
}

func loadPolicyFile(path, generation string) (*policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return loadDescriptor(data, generation)
}

// loadDescriptor parses and validates a descriptor. Unknown fields,
// unknown schema versions, and any rule the schema forbids are errors.
func loadDescriptor(data []byte, generation string) (*policy, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var d descriptor
	if err := decoder.Decode(&d); err != nil {
		return nil, fmt.Errorf("policy descriptor: %w", err)
	}
	if decoder.More() {
		return nil, errors.New("policy descriptor: trailing data")
	}
	if d.Schema != 1 {
		return nil, fmt.Errorf("policy descriptor: unsupported agents_net_policy %d", d.Schema)
	}
	if d.Version == "" || len(d.Version) > 256 {
		return nil, errors.New("policy descriptor: version is required")
	}
	if d.Sandbox == "" || len(d.Sandbox) > 256 {
		return nil, errors.New("policy descriptor: sandbox is required")
	}
	if d.Default != "deny" {
		return nil, fmt.Errorf("policy descriptor: default must be \"deny\", got %q", d.Default)
	}
	p := &policy{version: d.Version, sandbox: d.Sandbox, generation: generation, udp: d.Features.UDP, names: map[string][]*rule{}}
	for i, dr := range d.Rules {
		if err := p.addRule(dr); err != nil {
			return nil, fmt.Errorf("policy descriptor: rule %d: %w", i, err)
		}
	}
	for i, dr := range d.ResolvedAddresses {
		if dr.CIDR == "" || dr.Name != "" || dr.Suffix != "" || dr.IP != "" || dr.Transports != nil || dr.Resolve != nil || dr.ID != "" || dr.Depth != 0 {
			return nil, fmt.Errorf("policy descriptor: resolved_addresses %d: only cidr and ports are allowed", i)
		}
		prefix, err := parsePrefix(dr.CIDR)
		if err != nil {
			return nil, fmt.Errorf("policy descriptor: resolved_addresses %d: %w", i, err)
		}
		if !specialPurpose(prefix) {
			return nil, fmt.Errorf("policy descriptor: resolved_addresses %d: %s is not within a special-purpose range", i, prefix)
		}
		ports, err := parsePorts(dr.Ports)
		if err != nil {
			return nil, fmt.Errorf("policy descriptor: resolved_addresses %d: %w", i, err)
		}
		p.exceptions = append(p.exceptions, &rule{prefix: prefix, ports: ports})
	}
	return p, nil
}

func (p *policy) addRule(dr descriptorRule) error {
	kinds := 0
	for _, field := range []string{dr.Name, dr.Suffix, dr.IP, dr.CIDR} {
		if field != "" {
			kinds++
		}
	}
	if kinds != 1 {
		return errors.New("exactly one of name, suffix, ip, cidr is required")
	}
	if len(dr.ID) > 64 {
		return errors.New("id longer than 64 characters")
	}
	ports, err := parsePorts(dr.Ports)
	if err != nil {
		return err
	}
	transports, err := parseTransports(dr.Transports)
	if err != nil {
		return err
	}
	r := &rule{id: dr.ID, ports: ports, transports: transports}
	if dr.Resolve != nil {
		if dr.Name == "" || dr.Name == "*" {
			return errors.New("resolve requires a name other than \"*\"")
		}
		if len(dr.Resolve) == 0 {
			return errors.New("empty resolve list")
		}
		for _, raw := range dr.Resolve {
			address, err := netip.ParseAddr(raw)
			if err != nil || address.Zone() != "" {
				return fmt.Errorf("resolve address %q", raw)
			}
			r.resolve = append(r.resolve, address.Unmap())
		}
	}
	if dr.Depth != 0 && (dr.Suffix == "" || dr.Depth < 0) {
		return errors.New("depth requires a suffix and a positive value")
	}
	switch {
	case dr.Name == "*":
		p.wildcard = append(p.wildcard, r)
	case dr.Name != "":
		name, ok := normalizeName(dr.Name)
		if !ok {
			return fmt.Errorf("name %q is not a hostname", dr.Name)
		}
		p.names[name] = append(p.names[name], r)
	case dr.Suffix != "":
		suffix, ok := normalizeName(dr.Suffix)
		if !ok {
			return fmt.Errorf("suffix %q is not a hostname", dr.Suffix)
		}
		p.suffixes = append(p.suffixes, suffixRule{suffix: suffix, depth: dr.Depth, rule: r})
	case dr.IP != "":
		address, err := netip.ParseAddr(dr.IP)
		if err != nil || address.Zone() != "" {
			return fmt.Errorf("ip %q", dr.IP)
		}
		address = address.Unmap()
		r.prefix = netip.PrefixFrom(address, address.BitLen())
		p.literals = append(p.literals, r)
	default:
		if r.prefix, err = parsePrefix(dr.CIDR); err != nil {
			return err
		}
		p.literals = append(p.literals, r)
	}
	return nil
}

// parsePrefix reads a CIDR, mapping an IPv4-mapped IPv6 prefix to IPv4.
func parsePrefix(text string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(text)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("cidr %q", text)
	}
	if prefix.Addr().Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("cidr %q has a zone", text)
	}
	if prefix.Addr().Is4In6() {
		if prefix.Bits() < 96 {
			return netip.Prefix{}, fmt.Errorf("cidr %q: IPv4-mapped prefix shorter than /96", text)
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	return prefix.Masked(), nil
}

// nameProfile maps U-labels to A-labels for lookup without the STD3 ASCII
// rules, which would reject the underscore that validName permits.
var nameProfile = idna.New(idna.MapForLookup(), idna.StrictDomainName(false), idna.BidiRule())

// normalizeName lowercases a hostname, removes one trailing dot, converts
// U-labels to A-labels, and checks the result against the label syntax
// (spec/draft/wire.md Section 6). Addresses are not names.
func normalizeName(host string) (string, bool) {
	name := strings.TrimSuffix(strings.ToLower(host), ".")
	if name == "" {
		return "", false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return "", false
	}
	ascii, err := nameProfile.ToASCII(name)
	if err != nil {
		return "", false
	}
	return ascii, validName(ascii)
}

// validName accepts a normalized hostname: dot-separated non-empty labels
// of letters, digits, hyphens, and underscores, within DNS length limits.
func validName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

func parsePort(value string) (uint16, error) {
	number, err := strconv.ParseUint(value, 10, 16)
	if err != nil || number == 0 {
		return 0, fmt.Errorf("invalid port %q", value)
	}
	return uint16(number), nil
}

// nonPublic lists special-purpose ranges that netip's classifiers do not
// cover. Together with loopback, private, link-local, multicast, and
// unspecified addresses they are denied for resolved hostnames unless the
// policy lists them (spec/draft/wire.md Section 5.1).
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fec0::/10"),
}

func publicAddress(address netip.Addr) bool {
	if !address.IsGlobalUnicast() || address.IsPrivate() {
		return false
	}
	for _, prefix := range nonPublic {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

// specialPurpose reports whether every address in prefix is special-purpose
// (spec/draft/wire.md Section 5.1): the prefix lies within one nonPublic
// range or within one of the classifier ranges netip provides.
func specialPurpose(prefix netip.Prefix) bool {
	ranges := append([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("::/128"), netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8"),
	}, nonPublic...)
	for _, r := range ranges {
		if r.Addr().Is4() == prefix.Addr().Is4() && r.Bits() <= prefix.Bits() && r.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

// selectRule returns the first rule permitting port and network. When none
// does, reason says why the closest candidate failed: "" when no rule
// matched the destination at all.
func selectRule(candidates []*rule, port uint16, network string) (selected *rule, reason string) {
	for _, r := range candidates {
		switch {
		case !r.ports.permits(port):
			if reason == "" {
				reason = "port-not-allowed"
			}
		case !r.transports.has(network):
			reason = "transport-not-allowed"
		default:
			return r, ""
		}
	}
	return nil, reason
}

// literalRule returns a literal rule covering address on port, ignoring
// transport: a literal permission also admits the address as a resolution
// result for that port.
func (p *policy) literalRule(address netip.Addr, port uint16) *rule {
	for _, r := range p.literals {
		if r.prefix.Contains(address) && r.ports.permits(port) {
			return r
		}
	}
	return nil
}

func (p *policy) excepted(address netip.Addr, port uint16) bool {
	for _, r := range p.exceptions {
		if r.prefix.Contains(address) && r.ports.permits(port) {
			return true
		}
	}
	return false
}

// verdict is the outcome of authorizing one destination.
type verdict struct {
	destination string // normalized host:port for the audit record
	addresses   []netip.Addr
	rule        string
	reason      string // "" when allowed
	status      int    // HTTP status for a non-empty reason
	err         error  // resolution failure
}

func (v verdict) deny(status int, reason string) verdict {
	v.status, v.reason = status, reason
	return v
}

// authorize applies the descriptor to a destination (spec/draft/wire.md
// Section 5.2) and returns the exact addresses the boundary may dial.
func (p *policy) authorize(ctx context.Context, host, port, network string) verdict {
	v := verdict{destination: net.JoinHostPort(host, port), status: 403}
	number, err := parsePort(port)
	if err != nil {
		return v.deny(400, "malformed-port")
	}
	if address, err := netip.ParseAddr(strings.ToLower(host)); err == nil {
		if address.Zone() != "" {
			return v.deny(403, "scoped-ip")
		}
		address = address.Unmap()
		v.destination = net.JoinHostPort(address.String(), port)
		var candidates []*rule
		for _, r := range p.literals {
			if r.prefix.Contains(address) {
				candidates = append(candidates, r)
			}
		}
		selected, reason := selectRule(candidates, number, network)
		switch {
		case selected != nil:
			v.addresses, v.rule = []netip.Addr{address}, selected.id
			return v
		case reason != "":
			return v.deny(403, reason)
		default:
			return v.deny(403, "ip-not-on-allowlist")
		}
	}
	name, ok := normalizeName(host)
	if !ok {
		return v.deny(400, "malformed-target")
	}
	v.destination = net.JoinHostPort(name, port)
	candidates := append([]*rule(nil), p.names[name]...)
	for _, s := range p.suffixes {
		if !strings.HasSuffix(name, "."+s.suffix) {
			continue
		}
		if s.depth > 0 && strings.Count(name[:len(name)-len(s.suffix)-1], ".")+1 > s.depth {
			continue
		}
		candidates = append(candidates, s.rule)
	}
	candidates = append(candidates, p.wildcard...)
	selected, reason := selectRule(candidates, number, network)
	switch {
	case selected != nil:
	case reason != "":
		return v.deny(403, reason)
	default:
		return v.deny(403, "not-on-allowlist")
	}
	v.rule = selected.id
	resolved := selected.resolve
	if resolved == nil {
		if resolved, err = lookupNetIP(ctx, "ip", name); err != nil {
			v.err = err
			return v
		}
	}
	for _, address := range resolved {
		address = address.Unmap()
		if address.Zone() != "" {
			continue
		}
		if listed(selected.resolve, address) || p.literalRule(address, number) != nil || p.excepted(address, number) || publicAddress(address) {
			v.addresses = append(v.addresses, address)
		}
	}
	if len(v.addresses) == 0 {
		return v.deny(403, "resolved-address-denied")
	}
	return v
}

func listed(addresses []netip.Addr, address netip.Addr) bool {
	for _, a := range addresses {
		if a == address {
			return true
		}
	}
	return false
}

// authorize applies the current policy to a TCP destination and reports
// the dialable addresses, the reason token of a denial, or a resolution
// error. It is the entry point tests and fuzzers exercise.
func authorize(ctx context.Context, host, port string) ([]netip.Addr, string, error) {
	p := current.Load()
	if p == nil {
		return nil, "policy-unavailable", nil
	}
	v := p.authorize(ctx, host, port, "tcp")
	return v.addresses, v.reason, v.err
}
