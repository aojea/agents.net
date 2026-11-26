package main

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
)

// policyJSON builds a descriptor with the given rule objects and optional
// extra top-level members (a string starting with a comma).
func policyJSON(rules, extra string) string {
	return `{"agents_net_policy":1,"version":"test-v1","sandbox":"sandbox-test","default":"deny","rules":[` + rules + `]` + extra + `}`
}

// setPolicy installs a descriptor for one test and restores the previous
// policy afterwards.
func setPolicy(t *testing.T, descriptorJSON string) *policy {
	t.Helper()
	previous := current.Load()
	t.Cleanup(func() { current.Store(previous) })
	p, err := loadDescriptor([]byte(descriptorJSON), "")
	if err != nil {
		t.Fatal(err)
	}
	current.Store(p)
	return p
}

func TestDescriptorValidation(t *testing.T) {
	example := `{
	  "agents_net_policy": 1,
	  "version": "2026-09-17T10:00:00Z/3",
	  "sandbox": "sandbox-a",
	  "default": "deny",
	  "rules": [
	    {"id": "npm", "name": "registry.npmjs.org", "ports": [443]},
	    {"id": "gh-pkgs", "suffix": "pkg.github.com", "ports": [443]},
	    {"id": "db", "ip": "203.0.113.10", "ports": [5432]},
	    {"id": "v6net", "cidr": "2001:db8::/64", "ports": ["443", "8000-8099"], "transports": ["tcp", "udp"]},
	    {"id": "internal", "name": "svc.internal.example", "ports": [443], "resolve": ["10.0.1.50"]},
	    {"id": "idn", "name": "Bücher.Example.", "ports": [443]},
	    {"id": "any", "name": "*"}
	  ],
	  "resolved_addresses": [{"cidr": "10.0.0.0/8", "ports": [443]}],
	  "features": {"udp": true, "h2": false}
	}`
	p, err := loadDescriptor([]byte(example), "gen-1")
	if err != nil {
		t.Fatal(err)
	}
	if p.version != "2026-09-17T10:00:00Z/3" || p.sandbox != "sandbox-a" || p.generation != "gen-1" || !p.udp {
		t.Fatalf("labels: %+v", p)
	}
	if len(p.names["xn--bcher-kva.example"]) != 1 {
		t.Fatalf("U-label name was not converted: %v", p.names)
	}
	if len(p.literals) != 2 || len(p.suffixes) != 1 || len(p.wildcard) != 1 || len(p.exceptions) != 1 {
		t.Fatalf("rule counts: %+v", p)
	}
	v6 := p.literals[1]
	if !v6.ports.permits(443) || !v6.ports.permits(8050) || v6.ports.permits(8100) || !v6.transports.udp {
		t.Fatalf("port ranges or transports: %+v", v6)
	}
	for name, bad := range map[string]string{
		"unknown field":          `{"agents_net_policy":1,"version":"v","sandbox":"s","default":"deny","rules":[],"extra":1}`,
		"schema version":         `{"agents_net_policy":2,"version":"v","sandbox":"s","default":"deny","rules":[]}`,
		"missing version":        `{"agents_net_policy":1,"sandbox":"s","default":"deny","rules":[]}`,
		"missing sandbox":        `{"agents_net_policy":1,"version":"v","default":"deny","rules":[]}`,
		"default allow":          `{"agents_net_policy":1,"version":"v","sandbox":"s","default":"allow","rules":[]}`,
		"trailing data":          `{"agents_net_policy":1,"version":"v","sandbox":"s","default":"deny","rules":[]} {}`,
		"two kinds":              policyJSON(`{"name":"a.example","ip":"192.0.2.1"}`, ""),
		"no kind":                policyJSON(`{"ports":[443]}`, ""),
		"port zero":              policyJSON(`{"name":"a.example","ports":[0]}`, ""),
		"port too large":         policyJSON(`{"name":"a.example","ports":[65536]}`, ""),
		"named port":             policyJSON(`{"name":"a.example","ports":["https"]}`, ""),
		"fractional port":        policyJSON(`{"name":"a.example","ports":[443.5]}`, ""),
		"reversed range":         policyJSON(`{"name":"a.example","ports":["9000-8000"]}`, ""),
		"empty ports":            policyJSON(`{"name":"a.example","ports":[]}`, ""),
		"unknown transport":      policyJSON(`{"name":"a.example","transports":["sctp"]}`, ""),
		"empty transports":       policyJSON(`{"name":"a.example","transports":[]}`, ""),
		"resolve on wildcard":    policyJSON(`{"name":"*","resolve":["192.0.2.1"]}`, ""),
		"resolve on suffix":      policyJSON(`{"suffix":"example","resolve":["192.0.2.1"]}`, ""),
		"resolve bad address":    policyJSON(`{"name":"a.example","resolve":["not-an-ip"]}`, ""),
		"resolve zoned address":  policyJSON(`{"name":"a.example","resolve":["fe80::1%eth0"]}`, ""),
		"empty resolve":          policyJSON(`{"name":"a.example","resolve":[]}`, ""),
		"name is an address":     policyJSON(`{"name":"192.0.2.1"}`, ""),
		"name empty label":       policyJSON(`{"name":"a..b"}`, ""),
		"name glob":              policyJSON(`{"name":"ex*ample.com"}`, ""),
		"name space":             policyJSON(`{"name":"a b.example"}`, ""),
		"label too long":         policyJSON(`{"name":"`+strings.Repeat("a", 64)+`.example"}`, ""),
		"suffix is an address":   policyJSON(`{"suffix":"::1"}`, ""),
		"ip is a prefix":         policyJSON(`{"ip":"192.0.2.0/24"}`, ""),
		"ip zoned":               policyJSON(`{"ip":"fe80::1%eth0"}`, ""),
		"cidr too long":          policyJSON(`{"cidr":"192.0.2.1/33"}`, ""),
		"cidr v6 too long":       policyJSON(`{"cidr":"2001:db8::/129"}`, ""),
		"cidr mapped too short":  policyJSON(`{"cidr":"::ffff:192.0.2.0/80"}`, ""),
		"exception with name":    policyJSON(``, `,"resolved_addresses":[{"name":"a.example"}]`),
		"exception without cidr": policyJSON(``, `,"resolved_addresses":[{"ports":[443]}]`),
		"exception with id":      policyJSON(``, `,"resolved_addresses":[{"cidr":"10.0.0.0/8","id":"x"}]`),
		"exception catch-all":    policyJSON(``, `,"resolved_addresses":[{"cidr":"0.0.0.0/0"}]`),
		"exception v6 catch-all": policyJSON(``, `,"resolved_addresses":[{"cidr":"::/0"}]`),
		"exception public range": policyJSON(``, `,"resolved_addresses":[{"cidr":"8.0.0.0/8"}]`),
		"exception spans ranges": policyJSON(``, `,"resolved_addresses":[{"cidr":"192.0.0.0/8"}]`),
		"depth on name":          policyJSON(`{"name":"a.example","depth":1}`, ""),
		"depth negative":         policyJSON(`{"suffix":"example","depth":-1}`, ""),
		"depth too large":        policyJSON(`{"suffix":"example","depth":127}`, ""),
		"id too long":            policyJSON(`{"id":"`+strings.Repeat("i", 65)+`","name":"a.example"}`, ""),
	} {
		if _, err := loadDescriptor([]byte(bad), ""); err == nil {
			t.Errorf("%s: invalid descriptor accepted", name)
		}
	}
	for _, good := range []string{
		policyJSON(`{"name":"xn--bcher-kva.example"},{"name":"my_service.internal","ports":[8080]},{"name":"a-b.c"}`, ""),
		policyJSON(`{"cidr":"::ffff:203.0.113.0/120","ports":[443]}`, ""),
		policyJSON(``, `,"features":{}`),
		policyJSON(``, `,"resolved_addresses":[{"cidr":"10.0.0.0/8"},{"cidr":"127.0.0.1/32"},{"cidr":"169.254.169.254/32"},{"cidr":"fd00::/8"},{"cidr":"::1/128"},{"cidr":"100.64.0.0/10"},{"cidr":"::ffff:10.1.0.0/112"}]`),
		policyJSON(`{"suffix":"example.com","depth":1}`, ""),
	} {
		if _, err := loadDescriptor([]byte(good), ""); err != nil {
			t.Errorf("valid descriptor rejected: %v\n%s", err, good)
		}
	}
}

func TestLiteralPolicy(t *testing.T) {
	setResolver(t, func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	})
	ctx := context.Background()
	setPolicy(t, policyJSON(`{"name":"api.example"},{"name":"*"}`, ""))
	if _, reason, _ := authorize(ctx, "127.0.0.1", "443"); reason != "ip-not-on-allowlist" {
		t.Fatalf("hostname wildcard must not authorize literal addresses: %q", reason)
	}
	setPolicy(t, policyJSON(`{"name":"api.example"},{"ip":"192.0.2.1"},{"cidr":"198.51.100.19/24"},{"cidr":"2001:db8::/64"},{"cidr":"::ffff:203.0.113.0/120"}`, ""))
	for _, test := range []struct {
		host, port string
		want       bool
	}{
		{"API.EXAMPLE", "443", true}, {"api.example.", "443", true}, {"denied.example", "443", false},
		{"192.0.2.1", "443", true}, {"192.0.2.2", "443", false},
		{"198.51.100.254", "443", true}, {"198.51.101.1", "443", false},
		{"2001:db8::1", "443", true}, {"2001:db8:0:1::1", "443", false},
		{"::ffff:192.0.2.1", "443", true}, {"203.0.113.1", "443", true},
		{"127.0.0.1", "443", false}, {"169.254.169.254", "80", false}, {"fe80::1%eth0", "443", false},
		{"192.0.2.1", "0", false}, {"192.0.2.1", "65536", false}, {"192.0.2.1", "https", false}, {"192.0.2.1", "", false},
	} {
		t.Run(test.host+":"+test.port, func(t *testing.T) {
			addresses, reason, err := authorize(ctx, test.host, test.port)
			if err != nil {
				t.Fatal(err)
			}
			if ok := reason == ""; ok != test.want {
				t.Fatalf("authorize = %v (%s), want %v", ok, reason, test.want)
			}
			if test.want && len(addresses) != 1 {
				t.Fatalf("addresses = %v, want exactly one", addresses)
			}
		})
	}
}

// TestPortPolicy checks that ports on rules restrict the destination port
// on names, literals, suffixes, and the wildcard, that a rule without
// ports keeps every port open, and that ranges work.
func TestPortPolicy(t *testing.T) {
	setResolver(t, func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	})
	setPolicy(t, policyJSON(`
		{"name":"api.example","ports":[443,8443]},{"name":"any.example"},{"name":"*","ports":["80"]},
		{"suffix":"apps.example","ports":["8000-8099"]},
		{"ip":"192.0.2.1","ports":[443]},{"cidr":"198.51.100.0/24","ports":[22]},{"ip":"2001:db8::1","ports":[443]},
		{"cidr":"2001:db8:1::/64","ports":[53]},{"ip":"203.0.113.7"}`, ""))
	ctx := context.Background()
	for _, test := range []struct {
		host, port, reason string
	}{
		{"api.example", "443", ""}, {"api.example", "8443", ""}, {"api.example", "80", ""},
		{"api.example", "22", "port-not-allowed"},
		{"any.example", "22", ""}, {"any.example", "1", ""},
		{"other.example", "80", ""}, {"other.example", "443", "port-not-allowed"},
		{"web.apps.example", "8050", ""}, {"web.apps.example", "8100", "port-not-allowed"}, {"apps.example", "8050", "port-not-allowed"},
		{"192.0.2.1", "443", ""}, {"192.0.2.1", "80", "port-not-allowed"},
		{"198.51.100.9", "22", ""}, {"198.51.100.9", "23", "port-not-allowed"},
		{"2001:db8::1", "443", ""}, {"2001:db8::1", "444", "port-not-allowed"},
		{"2001:db8:1::5", "53", ""}, {"2001:db8:1::5", "443", "port-not-allowed"},
		{"203.0.113.7", "1", ""}, {"203.0.113.7", "65535", ""},
		{"203.0.113.8", "443", "ip-not-on-allowlist"},
	} {
		t.Run(test.host+":"+test.port, func(t *testing.T) {
			_, reason, err := authorize(ctx, test.host, test.port)
			if err != nil || reason != test.reason {
				t.Fatalf("authorize = %q, %v; want %q", reason, err, test.reason)
			}
		})
	}
	// A resolved-address exception is port-scoped too.
	setResolver(t, func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.1.2.3")}, nil
	})
	setPolicy(t, policyJSON(`{"name":"internal.example"}`, `,"resolved_addresses":[{"cidr":"10.1.2.0/24","ports":[9443]}]`))
	if _, reason, _ := authorize(ctx, "internal.example", "9443"); reason != "" {
		t.Fatalf("listed port: %q", reason)
	}
	if _, reason, _ := authorize(ctx, "internal.example", "443"); reason != "resolved-address-denied" {
		t.Fatalf("unlisted port on a private address: %q", reason)
	}
}

func TestTransportPolicy(t *testing.T) {
	p := setPolicy(t, policyJSON(`
		{"id":"tcp-only","ip":"192.0.2.1","ports":[443]},
		{"id":"both","ip":"192.0.2.2","ports":[443],"transports":["tcp","udp"]},
		{"id":"udp-only","name":"dns.example","ports":[53],"transports":["udp"],"resolve":["203.0.113.53"]}`,
		`,"features":{"udp":true}`))
	ctx := context.Background()
	for _, test := range []struct {
		host, port, network, reason, rule string
	}{
		{"192.0.2.1", "443", "tcp", "", "tcp-only"},
		{"192.0.2.1", "443", "udp", "transport-not-allowed", ""},
		{"192.0.2.1", "80", "udp", "port-not-allowed", ""},
		{"192.0.2.2", "443", "udp", "", "both"},
		{"dns.example", "53", "udp", "", "udp-only"},
		{"dns.example", "53", "tcp", "transport-not-allowed", ""},
	} {
		v := p.authorize(ctx, test.host, test.port, test.network)
		if v.reason != test.reason || v.rule != test.rule {
			t.Errorf("%s:%s/%s: reason %q rule %q, want %q %q", test.host, test.port, test.network, v.reason, v.rule, test.reason, test.rule)
		}
	}
}

func TestSuffixPolicy(t *testing.T) {
	setResolver(t, func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	})
	p := setPolicy(t, policyJSON(`{"id":"sfx","suffix":"Example.COM.","ports":[443]},{"id":"exact","name":"exact.example.com","ports":[443]},{"id":"one","suffix":"github.io","depth":1,"ports":[443]},{"id":"two","suffix":"pages.test","depth":2,"ports":[443]}`, ""))
	ctx := context.Background()
	for _, test := range []struct{ host, reason, rule string }{
		{"a.example.com", "", "sfx"}, {"a.b.example.com", "", "sfx"}, {"A.EXAMPLE.COM.", "", "sfx"},
		{"exact.example.com", "", "exact"},
		{"example.com", "not-on-allowlist", ""}, {"notexample.com", "not-on-allowlist", ""}, {"example.com.evil", "not-on-allowlist", ""},
		{"user.github.io", "", "one"}, {"a.user.github.io", "not-on-allowlist", ""}, {"github.io", "not-on-allowlist", ""},
		{"a.pages.test", "", "two"}, {"a.b.pages.test", "", "two"}, {"a.b.c.pages.test", "not-on-allowlist", ""},
	} {
		v := p.authorize(ctx, test.host, "443", "tcp")
		if v.reason != test.reason || v.rule != test.rule {
			t.Errorf("%s: reason %q rule %q, want %q %q", test.host, v.reason, v.rule, test.reason, test.rule)
		}
	}
}

// TestResolvedAddressPolicy checks that an allowed hostname only yields
// public or explicitly listed addresses, whatever its DNS answers say,
// and that a literal permission admits the same address as a result.
func TestResolvedAddressPolicy(t *testing.T) {
	setPolicy(t, policyJSON(`{"name":"*"},{"ip":"10.9.9.9","ports":[443]}`, `,"resolved_addresses":[{"cidr":"10.1.2.0/24"}]`))
	ctx := context.Background()
	answers := map[string][]string{
		"public.example":    {"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"},
		"metadata.example":  {"169.254.169.254"},
		"loopback.example":  {"127.0.0.1", "::1"},
		"private.example":   {"10.0.0.5", "172.16.0.1", "192.168.1.1", "fd00::1"},
		"mapped.example":    {"::ffff:127.0.0.1", "::ffff:10.0.0.1"},
		"nat64.example":     {"64:ff9b::7f00:1"},
		"shared.example":    {"100.64.0.1", "100::1"},
		"reserved.example":  {"0.0.0.1", "240.0.0.1", "255.255.255.255", "2001:db8::1", "2002:7f00:1::1", "fec0::1"},
		"multicast.example": {"224.0.0.1", "ff02::1", "0.0.0.0", "::"},
		"mixed.example":     {"127.0.0.1", "93.184.216.34", "169.254.169.254"},
		"listed.example":    {"10.1.2.3"},
		"literal.example":   {"10.9.9.9"},
		"empty.example":     {},
	}
	setResolver(t, func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		records, ok := answers[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		var addresses []netip.Addr
		for _, record := range records {
			addresses = append(addresses, netip.MustParseAddr(record))
		}
		return addresses, nil
	})
	for host, want := range map[string][]string{
		"public.example":    {"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"},
		"metadata.example":  nil,
		"loopback.example":  nil,
		"private.example":   nil,
		"mapped.example":    nil,
		"nat64.example":     nil,
		"shared.example":    nil,
		"reserved.example":  nil,
		"multicast.example": nil,
		"mixed.example":     {"93.184.216.34"},
		"listed.example":    {"10.1.2.3"},
		"literal.example":   {"10.9.9.9"},
		"empty.example":     nil,
	} {
		t.Run(host, func(t *testing.T) {
			addresses, reason, err := authorize(ctx, host, "443")
			if err != nil {
				t.Fatal(err)
			}
			if want == nil {
				if reason != "resolved-address-denied" || len(addresses) != 0 {
					t.Fatalf("expected denial, got %v (%q)", addresses, reason)
				}
				return
			}
			if reason != "" || len(addresses) != len(want) {
				t.Fatalf("addresses = %v (%q), want %v", addresses, reason, want)
			}
			for i, address := range addresses {
				if address.String() != want[i] {
					t.Fatalf("addresses = %v, want %v", addresses, want)
				}
			}
		})
	}
	if _, reason, err := authorize(ctx, "missing.example", "443"); err == nil || reason != "" {
		t.Fatalf("resolution failure must be an error, not a policy decision: %v %q", err, reason)
	}
	// The literal permission is port-scoped when used for a resolution result.
	if _, reason, _ := authorize(ctx, "literal.example", "80"); reason != "resolved-address-denied" {
		t.Fatalf("literal permission leaked to another port: %q", reason)
	}
	// An exception never authorizes a literal.
	if _, reason, _ := authorize(ctx, "10.1.2.3", "443"); reason != "ip-not-on-allowlist" {
		t.Fatalf("resolved_addresses authorized a literal: %q", reason)
	}
}

// TestStaticResolution checks that a rule's resolve list replaces DNS and
// authorizes exactly those addresses for the rule's ports.
func TestStaticResolution(t *testing.T) {
	var lookups atomic.Int32
	setResolver(t, func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		lookups.Add(1)
		return nil, errors.New("DNS must not be consulted for a mapped name")
	})
	p := setPolicy(t, policyJSON(`
		{"id":"target","name":"target.internal","ports":[9099],"resolve":["127.0.0.1","::1"]},
		{"id":"public","name":"Public.Example.","resolve":["93.184.216.34"]}`, ""))
	ctx := context.Background()
	v := p.authorize(ctx, "TARGET.INTERNAL.", "9099", "tcp")
	if v.reason != "" || len(v.addresses) != 2 || v.rule != "target" || v.destination != "target.internal:9099" {
		t.Fatalf("mapped loopback: %+v", v)
	}
	if v := p.authorize(ctx, "target.internal", "443", "tcp"); v.reason != "port-not-allowed" {
		t.Fatalf("mapped name on another port: %+v", v)
	}
	if v := p.authorize(ctx, "public.example", "443", "tcp"); v.reason != "" || len(v.addresses) != 1 || v.addresses[0] != netip.MustParseAddr("93.184.216.34") {
		t.Fatalf("public mapping: %+v", v)
	}
	if lookups.Load() != 0 {
		t.Fatalf("DNS consulted %d times for mapped names", lookups.Load())
	}
}

func TestNameNormalization(t *testing.T) {
	setResolver(t, func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		if host != "xn--bcher-kva.example" {
			return nil, errors.New("unexpected lookup of " + host)
		}
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	})
	p := setPolicy(t, policyJSON(`{"name":"bücher.example","ports":[443]}`, ""))
	ctx := context.Background()
	for _, host := range []string{"bücher.example", "BÜCHER.EXAMPLE.", "xn--bcher-kva.example", "XN--BCHER-KVA.EXAMPLE."} {
		if v := p.authorize(ctx, host, "443", "tcp"); v.reason != "" || v.destination != "xn--bcher-kva.example:443" {
			t.Errorf("%s: %+v", host, v)
		}
	}
	for _, host := range []string{"a..b", "-", "a b.example", "ex*ample.com", strings.Repeat("a", 64) + ".example", "."} {
		if v := p.authorize(ctx, host, "443", "tcp"); v.reason != "malformed-target" || v.status != 400 {
			t.Errorf("%q: %+v", host, v)
		}
	}
}

// TestPolicyUnavailable checks that a listener without a loaded policy
// refuses every tunnel request with 503 and audits the failure.
func TestPolicyUnavailable(t *testing.T) {
	previous := current.Load()
	t.Cleanup(func() { current.Store(previous) })
	current.Store(nil)
	output := captureAudit(t)
	status, reason, _ := rawRequest(t, "CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n")
	if status != 503 || reason != "policy-unavailable" {
		t.Fatalf("got %d %q", status, reason)
	}
	if !strings.Contains(output.String(), `"reason":"policy-unavailable"`) {
		t.Fatalf("audit: %s", output.String())
	}
}
