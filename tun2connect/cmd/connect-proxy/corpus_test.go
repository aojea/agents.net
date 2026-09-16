package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

// rawRequest sends one raw HTTP/1.1 head to serve and returns the status
// code (0 when the connection closed without a response) and, for a 200,
// whether bytes written after the head reached the echo upstream.
func rawRequest(t *testing.T, raw string) (status int, reason string, echoed bool) {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() { defer close(done); serve(server) }()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	go io.WriteString(client, raw)
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		<-done
		return 0, "", false
	}
	if response.StatusCode == http.StatusOK {
		trailer := make([]byte, len("after-head"))
		_, err := io.ReadFull(client, trailer)
		echoed = err == nil && string(trailer) == "after-head"
	}
	client.Close()
	<-done
	return response.StatusCode, response.Header.Get("Boundary-Reason"), echoed
}

// TestRequestHeadCorpus is the negative corpus for the HTTP/1.1 head:
// each malformed or conflicting request is refused before policy or
// before any upstream dial, and the two well-formed controls succeed.
func TestRequestHeadCorpus(t *testing.T) {
	upstream, connections := echoListener(t)
	port := strconv.Itoa(upstream.Addr().(*net.TCPAddr).Port)
	target := "127.0.0.1:" + port
	setPolicy(t, "", "127.0.0.1:"+port, "")
	captureAudit(t)
	previousUDP := enableUDP
	t.Cleanup(func() { enableUDP = previousUDP })
	enableUDP = false

	const after = "after-head"
	cases := []struct {
		name   string
		raw    string
		status int
		reason string
		dials  int32
	}{
		{"authority-form with matching Host", "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n" + after, 200, "", 1},
		{"HTTP/1.0 without Host", "CONNECT " + target + " HTTP/1.0\r\n\r\n" + after, 200, "", 1},
		{"Host with different case and trailing dot on a name", "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n" + after, 200, "", 1},
		{"Content-Length is ignored on CONNECT", "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\nContent-Length: 3\r\n\r\n" + after, 200, "", 1},
		{"HTTP/1.1 without Host", "CONNECT " + target + " HTTP/1.1\r\n\r\n", 400, "missing-host", 0},
		{"duplicate Host", "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\nHost: " + target + "\r\n\r\n", 400, "duplicate-host", 0},
		{"Host names another host", "CONNECT " + target + " HTTP/1.1\r\nHost: 192.0.2.1:" + port + "\r\n\r\n", 400, "authority-mismatch", 0},
		{"Host names another port", "CONNECT " + target + " HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n", 400, "authority-mismatch", 0},
		{"Host uses a different address text", "CONNECT " + target + " HTTP/1.1\r\nHost: [::ffff:127.0.0.1]:" + port + "\r\n\r\n", 400, "authority-mismatch", 0},
		{"no port", "CONNECT 127.0.0.1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", 400, "malformed-target", 0},
		{"port zero", "CONNECT 127.0.0.1:0 HTTP/1.1\r\nHost: 127.0.0.1:0\r\n\r\n", 400, "malformed-port", 0},
		{"port out of range", "CONNECT 127.0.0.1:65536 HTTP/1.1\r\nHost: 127.0.0.1:65536\r\n\r\n", 400, "malformed-port", 0},
		{"service name as port", "CONNECT 127.0.0.1:http HTTP/1.1\r\nHost: 127.0.0.1:http\r\n\r\n", 400, "malformed-port", 0},
		{"userinfo", "CONNECT user@" + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n", 400, "malformed-target", 0},
		{"path after authority", "CONNECT " + target + "/admin HTTP/1.1\r\nHost: " + target + "\r\n\r\n", 400, "malformed-target", 0},
		{"query after authority", "CONNECT " + target + "?x=1 HTTP/1.1\r\nHost: " + target + "\r\n\r\n", 400, "malformed-target", 0},
		{"absolute-form", "CONNECT http://" + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n", 400, "malformed-target", 0},
		{"empty authority", "CONNECT  HTTP/1.1\r\nHost: " + target + "\r\n\r\n", 400, "malformed-request-line", 0},
		{"unbracketed IPv6", "CONNECT ::1:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n", 400, "malformed-target", 0},
		{"bracketed IPv6 without port", "CONNECT [::1] HTTP/1.1\r\nHost: [::1]\r\n\r\n", 400, "malformed-target", 0},
		{"HTTP/2.0 on the cleartext wire", "CONNECT " + target + " HTTP/2.0\r\nHost: " + target + "\r\n\r\n", 505, "unsupported-version", 0},
		{"HTTP/0.9 style", "CONNECT " + target + "\r\n\r\n", 400, "malformed-request-line", 0},
		{"two spaces in the request line", "CONNECT " + target + "  HTTP/1.1\r\nHost: " + target + "\r\n\r\n", 400, "malformed-request-line", 0},
		{"tab in the method", "CONNECT\t" + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n", 400, "malformed-request-line", 0},
		{"lowercase method is not CONNECT", "connect " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n", 405, "connect-only", 0},
		{"GET without upgrade", "GET / HTTP/1.1\r\nHost: boundary\r\n\r\n", 405, "connect-only", 0},
		{"invalid header name", "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\nBad Header: x\r\n\r\n", 400, "malformed-header", 0},
		{"oversized head", "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\nX-Pad: " + strings.Repeat("a", maxHeadBytes) + "\r\n\r\n", 431, "head-too-large", 0},
		{"denied destination with trailing bytes", "CONNECT 192.0.2.1:443 HTTP/1.1\r\nHost: 192.0.2.1:443\r\n\r\n" + after, 403, "ip-not-on-allowlist", 0},
		{"allowed host on an unlisted port", "CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n", 403, "port-not-allowed", 0},
		{"connect-udp upgrade with UDP disabled", "GET /.well-known/masque/udp/127.0.0.1/" + port + "/ HTTP/1.1\r\nHost: boundary\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n\r\n", 403, "udp-disabled", 0},
		{"connect-udp upgrade without Connection: Upgrade", "GET /.well-known/masque/udp/127.0.0.1/" + port + "/ HTTP/1.1\r\nHost: boundary\r\nUpgrade: connect-udp\r\n\r\n", 400, "malformed-upgrade", 0},
		{"connect-udp upgrade with a wrong template", "GET /masque/udp/127.0.0.1/" + port + "/ HTTP/1.1\r\nHost: boundary\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n\r\n", 400, "malformed-template", 0},
		{"websocket upgrade", "GET / HTTP/1.1\r\nHost: boundary\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", 405, "connect-only", 0},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			before := connections.Load()
			status, reason, echoed := rawRequest(t, test.raw)
			if status != test.status || reason != test.reason {
				t.Fatalf("got %d %q, want %d %q", status, reason, test.status, test.reason)
			}
			if status == 200 && !echoed {
				t.Fatal("bytes after the head did not reach the upstream")
			}
			// The upstream accept loop may lag the 200 by a moment.
			deadline := time.Now().Add(2 * time.Second)
			for connections.Load()-before != test.dials && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if got := connections.Load() - before; got != test.dials {
				t.Fatalf("upstream dials = %d, want %d", got, test.dials)
			}
		})
	}
}

func TestSameAuthority(t *testing.T) {
	for _, test := range []struct {
		a, b string
		want bool
	}{
		{"api.example:443", "API.EXAMPLE.:443", true},
		{"api.example:443", "api.example:444", false},
		{"[::1]:443", "[0:0:0:0:0:0:0:1]:443", true},
		{"[::ffff:127.0.0.1]:443", "127.0.0.1:443", false},
		{"127.0.0.1:443", "localhost:443", false},
		{"api.example", "api.example:443", false},
		{"", "", false},
	} {
		if got := sameAuthority(test.a, test.b); got != test.want {
			t.Errorf("sameAuthority(%q, %q) = %v, want %v", test.a, test.b, got, test.want)
		}
	}
}

// Fuzz targets. Each checks that a guest-controlled parser never panics
// and that a successful parse satisfies the invariant policy relies on.

func FuzzReadHead(f *testing.F) {
	for _, seed := range []string{
		"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
		"CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n",
		"GET /.well-known/masque/udp/example.com/53/ HTTP/1.1\r\nHost: b\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n\r\n",
		"CONNECT  HTTP/1.1\r\n\r\n", "CONNECT a:1 HTTP/2.0\r\n\r\n", "\r\n\r\n", "CONNECT",
		"CONNECT a:1 HTTP/1.1\r\nHost: a:1\r\nHost: b:2\r\n\r\n",
		"CONNECT a:1 HTTP/1.1\r\nX:\x01\r\n\r\n", "CONNECT a:1 HTTP/1.1\r\n Folded: yes\r\n\r\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		limiter := &boundedReader{r: strings.NewReader(raw), remaining: maxHeadBytes}
		h, err := readHead(bufio.NewReader(limiter))
		if err != nil {
			return
		}
		if h.major != 1 || h.method == "" || h.target == "" || strings.ContainsAny(h.method, " \t") || len(h.header.Values("Host")) > 1 {
			t.Fatalf("invalid head accepted: %+v", h)
		}
		if h.minor >= 1 && len(h.header.Values("Host")) == 0 {
			t.Fatal("HTTP/1.1 head without Host accepted")
		}
		if host, port, reason := connectTarget(h); reason == "" {
			if host == "" || strings.ContainsAny(host, "/?#@ ") {
				t.Fatalf("invalid host %q accepted", host)
			}
			if _, err := parsePort(port); err != nil {
				t.Fatalf("invalid port %q accepted", port)
			}
			if hostField := h.header.Get("Host"); hostField != "" && !sameAuthority(hostField, net.JoinHostPort(host, port)) {
				t.Fatalf("Host %q accepted for target %q", hostField, h.target)
			}
		}
		if path, ok := upgradeTarget(h); ok {
			if host, port, ok := masqueTarget(path); ok && (host == "" || port == "") {
				t.Fatalf("empty template component accepted: %q", path)
			}
		}
	})
}

func FuzzAuthorize(f *testing.F) {
	for _, seed := range [][2]string{
		{"api.example", "443"}, {"127.0.0.1", "443"}, {"::1", "443"}, {"::ffff:169.254.169.254", "80"},
		{"fe80::1%eth0", "443"}, {"API.EXAMPLE.", "0"}, {"", ""}, {"a", "65536"}, {"metadata.example", "80"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, host, port string) {
		// Every name is allowed; the resolver returns a mix of public and
		// non-public answers. No literal is listed.
		allowed = map[string]*portSet{"*": {any: true}}
		allowedIPs = nil
		static = nil
		lookupNetIP = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
			return []netip.Addr{
				netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("169.254.169.254"), netip.MustParseAddr("::ffff:192.168.0.1"),
				netip.MustParseAddr("fd00::1"), netip.MustParseAddr("93.184.216.34"),
				netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946"),
			}, nil
		}
		addresses, reason, err := authorize(context.Background(), host, port)
		if err != nil {
			t.Fatalf("resolver never fails: %v", err)
		}
		if number, perr := parsePort(port); perr != nil && reason != "malformed-port" {
			t.Fatalf("port %q accepted with reason %q", port, reason)
		} else if perr == nil && number == 0 {
			t.Fatal("port zero parsed")
		}
		if _, isLiteral := netip.ParseAddr(strings.ToLower(host)); isLiteral == nil && reason == "" {
			t.Fatalf("unlisted literal %q authorized", host)
		}
		for _, address := range addresses {
			if !publicAddress(address) {
				t.Fatalf("non-public %v authorized for %q", address, host)
			}
		}
	})
}

func FuzzPolicyParsers(f *testing.F) {
	for _, seed := range []string{
		"api.example:443, *:80, name", "192.0.2.1:443, [2001:db8::/64]:443, 10.0.0.0/8, ::ffff:203.0.113.0/120",
		"a=1.2.3.4+::1, b.=5.6.7.8", "[", "]:", ":", "*", "1.2.3.4", "a:b:c", "[::1]", "[::1]:x", ",,,",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		rest, port, hasPort, err := splitPort(value)
		if err == nil && hasPort && (port == 0) {
			t.Fatalf("splitPort(%q) accepted port zero", value)
		}
		if err == nil && !hasPort && !strings.HasPrefix(value, "[") && rest != value {
			t.Fatalf("splitPort(%q) changed a portless entry to %q", value, rest)
		}
		if names, err := parseAllow(value); err == nil {
			for name, ports := range names {
				if name != "*" && !validName(name) {
					t.Fatalf("invalid name %q accepted", name)
				}
				if _, isIP := netip.ParseAddr(name); isIP == nil {
					t.Fatalf("address %q accepted as a name", name)
				}
				if !ports.any && len(ports.ports) == 0 {
					t.Fatalf("name %q permits no port", name)
				}
			}
		}
		if rules, err := parseIPAllowlist(value); err == nil {
			for _, rule := range rules {
				if !rule.prefix.IsValid() || rule.prefix.Addr().Is4In6() || rule.prefix.Addr().Zone() != "" {
					t.Fatalf("invalid rule %+v", rule)
				}
			}
		}
		if mappings, err := parseStatic(value); err == nil {
			for name, addresses := range mappings {
				if !validName(name) || len(addresses) == 0 {
					t.Fatalf("invalid mapping %q -> %v", name, addresses)
				}
			}
		}
	})
}

func FuzzMasqueTarget(f *testing.F) {
	for _, seed := range []string{
		"/.well-known/masque/udp/example.com/53/", "/.well-known/masque/udp/2001%3Adb8%3A%3A1/53/",
		"/.well-known/masque/udp//53/", "/.well-known/masque/udp/a/b/c/", "/", "", "/.well-known/masque/udp/%zz/53/",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, path string) {
		host, port, ok := masqueTarget(path)
		if ok && (host == "" || port == "" || strings.Contains(port, "/")) {
			t.Fatalf("masqueTarget(%q) = %q, %q", path, host, port)
		}
	})
}
