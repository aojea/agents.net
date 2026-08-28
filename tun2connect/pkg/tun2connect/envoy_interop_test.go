package tun2connect

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
)

// TestEnvoyInterop proves the mesh-integration claim against a real
// dataplane: an unmodified Envoy (examples/envoy-boundary.yaml)
// terminating the wire at both stages. Gated on env vars because it
// needs docker and real egress -- run it via test_envoy.sh.
func TestEnvoyInterop(t *testing.T) {
	h1 := os.Getenv("ENVOY_CONNECT_H1")
	h2 := os.Getenv("ENVOY_CONNECT_H2")
	if h1 == "" || h2 == "" {
		t.Skip("set ENVOY_CONNECT_H1/ENVOY_CONNECT_H2 (see test_envoy.sh)")
	}
	dialTo := func(addr string) func(ctx context.Context) (net.Conn, error) {
		return func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		}
	}
	for _, tc := range []struct {
		name   string
		dialer Dialer
	}{
		{"h1-wire", &BoundaryClient{DialBoundary: dialTo(h1)}},
		{"h2-wire", &BoundaryClientH2{DialBoundary: dialTo(h2)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := tc.dialer.DialTCP(context.Background(), "example.com", 80)
			if err != nil {
				t.Fatalf("CONNECT via Envoy: %v", err)
			}
			defer conn.Close()
			fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatalf("read through tunnel: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET example.com through Envoy = %s", resp.Status)
			}
		})
	}
}
