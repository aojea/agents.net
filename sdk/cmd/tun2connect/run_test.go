package main

import (
	"slices"
	"testing"
)

func TestParseRunArgs(t *testing.T) {
	for _, test := range []struct {
		name     string
		args     []string
		boundary string
		command  []string
		ok       bool
	}{
		{name: "no arguments", args: nil},
		{name: "boundary only serves", args: []string{"vsock://2:1024"}, boundary: "vsock://2:1024", ok: true},
		{name: "bare path is a unix socket", args: []string{"/run/boundary.sock", "agent", "-v"}, boundary: "unix:///run/boundary.sock", command: []string{"agent", "-v"}, ok: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			boundary, command, ok := parseRunArgs(test.args)
			if ok != test.ok || boundary != test.boundary || !slices.Equal(command, test.command) {
				t.Fatalf("parseRunArgs(%q) = %q, %q, %v; want %q, %q, %v", test.args, boundary, command, ok, test.boundary, test.command, test.ok)
			}
		})
	}
}
