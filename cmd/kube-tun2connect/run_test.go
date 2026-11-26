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

func TestParsePinnedPorts(t *testing.T) {
	for _, test := range []struct {
		value    string
		in, out  []uint16
		wantFail bool
	}{
		{value: "8081", in: []uint16{8081}, out: []uint16{8080, 8082}},
		{value: "80, 8081", in: []uint16{80, 8081}, out: []uint16{81, 8080}},
		{value: "443,8000-9000", in: []uint16{443, 8000, 8500, 9000}, out: []uint16{442, 7999, 9001}},
		{value: "1-65535", in: []uint16{1, 22, 65535}, out: []uint16{0}},
		{value: "5-5", in: []uint16{5}, out: []uint16{4, 6}},
		{value: "0", wantFail: true},
		{value: "0-10", wantFail: true},
		{value: "10-5", wantFail: true},
		{value: "1-65536", wantFail: true},
		{value: "80-", wantFail: true},
		{value: "-80", wantFail: true},
		{value: "80,,81", wantFail: true},
		{value: "http", wantFail: true},
	} {
		pinned, err := parsePinnedPorts(test.value)
		if test.wantFail {
			if err == nil {
				t.Errorf("%q: want an error", test.value)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", test.value, err)
			continue
		}
		for _, port := range test.in {
			if !pinned.has(port) {
				t.Errorf("%q: port %d should be pinned", test.value, port)
			}
		}
		for _, port := range test.out {
			if pinned.has(port) {
				t.Errorf("%q: port %d should not be pinned", test.value, port)
			}
		}
	}
	if pinned, err := parsePinnedPorts(""); err != nil || !pinned.empty() {
		t.Errorf("empty value: got %v, %v", pinned.empty(), err)
	}
}

func TestJoinAddress(t *testing.T) {
	for _, test := range []struct {
		target string
		viaTUN bool
		want   string
	}{
		{"127.0.0.1:8081", false, "127.0.0.1:8081"},
		{"[::1]:8081", false, "[::1]:8081"},
		{"127.0.0.1:8081", true, guestAddr4 + ":8081"},
		{"[::1]:8081", true, "[" + guestAddr6 + "]:8081"},
	} {
		if got := joinAddress(test.target, test.viaTUN); got != test.want {
			t.Errorf("joinAddress(%q, %v) = %q, want %q", test.target, test.viaTUN, got, test.want)
		}
	}
}
