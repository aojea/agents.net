package main

import (
	"testing"
)

func TestBoundaryDialerSchemes(t *testing.T) {
	tests := []struct {
		proxy   string
		wantErr bool
	}{
		{"unix:///tmp/test.sock", false},
		{"tcp://127.0.0.1:8080", false},
		{"vsock://2:10050", false},
		{"http://127.0.0.1:8080", true},
		{"vsock://invalid", true},
		{"://invalid-url", true},
	}

	for _, tt := range tests {
		dial, err := boundaryDialer(tt.proxy)
		if (err != nil) != tt.wantErr {
			t.Errorf("boundaryDialer(%q) error = %v, wantErr %v", tt.proxy, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && dial == nil {
			t.Errorf("boundaryDialer(%q) returned nil dialer without error", tt.proxy)
		}
	}
}

func TestDialVSOCKInvalidAddresses(t *testing.T) {
	badAddrs := []string{
		"only-port",
		"not-a-number:1000",
		"2:not-a-number",
		"1:2:3",
	}

	for _, addr := range badAddrs {
		_, err := dialVSOCK(addr)
		if err == nil {
			t.Errorf("dialVSOCK(%q) expected error, got nil", addr)
		}
	}
}
