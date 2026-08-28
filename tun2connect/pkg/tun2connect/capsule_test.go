package tun2connect

import (
	"bytes"
	"testing"
)

func TestCapsuleRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	s := NewCapsuleStream(&buf)
	// Sizes chosen to cross the 1/2/4-byte varint boundaries.
	for _, n := range []int{0, 1, 62, 63, 1000, 16382, 16383, 65000} {
		payload := bytes.Repeat([]byte{0xab}, n)
		if err := s.WriteDatagram(payload); err != nil {
			t.Fatalf("write %d bytes: %v", n, err)
		}
		got, err := s.ReadDatagram()
		if err != nil {
			t.Fatalf("read %d bytes: %v", n, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("roundtrip of %d bytes corrupted (got %d)", n, len(got))
		}
	}
}

func TestCapsuleSkipsUnknownTypesAndContexts(t *testing.T) {
	var buf bytes.Buffer
	// An unknown capsule type, then a datagram with non-zero context,
	// then a real one: readers MUST skip the first two (RFC 9297).
	raw := appendVarint(nil, 0x17)
	raw = appendVarint(raw, 3)
	raw = append(raw, "junk"[:3]...)
	buf.Write(raw)
	weird := appendVarint(nil, capsuleTypeDatagram)
	weird = appendVarint(weird, 3)
	weird = appendVarint(weird, 5) // context ID 5: not ours
	weird = append(weird, 0xff, 0xff)
	buf.Write(weird)
	s := NewCapsuleStream(&buf)
	if err := s.WriteDatagram([]byte("real")); err != nil {
		t.Fatal(err)
	}
	got, err := s.ReadDatagram()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "real" {
		t.Fatalf("got %q, want %q", got, "real")
	}
}

func TestCapsuleRejectsOversizedLength(t *testing.T) {
	var buf bytes.Buffer
	raw := appendVarint(nil, capsuleTypeDatagram)
	raw = appendVarint(raw, 1<<20)
	buf.Write(raw)
	s := NewCapsuleStream(&buf)
	if _, err := s.ReadDatagram(); err == nil {
		t.Fatal("oversized capsule length must be rejected")
	}
}
