package tun2connect

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

// HTTP capsule types (RFC 9297): DATAGRAM carries one HTTP Datagram,
// whose payload for connect-udp is a context ID (0) plus the UDP
// payload (RFC 9298 section 5).
const capsuleTypeDatagram = 0x00

// maxCapsulePayload bounds a peer's declared capsule length so a
// malicious boundary cannot make us allocate unbounded memory.
const maxCapsulePayload = 1 << 16

// varints are QUIC variable-length integers (RFC 9000 section 16).

func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return binary.BigEndian.AppendUint16(b, uint16(v)|0x4000)
	case v < 1<<30:
		return binary.BigEndian.AppendUint32(b, uint32(v)|0x8000_0000)
	case v < 1<<62:
		return binary.BigEndian.AppendUint64(b, v|0xc000_0000_0000_0000)
	default:
		panic("varint overflow")
	}
}

func readVarint(r io.ByteReader) (uint64, error) {
	b0, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	v := uint64(b0 & 0x3f)
	for i := 1; i < 1<<(b0>>6); i++ {
		b, err := r.ReadByte()
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
		v = v<<8 | uint64(b)
	}
	return v, nil
}

// CapsuleStream frames HTTP Datagrams on a reliable stream, the form
// connect-udp takes when the transport is not QUIC -- e.g. HTTP/1.1
// over a Unix socket or vsock. It is exported so boundary (server)
// implementations can reuse the same codec.
type CapsuleStream struct {
	wmu sync.Mutex
	w   io.Writer
	r   *bufio.Reader
}

func NewCapsuleStream(rw io.ReadWriter) *CapsuleStream {
	return &CapsuleStream{w: rw, r: bufio.NewReader(rw)}
}

// WriteDatagram sends one UDP payload as a DATAGRAM capsule with
// context ID 0. Safe for concurrent writers.
func (s *CapsuleStream) WriteDatagram(p []byte) error {
	buf := make([]byte, 0, len(p)+8)
	buf = appendVarint(buf, capsuleTypeDatagram)
	buf = appendVarint(buf, uint64(len(p))+1) // +1: the context ID below
	buf = appendVarint(buf, 0)
	buf = append(buf, p...)
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, err := s.w.Write(buf)
	return err
}

// ReadDatagram returns the next UDP payload, skipping capsule types and
// datagram contexts it does not understand, as RFC 9297 requires.
func (s *CapsuleStream) ReadDatagram() ([]byte, error) {
	for {
		ctype, err := readVarint(s.r)
		if err != nil {
			return nil, err
		}
		clen, err := readVarint(s.r)
		if err != nil {
			return nil, err
		}
		if clen > maxCapsulePayload {
			return nil, fmt.Errorf("tun2connect: capsule of %d bytes exceeds limit", clen)
		}
		value := make([]byte, clen)
		if _, err := io.ReadFull(s.r, value); err != nil {
			return nil, err
		}
		if ctype != capsuleTypeDatagram {
			continue
		}
		rd := bytes.NewReader(value)
		ctxID, err := readVarint(rd)
		if err != nil {
			return nil, errors.New("tun2connect: malformed DATAGRAM capsule")
		}
		if ctxID != 0 {
			continue
		}
		return value[len(value)-rd.Len():], nil
	}
}
