// Copyright 2026 The Kubernetes Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tunnel

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	capsuleTypeDatagram  = 0
	maxCapsulePayloadLen = 65536
	maxSkippedCapsules   = 1024
)

var (
	errCapsuleTooLarge       = errors.New("capsule payload exceeds 65536 bytes")
	errVarintTooLarge        = errors.New("varint exceeds 62-bit QUIC maximum")
	errTooManySkippedCapsule = errors.New("exceeded maximum consecutive skipped capsules")
)

// CapsuleStream reads and writes RFC 9297/9298 HTTP Datagrams over an upgraded stream.
type CapsuleStream struct {
	r *bufio.Reader
	w io.Writer
}

// NewCapsuleStream wraps r and w as an RFC 9297/9298 capsule stream.
func NewCapsuleStream(r *bufio.Reader, w io.Writer) *CapsuleStream {
	return &CapsuleStream{r: r, w: w}
}

// ReadDatagram reads the next DATAGRAM (type 0, context ID 0) payload, skipping unknown
// capsule types per RFC 9297 Section 3.2.
func (c *CapsuleStream) ReadDatagram() ([]byte, error) {
	skipped := 0
	for {
		typ, err := readVarint(c.r)
		if err != nil {
			return nil, err
		}
		length, err := readVarint(c.r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		if length > maxCapsulePayloadLen {
			return nil, errCapsuleTooLarge
		}
		if typ != capsuleTypeDatagram {
			skipped++
			if skipped > maxSkippedCapsules {
				return nil, errTooManySkippedCapsule
			}
			if _, err := io.CopyN(io.Discard, c.r, int64(length)); err != nil {
				if errors.Is(err, io.EOF) {
					return nil, io.ErrUnexpectedEOF
				}
				return nil, err
			}
			continue
		}
		if length == 0 {
			return nil, errors.New("empty DATAGRAM capsule missing context ID")
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(c.r, payload); err != nil {
			if errors.Is(err, io.EOF) {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		ctxID, n, err := decodeVarintSlice(payload)
		if err != nil {
			return nil, fmt.Errorf("invalid DATAGRAM context ID: %w", err)
		}
		if ctxID != 0 {
			skipped++
			if skipped > maxSkippedCapsules {
				return nil, errTooManySkippedCapsule
			}
			continue
		}
		return payload[n:], nil
	}
}

// WriteDatagram writes a single RFC 9298 DATAGRAM capsule with context ID 0.
func (c *CapsuleStream) WriteDatagram(datagram []byte) error {
	if len(datagram)+1 > maxCapsulePayloadLen {
		return errCapsuleTooLarge
	}
	var hdr [16]byte
	n := 0
	n += putVarint(hdr[n:], capsuleTypeDatagram)
	n += putVarint(hdr[n:], uint64(len(datagram)+1))
	n += putVarint(hdr[n:], 0)
	if _, err := c.w.Write(hdr[:n]); err != nil {
		return err
	}
	_, err := c.w.Write(datagram)
	return err
}

func readVarint(r *bufio.Reader) (uint64, error) {
	first, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	prefix := first >> 6
	length := 1 << prefix
	val := uint64(first & 0x3f)
	for i := 1; i < length; i++ {
		b, err := r.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return 0, io.ErrUnexpectedEOF
			}
			return 0, err
		}
		val = (val << 8) | uint64(b)
	}
	return val, nil
}

func decodeVarintSlice(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	length := 1 << (b[0] >> 6)
	if len(b) < length {
		return 0, 0, io.ErrUnexpectedEOF
	}
	val := uint64(b[0] & 0x3f)
	for i := 1; i < length; i++ {
		val = (val << 8) | uint64(b[i])
	}
	return val, length, nil
}

func putVarint(dst []byte, v uint64) int {
	switch {
	case v < 1<<6:
		dst[0] = byte(v)
		return 1
	case v < 1<<14:
		binary.BigEndian.PutUint16(dst, uint16(v)|0x4000)
		return 2
	case v < 1<<30:
		binary.BigEndian.PutUint32(dst, uint32(v)|0x80000000)
		return 4
	case v < 1<<62:
		binary.BigEndian.PutUint64(dst, v|0xc000000000000000)
		return 8
	default:
		panic(errVarintTooLarge)
	}
}
