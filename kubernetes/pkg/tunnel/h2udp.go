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
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

var errExtendedConnectNotSupported = errors.New("PEP does not advertise HTTP/2 extended CONNECT (SETTINGS_ENABLE_CONNECT_PROTOCOL)")

const (
	defaultH2InitialWindow = 65535
	defaultH2MaxFrameSize  = 16384
)

// dialH2ConnectUDP opens an RFC 9298 / RFC 8441 HTTP/2 extended CONNECT
// (:protocol: connect-udp) stream using http2.Framer + hpack directly so that
// it works across Go versions (including Go 1.27 where net/http.Transport
// rejects the ":protocol" pseudo-header key; go.dev/issue/53208).
func (u *upstreamDialer) dialH2ConnectUDP(ctx context.Context, host, port string, hdrs http.Header) (*upstreamTunnel, error) {
	conn, err := u.dialRawUpstreamConn(ctx, []string{"h2", "http/1.1"})
	if err != nil {
		return nil, err
	}
	tlsConn, ok := conn.(*tls.Conn)
	if !ok || tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		_ = conn.Close()
		u.useH1.Store(true)
		return nil, errALPNFallbackHTTP1
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stopCancel := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})

	abort := func(retErr error) (*upstreamTunnel, error) {
		_ = stopCancel()
		_ = conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, retErr
	}

	bw := bufio.NewWriter(conn)
	br := bufio.NewReader(conn)
	fr := http2.NewFramer(bw, br)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	fr.SetMaxReadFrameSize(1 << 20)

	if _, err := bw.WriteString(http2.ClientPreface); err != nil {
		return abort(err)
	}
	if err := fr.WriteSettings(); err != nil {
		return abort(err)
	}
	if err := bw.Flush(); err != nil {
		return abort(err)
	}

	// Read server initial SETTINGS before sending extended CONNECT (RFC 8441 Section 3).
	initialWin := int64(defaultH2InitialWindow)
	maxFrame := defaultH2MaxFrameSize
	connWin := int64(defaultH2InitialWindow)
	gotServerSettings := false
	for !gotServerSettings {
		f, err := fr.ReadFrame()
		if err != nil {
			return abort(err)
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if f.IsAck() {
				continue
			}
			gotServerSettings = true
			val, hasExt := f.Value(http2.SettingEnableConnectProtocol)
			if !hasExt || val != 1 {
				u.useH1UDP.Store(true)
				return abort(errExtendedConnectNotSupported)
			}
			if v, ok := f.Value(http2.SettingInitialWindowSize); ok {
				initialWin = int64(v)
			}
			if v, ok := f.Value(http2.SettingMaxFrameSize); ok && v >= defaultH2MaxFrameSize {
				maxFrame = int(v)
			}
			if err := fr.WriteSettingsAck(); err != nil {
				return abort(err)
			}
			if err := bw.Flush(); err != nil {
				return abort(err)
			}
		case *http2.WindowUpdateFrame:
			if f.StreamID == 0 {
				connWin += int64(f.Increment)
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				if err := fr.WritePing(true, f.Data); err != nil {
					return abort(err)
				}
				if err := bw.Flush(); err != nil {
					return abort(err)
				}
			}
		case *http2.GoAwayFrame:
			return abort(fmt.Errorf("PEP sent GOAWAY during H2 setup: %v", f.ErrCode))
		}
	}

	// Encode RFC 8441 + RFC 9298 extended CONNECT headers on Stream 1.
	var hbuf bytes.Buffer
	enc := hpack.NewEncoder(&hbuf)
	targetPath := fmt.Sprintf("%s%s/%s/", udpTargetPrefix, encodeConnectUDPHost(host), url.PathEscape(port))
	writeField := func(name, value string) error {
		return enc.WriteField(hpack.HeaderField{Name: name, Value: value})
	}
	for _, pf := range [][2]string{
		{":method", http.MethodConnect},
		{":protocol", "connect-udp"},
		{":scheme", "https"},
		{":authority", u.target.host},
		{":path", targetPath},
		{"capsule-protocol", "?1"},
	} {
		if err := writeField(pf[0], pf[1]); err != nil {
			return abort(err)
		}
	}

	keys := make([]string, 0, len(hdrs))
	for k := range hdrs {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		lower := strings.ToLower(k)
		if !isValidHTTPToken(lower) || lower == "host" || lower == "connection" || lower == "upgrade" || lower == "capsule-protocol" {
			continue
		}
		for _, v := range hdrs[k] {
			if !isSafeHeaderValue(v) {
				continue
			}
			if err := writeField(lower, v); err != nil {
				return abort(err)
			}
		}
	}

	block := hbuf.Bytes()
	if err := writeHeaderBlock(fr, 1, block, maxFrame); err != nil {
		return abort(err)
	}
	if err := bw.Flush(); err != nil {
		return abort(err)
	}

	streamWin := initialWin
	interimCount := 0
	var respStatus int
	var respProxyStatus string
	var streamEnded bool
	for respStatus == 0 {
		f, err := fr.ReadFrame()
		if err != nil {
			return abort(err)
		}
		switch f := f.(type) {
		case *http2.MetaHeadersFrame:
			if f.StreamID != 1 {
				continue
			}
			var statusCode int
			var proxyStatus string
			for _, hf := range f.Fields {
				switch hf.Name {
				case ":status":
					statusCode, _ = strconv.Atoi(hf.Value)
				case "proxy-status":
					proxyStatus = hf.Value
				}
			}
			if statusCode >= 100 && statusCode < 200 {
				interimCount++
				if interimCount > maxInterimResponses {
					return abort(fmt.Errorf("PEP sent more than %d interim responses", maxInterimResponses))
				}
				continue
			}
			if statusCode == 0 {
				return abort(errors.New("PEP H2 response missing :status"))
			}
			respStatus = statusCode
			respProxyStatus = proxyStatus
			streamEnded = f.StreamEnded()
		case *http2.SettingsFrame:
			if !f.IsAck() {
				if v, ok := f.Value(http2.SettingInitialWindowSize); ok {
					delta := int64(v) - initialWin
					initialWin = int64(v)
					streamWin += delta
				}
				if v, ok := f.Value(http2.SettingMaxFrameSize); ok && v >= defaultH2MaxFrameSize {
					maxFrame = int(v)
				}
				if err := fr.WriteSettingsAck(); err != nil {
					return abort(err)
				}
				if err := bw.Flush(); err != nil {
					return abort(err)
				}
			}
		case *http2.WindowUpdateFrame:
			switch f.StreamID {
			case 0:
				connWin += int64(f.Increment)
			case 1:
				streamWin += int64(f.Increment)
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				if err := fr.WritePing(true, f.Data); err != nil {
					return abort(err)
				}
				if err := bw.Flush(); err != nil {
					return abort(err)
				}
			}
		case *http2.RSTStreamFrame:
			if f.StreamID == 1 {
				return abort(fmt.Errorf("PEP reset connect-udp stream: %v", f.ErrCode))
			}
		case *http2.GoAwayFrame:
			return abort(fmt.Errorf("PEP sent GOAWAY: %v", f.ErrCode))
		}
	}

	if !stopCancel() {
		_ = conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("dial cancelled")
	}
	_ = conn.SetDeadline(time.Time{})

	if respStatus < 200 || respStatus > 299 {
		_ = conn.Close()
		return nil, &upstreamDeniedError{
			status:      respStatus,
			proxyStatus: respProxyStatus,
			reason:      "upstream-denied",
		}
	}

	stream := newH2UDPStream(conn, bw, fr, maxFrame, connWin, streamWin, initialWin, streamEnded)
	return &upstreamTunnel{
		r:     stream.pr,
		w:     stream,
		close: func() { _ = stream.Close() },
	}, nil
}

func writeHeaderBlock(fr *http2.Framer, streamID uint32, block []byte, maxFrame int) error {
	if len(block) <= maxFrame {
		return fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: block,
			EndHeaders:    true,
		})
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: block[:maxFrame],
		EndHeaders:    false,
	}); err != nil {
		return err
	}
	rest := block[maxFrame:]
	for len(rest) > 0 {
		n := min(len(rest), maxFrame)
		end := n == len(rest)
		if err := fr.WriteContinuation(streamID, end, rest[:n]); err != nil {
			return err
		}
		rest = rest[n:]
	}
	return nil
}

type h2UDPStream struct {
	conn net.Conn
	bw   *bufio.Writer
	fr   *http2.Framer
	pr   *io.PipeReader
	pw   *io.PipeWriter

	writeMu   sync.Mutex
	sentEnd   bool
	closeOnce sync.Once
	readDone  chan struct{}

	winMu      sync.Mutex
	winCond    *sync.Cond
	connWin    int64
	streamWin  int64
	initialWin int64
	maxFrame   int
	closed     bool
}

func newH2UDPStream(conn net.Conn, bw *bufio.Writer, fr *http2.Framer, maxFrame int, connWin, streamWin, initialWin int64, streamEnded bool) *h2UDPStream {
	pr, pw := io.Pipe()
	s := &h2UDPStream{
		conn:       conn,
		bw:         bw,
		fr:         fr,
		pr:         pr,
		pw:         pw,
		readDone:   make(chan struct{}),
		connWin:    connWin,
		streamWin:  streamWin,
		initialWin: initialWin,
		maxFrame:   maxFrame,
	}
	s.winCond = sync.NewCond(&s.winMu)
	if streamEnded {
		_ = pw.Close()
		close(s.readDone)
		return s
	}
	go s.readLoop()
	return s
}

func (s *h2UDPStream) readLoop() {
	defer close(s.readDone)
	var pipeErr error
	defer func() {
		s.winMu.Lock()
		s.closed = true
		s.winCond.Broadcast()
		s.winMu.Unlock()
		if pipeErr != nil {
			_ = s.pw.CloseWithError(pipeErr)
		} else {
			_ = s.pw.Close()
		}
	}()

	for {
		f, err := s.fr.ReadFrame()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				pipeErr = err
			}
			return
		}
		switch f := f.(type) {
		case *http2.DataFrame:
			if f.StreamID != 1 {
				continue
			}
			data := f.Data()
			if len(data) > 0 {
				if _, werr := s.pw.Write(data); werr != nil {
					return
				}
				inc := uint32(len(data))
				s.writeMu.Lock()
				_ = s.fr.WriteWindowUpdate(0, inc)
				_ = s.fr.WriteWindowUpdate(1, inc)
				_ = s.bw.Flush()
				s.writeMu.Unlock()
			}
			if f.StreamEnded() {
				return
			}
		case *http2.WindowUpdateFrame:
			s.winMu.Lock()
			switch f.StreamID {
			case 0:
				s.connWin += int64(f.Increment)
			case 1:
				s.streamWin += int64(f.Increment)
			}
			s.winCond.Broadcast()
			s.winMu.Unlock()
		case *http2.SettingsFrame:
			if !f.IsAck() {
				s.winMu.Lock()
				if v, ok := f.Value(http2.SettingInitialWindowSize); ok {
					delta := int64(v) - s.initialWin
					s.initialWin = int64(v)
					s.streamWin += delta
				}
				if v, ok := f.Value(http2.SettingMaxFrameSize); ok && v >= defaultH2MaxFrameSize {
					s.maxFrame = int(v)
				}
				s.winCond.Broadcast()
				s.winMu.Unlock()

				s.writeMu.Lock()
				_ = s.fr.WriteSettingsAck()
				_ = s.bw.Flush()
				s.writeMu.Unlock()
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				s.writeMu.Lock()
				_ = s.fr.WritePing(true, f.Data)
				_ = s.bw.Flush()
				s.writeMu.Unlock()
			}
		case *http2.RSTStreamFrame:
			if f.StreamID == 1 {
				pipeErr = fmt.Errorf("H2 connect-udp stream reset: %v", f.ErrCode)
				return
			}
		case *http2.GoAwayFrame:
			return
		}
	}
}

func (s *h2UDPStream) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		s.winMu.Lock()
		for !s.closed && (s.connWin <= 0 || s.streamWin <= 0) {
			s.winCond.Wait()
		}
		if s.closed {
			s.winMu.Unlock()
			return written, net.ErrClosed
		}
		chunk := min(len(p), s.maxFrame)
		if int64(chunk) > s.connWin {
			chunk = int(s.connWin)
		}
		if int64(chunk) > s.streamWin {
			chunk = int(s.streamWin)
		}
		s.connWin -= int64(chunk)
		s.streamWin -= int64(chunk)
		s.winMu.Unlock()

		s.writeMu.Lock()
		if s.sentEnd {
			s.writeMu.Unlock()
			return written, net.ErrClosed
		}
		err := s.fr.WriteData(1, false, p[:chunk])
		if err == nil {
			err = s.bw.Flush()
		}
		s.writeMu.Unlock()
		if err != nil {
			return written, err
		}
		written += chunk
		p = p[chunk:]
	}
	return written, nil
}

func (s *h2UDPStream) CloseWrite() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.sentEnd {
		return nil
	}
	s.sentEnd = true
	if err := s.fr.WriteData(1, true, nil); err != nil {
		return err
	}
	return s.bw.Flush()
}

func (s *h2UDPStream) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.winMu.Lock()
		s.closed = true
		s.winCond.Broadcast()
		s.winMu.Unlock()
		_ = s.pw.Close()
		_ = s.pr.Close()
		err = s.conn.Close()
		<-s.readDone
	})
	return err
}
