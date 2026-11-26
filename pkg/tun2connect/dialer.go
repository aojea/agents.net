package tun2connect

import (
	"context"
	"fmt"
	"net"
)

// Dialer opens one tunnel per guest flow. The destination is a hostname
// recovered from virtual DNS, or an IP literal when no mapping exists.
type Dialer interface {
	DialTCP(ctx context.Context, host string, port uint16) (net.Conn, error)
	DialUDP(ctx context.Context, host string, port uint16) (DatagramConn, error)
}

// DatagramConn is one authorized UDP session. Datagram boundaries are
// preserved end-to-end; delivery and ordering are not guaranteed.
type DatagramConn interface {
	WriteDatagram(p []byte) error
	ReadDatagram() ([]byte, error)
	Close() error
}

// DialError is a boundary refusal (e.g. 403 for a name off the
// allow-list), distinct from transport failures: the engine turns it
// into an ordinary connection refusal in the guest.
type DialError struct {
	StatusCode int
	Status     string
	Reason     string // Proxy-Status reason parameter, if the boundary sent one
}

func (e *DialError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("boundary refused: %s (%s)", e.Status, e.Reason)
	}
	return fmt.Sprintf("boundary refused: %s", e.Status)
}
