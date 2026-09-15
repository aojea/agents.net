package netnsproxy

import (
	"net"
	"os"
	"sync"
	"time"
)

type packetFlow struct {
	socket   *net.UDPConn
	peer     *net.UDPAddr
	packets  chan []byte
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	deadline time.Time
	changed  chan struct{}
}

func (f *packetFlow) Read(buf []byte) (int, error) {
	for {
		f.mu.Lock()
		deadline, changed := f.deadline, f.changed
		f.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			if !deadline.After(time.Now()) {
				return 0, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		select {
		case <-f.done:
			if timer != nil {
				timer.Stop()
			}
			return 0, net.ErrClosed
		case packet := <-f.packets:
			if timer != nil {
				timer.Stop()
			}
			return copy(buf, packet), nil
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
		}
	}
}

func (f *packetFlow) Write(packet []byte) (int, error) {
	select {
	case <-f.done:
		return 0, net.ErrClosed
	default:
	}
	return f.socket.Write(packet)
}

func (f *packetFlow) Close() error {
	f.once.Do(func() {
		close(f.done)
		if f.socket != nil {
			f.socket.Close()
		}
	})
	return nil
}

func (f *packetFlow) LocalAddr() net.Addr  { return f.socket.LocalAddr() }
func (f *packetFlow) RemoteAddr() net.Addr { return f.peer }

func (f *packetFlow) SetReadDeadline(deadline time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deadline = deadline
	close(f.changed)
	f.changed = make(chan struct{})
	return nil
}

func (f *packetFlow) SetWriteDeadline(time.Time) error { return os.ErrNoDeadline }
func (f *packetFlow) SetDeadline(time.Time) error      { return os.ErrNoDeadline }
