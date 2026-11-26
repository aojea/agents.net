package tun2connect

import (
	"io"
	"sync"
	"time"
)

// time0 clears a net.Conn deadline.
var time0 time.Time

type closeWriter interface{ CloseWrite() error }

// relay copies both directions until each side has seen EOF,
// propagating half-close where the conn supports it.
func relay(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	cp := func(dst, src io.ReadWriteCloser) {
		defer wg.Done()
		io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
			src.Close()
		}
	}
	wg.Add(2)
	go cp(a, b)
	cp(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}
