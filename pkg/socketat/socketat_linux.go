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

//go:build linux

// Package socketat creates sockets and net.Listeners inside a target Linux
// network namespace without leaking namespace state across Go goroutines,
// following the mechanism from https://github.com/aojea/socketat.
package socketat

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

// ListenAtPath opens netnsPath and binds a net.Listener inside that network
// namespace. Accepted connections remain confined to the target namespace while
// Accept and I/O run safely on ordinary host goroutines.
func ListenAtPath(netnsPath, network, address string) (net.Listener, error) {
	f, err := os.Open(netnsPath)
	if err != nil {
		return nil, fmt.Errorf("open network namespace %q: %w", netnsPath, err)
	}
	defer func() { _ = f.Close() }()
	return ListenAt(int(f.Fd()), network, address)
}

// ListenAt binds a net.Listener inside the network namespace referenced by nsFD.
// Address must use a literal IP:port (such as 127.0.0.1:15001) so Listen executes
// synchronously on the locked OS thread without triggering async DNS resolution.
func ListenAt(nsFD int, network, address string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil {
		return nil, fmt.Errorf("socketat.ListenAt requires literal IP:port, got %q", address)
	}
	var ln net.Listener
	err = DoAtNS(nsFD, func() error {
		var lerr error
		ln, lerr = net.Listen(network, address)
		return lerr
	})
	if err != nil {
		if ln != nil {
			_ = ln.Close()
		}
		return nil, err
	}
	return ln, nil
}

// DialAtPath opens netnsPath and dials address inside that network namespace.
// Address must use a literal IP (such as 127.0.0.1:<port>) so Dial executes
// synchronously on the locked OS thread without spawning a DNS goroutine.
func DialAtPath(netnsPath, network, address string, timeout time.Duration) (net.Conn, error) {
	f, err := os.Open(netnsPath)
	if err != nil {
		return nil, fmt.Errorf("open network namespace %q: %w", netnsPath, err)
	}
	defer func() { _ = f.Close() }()
	return DialAt(int(f.Fd()), network, address, timeout)
}

// DialAt dials a literal IP:port inside the network namespace referenced by nsFD.
// The returned net.Conn stays bound to the target namespace while I/O runs on
// ordinary host goroutines.
func DialAt(nsFD int, network, address string, timeout time.Duration) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil {
		return nil, fmt.Errorf("socketat.DialAt requires literal IP:port, got %q", address)
	}
	var conn net.Conn
	err = DoAtNS(nsFD, func() error {
		d := net.Dialer{
			Timeout:       timeout,
			FallbackDelay: -1,
		}
		var derr error
		conn, derr = d.Dial(network, address)
		return derr
	})
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, err
	}
	return conn, nil
}

// DoAtNSPath opens netnsPath and executes fn synchronously on a locked OS thread
// inside that network namespace. fn must not spawn goroutines that rely on the
// target namespace because spawned goroutines may schedule onto other OS threads.
func DoAtNSPath(netnsPath string, fn func() error) error {
	f, err := os.Open(netnsPath)
	if err != nil {
		return fmt.Errorf("open network namespace %q: %w", netnsPath, err)
	}
	defer func() { _ = f.Close() }()
	return DoAtNS(int(f.Fd()), fn)
}

// DoAtNS executes fn synchronously inside the network namespace referenced by nsFD
// on a dedicated goroutine locked to an OS thread, restoring the thread's original
// network namespace before unlocking. If restoring the original namespace fails or
// fn panics while entered, the goroutine exits without calling UnlockOSThread so
// the Go runtime terminates the tainted OS thread instead of returning it to the pool.
func DoAtNS(nsFD int, fn func() error) error {
	type result struct {
		err      error
		panicked bool
		panicVal any
	}
	resCh := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		entered := false
		restored := false
		var res result
		defer func() {
			if r := recover(); r != nil {
				res.panicked = true
				res.panicVal = r
			}
			// Only unlock and return this OS thread to the Go runtime pool if it is
			// guaranteed to be in its original network namespace.
			if !entered || restored {
				runtime.UnlockOSThread()
			}
			resCh <- res
		}()

		originPath := fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid())
		originFile, err := os.Open(originPath)
		if err != nil {
			res.err = fmt.Errorf("open current thread netns %q: %w", originPath, err)
			return
		}
		defer func() { _ = originFile.Close() }()

		if err := unix.Setns(nsFD, unix.CLONE_NEWNET); err != nil {
			res.err = fmt.Errorf("enter target netns: %w", err)
			return
		}
		entered = true

		fnErr := fn()
		if restoreErr := unix.Setns(int(originFile.Fd()), unix.CLONE_NEWNET); restoreErr != nil {
			if fnErr != nil {
				res.err = fmt.Errorf("%w (also failed restoring original netns: %v)", fnErr, restoreErr)
			} else {
				res.err = fmt.Errorf("restore original netns: %w", restoreErr)
			}
			return
		}
		restored = true
		res.err = fnErr
	}()

	res := <-resCh
	if res.panicked {
		panic(res.panicVal)
	}
	return res.err
}
