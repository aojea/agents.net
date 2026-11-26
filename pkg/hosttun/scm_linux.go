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

package hosttun

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// newSeqPacketPair creates a non-blocking, close-on-exec AF_UNIX SOCK_SEQPACKET
// socketpair wrapped in *os.File so Go's epoll poller handles deadlines and
// instant wakeups on Close().
func newSeqPacketPair(nameA, nameB string) (*os.File, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("socketpair(SOCK_SEQPACKET): %w", err)
	}
	return os.NewFile(uintptr(fds[0]), nameA), os.NewFile(uintptr(fds[1]), nameB), nil
}

// sendMsgWithFDs sends one SOCK_SEQPACKET datagram with optional SCM_RIGHTS FDs.
func sendMsgWithFDs(f *os.File, payload []byte, fds ...int) error {
	raw, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var oob []byte
	if len(fds) > 0 {
		oob = unix.UnixRights(fds...)
	}
	var sendErr error
	ctrlErr := raw.Write(func(fd uintptr) bool {
		err := unix.Sendmsg(int(fd), payload, oob, nil, unix.MSG_NOSIGNAL)
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
			return false
		}
		sendErr = err
		return true
	})
	if ctrlErr != nil {
		return ctrlErr
	}
	return sendErr
}

// recvMsgWithFDs receives one SOCK_SEQPACKET datagram and up to maxFDs SCM_RIGHTS FDs
// atomically marked close-on-exec via MSG_CMSG_CLOEXEC.
func recvMsgWithFDs(f *os.File, maxPayload, maxFDs int) ([]byte, []int, error) {
	raw, err := f.SyscallConn()
	if err != nil {
		return nil, nil, err
	}
	buf := make([]byte, maxPayload)
	var oob []byte
	if maxFDs > 0 {
		oob = make([]byte, unix.CmsgSpace(maxFDs*4))
	}

	var (
		n       int
		oobn    int
		flags   int
		recvErr error
	)
	ctrlErr := raw.Read(func(fd uintptr) bool {
		var err error
		n, oobn, flags, _, err = unix.Recvmsg(int(fd), buf, oob, unix.MSG_CMSG_CLOEXEC)
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
			return false
		}
		recvErr = err
		return true
	})
	if ctrlErr != nil {
		return nil, nil, ctrlErr
	}
	if recvErr != nil {
		return nil, nil, recvErr
	}
	if n == 0 && oobn == 0 {
		return nil, nil, io.EOF
	}

	var fds []int
	if oobn > 0 {
		cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			return nil, nil, fmt.Errorf("parse control message: %w", err)
		}
		for _, cm := range cmsgs {
			parsed, err := unix.ParseUnixRights(&cm)
			if err != nil {
				closeFDs(fds)
				return nil, nil, fmt.Errorf("parse SCM_RIGHTS: %w", err)
			}
			fds = append(fds, parsed...)
		}
	}
	if flags&unix.MSG_TRUNC != 0 || flags&unix.MSG_CTRUNC != 0 {
		closeFDs(fds)
		return nil, nil, errors.New("control message or ancillary FDs truncated")
	}
	return buf[:n], fds, nil
}

func closeFDs(fds []int) {
	for _, fd := range fds {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}
}
