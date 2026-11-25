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

//go:build !linux

package socketat

import (
	"errors"
	"net"
	"time"
)

var errUnsupportedOS = errors.New("socketat network namespace operations require Linux")

// ListenAtPath returns an error on non-Linux platforms.
func ListenAtPath(_, _, _ string) (net.Listener, error) {
	return nil, errUnsupportedOS
}

// ListenAt returns an error on non-Linux platforms.
func ListenAt(_ int, _, _ string) (net.Listener, error) {
	return nil, errUnsupportedOS
}

// DialAtPath returns an error on non-Linux platforms.
func DialAtPath(_, _, _ string, _ time.Duration) (net.Conn, error) {
	return nil, errUnsupportedOS
}

// DialAt returns an error on non-Linux platforms.
func DialAt(_ int, _, _ string, _ time.Duration) (net.Conn, error) {
	return nil, errUnsupportedOS
}

// DoAtNSPath returns an error on non-Linux platforms.
func DoAtNSPath(_ string, _ func() error) error {
	return errUnsupportedOS
}

// DoAtNS returns an error on non-Linux platforms.
func DoAtNS(_ int, _ func() error) error {
	return errUnsupportedOS
}
