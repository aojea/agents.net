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

package driver

import (
	"errors"
	"net"
)

type unsupportedNetNSManager struct{}

// NewLinuxNetNSManager returns a stub NetNSManager on non-Linux hosts.
func NewLinuxNetNSManager() NetNSManager {
	return unsupportedNetNSManager{}
}

func (unsupportedNetNSManager) VerifyLoopbackOnly(string, bool) error {
	return errors.New("network namespace verification requires Linux")
}

func (unsupportedNetNSManager) FlushNonLoopbackRoutes(string) error {
	return errors.New("network namespace route flush requires Linux")
}

func (unsupportedNetNSManager) HasNonLoopbackRoutes(string) (bool, error) {
	return false, errors.New("network namespace route inspection requires Linux")
}

func (unsupportedNetNSManager) BlockNonLoopbackNICs(string, bool) error {
	return errors.New("network namespace tc NIC blocking requires Linux")
}

func (unsupportedNetNSManager) VerifyNonLoopbackNICsBlocked(string, bool) (bool, error) {
	return false, errors.New("network namespace tc NIC verification requires Linux")
}

func (unsupportedNetNSManager) ListenAt(string, string, string) (net.Listener, error) {
	return nil, errors.New("socketat network namespace listener requires Linux")
}
