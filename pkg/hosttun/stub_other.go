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

package hosttun

import (
	"context"
	"errors"
	"io"
)

// IsWorkerEnv always reports false on non-Linux hosts.
func IsWorkerEnv() bool { return false }

// RunWorker returns an error on non-Linux hosts.
func RunWorker() error {
	return errors.New("host-tun worker requires Linux")
}

// ServeSocket returns an error on non-Linux hosts.
func ServeSocket(context.Context, string) error {
	return errors.New("host-tun stack server requires Linux")
}

// Manager is a non-Linux stub.
type Manager struct{}

// NewManager returns a stub Manager on non-Linux hosts.
func NewManager(ManagerConfig) *Manager { return &Manager{} }

// Attach returns an error on non-Linux hosts.
func (*Manager) Attach(AttachConfig) (io.Closer, error) {
	return nil, errors.New("host-tun worker requires Linux")
}

// WorkerPID always returns 0 on non-Linux hosts.
func (*Manager) WorkerPID(string) int { return 0 }

// Close is a no-op on non-Linux hosts.
func (*Manager) Close() error { return nil }
