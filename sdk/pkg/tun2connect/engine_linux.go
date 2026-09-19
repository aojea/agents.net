//go:build linux

package tun2connect

import (
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// NewTUNDevice wraps an already-open tun file descriptor (raw IP, no
// ethernet framing) as the engine's link endpoint.
func NewTUNDevice(fd int, mtu uint32) (stack.LinkEndpoint, error) {
	return fdbased.New(&fdbased.Options{FDs: []int{fd}, MTU: mtu})
}
