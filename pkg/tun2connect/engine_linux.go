//go:build linux

package tun2connect

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// DefaultTAPMAC is the locally administered Ethernet address used by
// NewTAPDevice when the caller does not provide an explicit MAC address.
var DefaultTAPMAC = tcpip.LinkAddress("\x02\x61\x67\x6e\x74\x01")

// NewTUNDevice wraps an already-open tun file descriptor (raw IP, no
// ethernet framing) as the engine's link endpoint.
func NewTUNDevice(fd int, mtu uint32) (stack.LinkEndpoint, error) {
	return fdbased.New(&fdbased.Options{FDs: []int{fd}, MTU: mtu})
}

// NewTAPDevice wraps an already-open L2 Ethernet file descriptor (either a
// kernel IFF_TAP|IFF_NO_PI descriptor or a datagram/seqpacket socketpair such
// as QEMU -netdev dgram) as the engine's link endpoint with ARP/Ethernet framing.
func NewTAPDevice(fd int, mtu uint32, mac tcpip.LinkAddress) (stack.LinkEndpoint, error) {
	if len(mac) == 0 {
		mac = DefaultTAPMAC
	}
	return fdbased.New(&fdbased.Options{
		FDs:            []int{fd},
		MTU:            mtu,
		Address:        mac,
		EthernetHeader: true,
	})
}
