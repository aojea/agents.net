package netnsproxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

const socketOriginalDestination = 80

func originalDestination(conn *net.TCPConn) (netip.AddrPort, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var destination netip.AddrPort
	var socketErr error
	err = raw.Control(func(fd uintptr) {
		local := conn.LocalAddr().(*net.TCPAddr).AddrPort()
		if local.Addr().Is4() {
			address, err := unix.GetsockoptIPv6Mreq(int(fd), unix.SOL_IP, socketOriginalDestination)
			socketErr = err
			if err == nil {
				destination = netip.AddrPortFrom(netip.AddrFrom4([4]byte(address.Multiaddr[4:8])), binary.BigEndian.Uint16(address.Multiaddr[2:4]))
			}
		} else {
			address, err := unix.GetsockoptIPv6MTUInfo(int(fd), unix.SOL_IPV6, socketOriginalDestination)
			socketErr = err
			if err == nil {
				port := binary.BigEndian.Uint16(binary.NativeEndian.AppendUint16(nil, address.Addr.Port))
				destination = netip.AddrPortFrom(netip.AddrFrom16(address.Addr.Addr), port)
			}
		}
	})
	if err != nil {
		return netip.AddrPort{}, err
	}
	return destination, socketErr
}

func udpOptions(ipv6 bool) func(string, string, syscall.RawConn) error {
	return func(network, address string, raw syscall.RawConn) error {
		var socketErr error
		err := raw.Control(func(fd uintptr) {
			level, original := unix.SOL_IP, unix.IP_RECVORIGDSTADDR
			if ipv6 {
				level, original = unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR
			}
			if socketErr = unix.SetsockoptInt(int(fd), level, original, 1); socketErr != nil {
				return
			}
			option := unix.IP_TRANSPARENT
			if ipv6 {
				option = unix.IPV6_TRANSPARENT
			}
			socketErr = unix.SetsockoptInt(int(fd), level, option, 1)
		})
		if err != nil {
			return err
		}
		return socketErr
	}
}

func replySocket(peer *net.UDPAddr, destination netip.AddrPort) (*net.UDPConn, error) {
	network := "udp4"
	if destination.Addr().Is6() {
		network = "udp6"
	}
	config := net.Dialer{LocalAddr: net.UDPAddrFromAddrPort(destination),
		Control: func(network, address string, raw syscall.RawConn) error {
			var socketErr error
			err := raw.Control(func(fd uintptr) {
				level, option := unix.SOL_IP, unix.IP_TRANSPARENT
				if destination.Addr().Is6() {
					level, option = unix.SOL_IPV6, unix.IPV6_TRANSPARENT
				}
				if socketErr = unix.SetsockoptInt(int(fd), level, option, 1); socketErr == nil {
					socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				}
			})
			if err != nil {
				return err
			}
			return socketErr
		}}
	conn, err := config.Dial(network, peer.String())
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}

func packetDestination(control []byte) (netip.AddrPort, error) {
	messages, err := unix.ParseSocketControlMessage(control)
	if err != nil {
		return netip.AddrPort{}, err
	}
	var destination netip.AddrPort
	for _, message := range messages {
		switch {
		case message.Header.Level == unix.SOL_IP && message.Header.Type == unix.IP_ORIGDSTADDR && len(message.Data) >= unix.SizeofSockaddrInet4:
			destination = netip.AddrPortFrom(netip.AddrFrom4([4]byte(message.Data[4:8])), binary.BigEndian.Uint16(message.Data[2:4]))
		case message.Header.Level == unix.SOL_IPV6 && message.Header.Type == unix.IPV6_ORIGDSTADDR && len(message.Data) >= unix.SizeofSockaddrInet6:
			destination = netip.AddrPortFrom(netip.AddrFrom16([16]byte(message.Data[8:24])), binary.BigEndian.Uint16(message.Data[2:4]))
		}
	}
	if !destination.IsValid() || destination.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("netnsproxy: missing original destination")
	}
	return destination, nil
}
