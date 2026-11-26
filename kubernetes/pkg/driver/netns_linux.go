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

package driver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/aojea/agents.net/kubernetes/pkg/socketat"
	"github.com/aojea/agents.net/sdk/pkg/tun2connect"
)

type linuxNetNSManager struct{}

// NewLinuxNetNSManager returns a NetNSManager backed by socketat and Linux netlink.
func NewLinuxNetNSManager() NetNSManager {
	return linuxNetNSManager{}
}

const (
	maxNetlinkDumpRetries = 5

	// tc filter priority and handle for dra-agents-net's non-loopback NIC blocker.
	// Priority 1 runs ahead of higher-numbered clsact filters on both ingress and egress.
	nicBlockFilterPriority uint16 = 1
	nicBlockFilterHandle   uint32 = 1

	hostTunDeviceName         = "tun0"
	hostTunMTU                = 1500
	hostTunReturnTable        = 100
	hostTunReturnRulePriority = 1000
)

func retryNetlinkDump[T any](fn func() (T, error)) (T, error) {
	var zero T
	for attempt := range maxNetlinkDumpRetries {
		res, err := fn()
		if err == nil {
			return res, nil
		}
		if !errors.Is(err, netlink.ErrDumpInterrupted) || attempt == maxNetlinkDumpRetries-1 {
			return zero, err
		}
	}
	return zero, netlink.ErrDumpInterrupted
}

func isFamilyUnsupported(err error) bool {
	return errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EOPNOTSUPP)
}

func isKernelFallbackTunnelType(linkType string) bool {
	switch linkType {
	case "sit", "ipip", "ip6tnl", "gre", "gretap", "ip6gre", "ip6gretap", "erspan", "ip6erspan":
		return true
	default:
		return false
	}
}

// shouldSkipLinkForIsolation reports whether link should be excluded from
// loopback-only checks and tc NIC blocking: loopback itself, tuntap when
// allowTunTap is true (TunSidecar), and administratively DOWN address-less
// kernel auto-created fallback tunnel devices (sit0, tunl0, etc.).
func shouldSkipLinkForIsolation(handle *netlink.Handle, link netlink.Link, allowTunTap bool) bool {
	attrs := link.Attrs()
	if attrs.Flags&net.FlagLoopback != 0 {
		return true
	}
	if allowTunTap && link.Type() == "tuntap" {
		return true
	}
	if attrs.Flags&net.FlagUp == 0 && isKernelFallbackTunnelType(link.Type()) {
		addrs, addrErr := retryNetlinkDump(func() ([]netlink.Addr, error) {
			return handle.AddrList(link, netlink.FAMILY_ALL)
		})
		if addrErr == nil && len(addrs) == 0 {
			return true
		}
	}
	return false
}

func (linuxNetNSManager) VerifyLoopbackOnly(netnsPath string, allowTunTap bool) error {
	return socketat.DoAtNSPath(netnsPath, func() error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return fmt.Errorf("open netlink handle in pod netns: %w", err)
		}
		defer handle.Close()

		links, err := retryNetlinkDump(handle.LinkList)
		if err != nil {
			return fmt.Errorf("list links in pod netns: %w", err)
		}
		for _, link := range links {
			if shouldSkipLinkForIsolation(handle, link, allowTunTap) {
				continue
			}
			return fmt.Errorf("non-loopback network interface %q (%s) present in PodNetworkIsolated netns", link.Attrs().Name, link.Type())
		}
		return nil
	})
}

// BlockNonLoopbackNICs attaches a tc clsact qdisc with matchall gact DROP filters
// on both ingress and egress of every non-loopback NIC inside the Pod netns via
// pure netlink (zero exec, zero iptables/nftables). This blocks all L2/L3 traffic
// on primary and secondary NICs independently of CNI NetworkPolicy enforcement
// while leaving loopback (lo) untouched.
func (linuxNetNSManager) BlockNonLoopbackNICs(netnsPath string, allowTunTap bool) error {
	return socketat.DoAtNSPath(netnsPath, func() error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return fmt.Errorf("open netlink handle in pod netns: %w", err)
		}
		defer handle.Close()

		links, err := retryNetlinkDump(handle.LinkList)
		if err != nil {
			return fmt.Errorf("list links in pod netns: %w", err)
		}
		for _, link := range links {
			if shouldSkipLinkForIsolation(handle, link, allowTunTap) {
				continue
			}
			if err := attachDropAllTC(handle, link); err != nil {
				return err
			}
		}
		return nil
	})
}

func attachDropAllTC(handle *netlink.Handle, link netlink.Link) error {
	idx := link.Attrs().Index
	name := link.Attrs().Name

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: idx,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := handle.QdiscAdd(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("add clsact qdisc on %q: %w", name, err)
	}

	for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
		existing, err := retryNetlinkDump(func() ([]netlink.Filter, error) {
			return handle.FilterList(link, parent)
		})
		if err == nil && hasLeadingMatchAllDrop(existing) {
			continue
		}
		filter := &netlink.MatchAll{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: idx,
				Handle:    nicBlockFilterHandle,
				Parent:    parent,
				Priority:  nicBlockFilterPriority,
				Protocol:  unix.ETH_P_ALL,
			},
			Actions: []netlink.Action{
				&netlink.GenericAction{
					ActionAttrs: netlink.ActionAttrs{
						Action: netlink.TC_ACT_SHOT,
					},
				},
			},
		}
		if err := handle.FilterReplace(filter); err != nil {
			return fmt.Errorf("install tc matchall drop filter (parent=%#x) on %q: %w", parent, name, err)
		}
	}
	return nil
}

// VerifyNonLoopbackNICsBlocked reports whether every non-loopback NIC in netnsPath
// has a leading tc clsact matchall DROP filter installed on both ingress and egress.
func (linuxNetNSManager) VerifyNonLoopbackNICsBlocked(netnsPath string, allowTunTap bool) (bool, error) {
	allBlocked := true
	err := socketat.DoAtNSPath(netnsPath, func() error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return fmt.Errorf("open netlink handle in pod netns: %w", err)
		}
		defer handle.Close()

		links, err := retryNetlinkDump(handle.LinkList)
		if err != nil {
			return fmt.Errorf("list links in pod netns: %w", err)
		}
		for _, link := range links {
			if shouldSkipLinkForIsolation(handle, link, allowTunTap) {
				continue
			}
			for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
				filters, ferr := retryNetlinkDump(func() ([]netlink.Filter, error) {
					return handle.FilterList(link, parent)
				})
				if ferr != nil {
					if errors.Is(ferr, unix.ENOENT) || errors.Is(ferr, unix.EINVAL) {
						allBlocked = false
						return nil
					}
					return fmt.Errorf("list tc filters (parent=%#x) on %q: %w", parent, link.Attrs().Name, ferr)
				}
				if !hasLeadingMatchAllDrop(filters) {
					allBlocked = false
					return nil
				}
			}
		}
		return nil
	})
	return allBlocked, err
}

// hasLeadingMatchAllDrop reports whether filters contain an ETH_P_ALL matchall
// filter with a TC_ACT_SHOT generic action at the highest precedence (lowest
// Priority) among all filters present on the hook.
func hasLeadingMatchAllDrop(filters []netlink.Filter) bool {
	if len(filters) == 0 {
		return false
	}
	minPrio := filters[0].Attrs().Priority
	for _, f := range filters[1:] {
		if p := f.Attrs().Priority; p < minPrio {
			minPrio = p
		}
	}
	for _, f := range filters {
		ma, ok := f.(*netlink.MatchAll)
		if !ok || ma.Priority != minPrio || ma.Protocol != unix.ETH_P_ALL {
			continue
		}
		for _, act := range ma.Actions {
			if gact, ok := act.(*netlink.GenericAction); ok && gact.Action == netlink.TC_ACT_SHOT {
				return true
			}
		}
	}
	return false
}

func (linuxNetNSManager) FlushNonLoopbackRoutes(netnsPath string) error {
	return socketat.DoAtNSPath(netnsPath, func() error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return fmt.Errorf("open netlink handle in pod netns: %w", err)
		}
		defer handle.Close()

		links, err := retryNetlinkDump(handle.LinkList)
		if err != nil {
			return fmt.Errorf("list links in pod netns: %w", err)
		}
		for _, link := range links {
			if link.Attrs().Flags&net.FlagLoopback != 0 {
				continue
			}
			filter := &netlink.Route{
				LinkIndex: link.Attrs().Index,
				Table:     unix.RT_TABLE_UNSPEC,
			}
			for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
				routes, err := retryNetlinkDump(func() ([]netlink.Route, error) {
					return handle.RouteListFiltered(family, filter, netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
				})
				if err != nil {
					if family == netlink.FAMILY_V6 && isFamilyUnsupported(err) {
						continue
					}
					return fmt.Errorf("list routes on %q: %w", link.Attrs().Name, err)
				}
				for i := range routes {
					if routes[i].Table == unix.RT_TABLE_LOCAL {
						continue
					}
					if err := handle.RouteDel(&routes[i]); err != nil && !errors.Is(err, unix.ESRCH) {
						return fmt.Errorf("delete route %v on %q: %w", routes[i], link.Attrs().Name, err)
					}
				}
			}
		}
		return nil
	})
}

func (linuxNetNSManager) HasNonLoopbackRoutes(netnsPath string) (bool, error) {
	var found bool
	err := socketat.DoAtNSPath(netnsPath, func() error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return fmt.Errorf("open netlink handle in pod netns: %w", err)
		}
		defer handle.Close()

		links, err := retryNetlinkDump(handle.LinkList)
		if err != nil {
			return fmt.Errorf("list links in pod netns: %w", err)
		}
		for _, link := range links {
			if link.Attrs().Flags&net.FlagLoopback != 0 {
				continue
			}
			// Ignore tun devices created intentionally by agents-net-tun2connect.
			if link.Type() == "tuntap" {
				continue
			}
			filter := &netlink.Route{
				LinkIndex: link.Attrs().Index,
				Table:     unix.RT_TABLE_UNSPEC,
			}
			for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
				routes, err := retryNetlinkDump(func() ([]netlink.Route, error) {
					return handle.RouteListFiltered(family, filter, netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
				})
				if err != nil {
					if family == netlink.FAMILY_V6 && isFamilyUnsupported(err) {
						continue
					}
					return fmt.Errorf("list routes on %q: %w", link.Attrs().Name, err)
				}
				for i := range routes {
					if routes[i].Table == unix.RT_TABLE_LOCAL {
						continue
					}
					found = true
					return nil
				}
			}
		}
		return nil
	})
	return found, err
}

func (linuxNetNSManager) ListenAt(netnsPath, network, address string) (net.Listener, error) {
	return socketat.ListenAtPath(netnsPath, network, address)
}

type hostTunHandle struct {
	eng  *tun2connect.Engine
	fd   int
	once sync.Once
}

func (h *hostTunHandle) Close() error {
	var closeErr error
	h.once.Do(func() {
		h.eng.Close()
		closeErr = unix.Close(h.fd)
	})
	return closeErr
}

// StartHostTun creates or re-attaches a persistent TUN device (tun0) inside
// netnsPath, configures synthetic addresses and default routes inside the Pod
// netns, and runs a host-side userspace tun2connect Engine over the returned
// TUN file descriptor with zero sidecar container and zero Pod capabilities.
func (linuxNetNSManager) StartHostTun(netnsPath, egressSocketPath string, maxConns int, preserveNICReturn bool) (io.Closer, error) {
	fd, err := openAndConfigureHostTun(netnsPath, preserveNICReturn)
	if err != nil {
		return nil, err
	}
	dev, err := tun2connect.NewTUNDevice(fd, hostTunMTU)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("create gvisor tun endpoint: %w", err)
	}
	var dialer net.Dialer
	client := &tun2connect.BoundaryClient{
		DialBoundary: func(ctx context.Context) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", egressSocketPath)
		},
	}
	eng, err := tun2connect.New(tun2connect.Config{
		Device:         dev,
		Dialer:         client,
		DNS:            tun2connect.NewVirtualDNS(),
		EnableUDP:      true,
		MaxConnections: maxConns,
	})
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("start host tun2connect engine: %w", err)
	}
	return &hostTunHandle{eng: eng, fd: fd}, nil
}

// CleanupHostTun deletes the persistent tun0 interface from netnsPath when the
// sandbox is removed. Missing netns or link errors are ignored.
func (linuxNetNSManager) CleanupHostTun(netnsPath string) error {
	if netnsPath == "" {
		return nil
	}
	if _, err := os.Stat(netnsPath); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	err := socketat.DoAtNSPath(netnsPath, func() error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return fmt.Errorf("open netlink handle in pod netns: %w", err)
		}
		defer handle.Close()
		link, err := handle.LinkByName(hostTunDeviceName)
		if err != nil {
			if _, ok := errors.AsType[netlink.LinkNotFoundError](err); ok || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENOENT) {
				return nil
			}
			return err
		}
		if err := handle.LinkDel(link); err != nil && !errors.Is(err, unix.ENODEV) && !errors.Is(err, unix.ENOENT) {
			return err
		}
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func openAndConfigureHostTun(netnsPath string, preserveNICReturn bool) (int, error) {
	tunFD := -1
	err := socketat.DoAtNSPath(netnsPath, func() error {
		fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open /dev/net/tun: %w", err)
		}
		cleanupFD := true
		defer func() {
			if cleanupFD {
				_ = unix.Close(fd)
			}
		}()

		ifr, err := unix.NewIfreq(hostTunDeviceName)
		if err != nil {
			return err
		}
		ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
		if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
			return fmt.Errorf("TUNSETIFF %s: %w", hostTunDeviceName, err)
		}
		// Keep tun0 and its routes across dra-agents-net restarts so Synchronize can re-attach.
		if err := unix.IoctlSetInt(fd, unix.TUNSETPERSIST, 1); err != nil {
			return fmt.Errorf("TUNSETPERSIST %s: %w", hostTunDeviceName, err)
		}
		if err := unix.SetNonblock(fd, true); err != nil {
			return fmt.Errorf("set nonblock on %s: %w", hostTunDeviceName, err)
		}

		handle, err := netlink.NewHandle()
		if err != nil {
			return fmt.Errorf("open netlink handle in pod netns: %w", err)
		}
		defer handle.Close()

		if lo, err := handle.LinkByName("lo"); err == nil {
			if err := handle.LinkSetUp(lo); err != nil {
				return fmt.Errorf("bring loopback up: %w", err)
			}
		}

		link, err := handle.LinkByName(hostTunDeviceName)
		if err != nil {
			return fmt.Errorf("lookup %s: %w", hostTunDeviceName, err)
		}
		if err := handle.LinkSetMTU(link, hostTunMTU); err != nil {
			return fmt.Errorf("set %s mtu %d: %w", hostTunDeviceName, hostTunMTU, err)
		}

		v4Addr, err := netlink.ParseAddr(fmt.Sprintf("%s/%d", tun2connect.DefaultGuestAddr4, tun2connect.DefaultPool4Bits))
		if err != nil {
			return err
		}
		if err := handle.AddrReplace(link, v4Addr); err != nil {
			return fmt.Errorf("set IPv4 address on %s: %w", hostTunDeviceName, err)
		}

		v6Addr, err := netlink.ParseAddr(fmt.Sprintf("%s/%d", tun2connect.DefaultGuestAddr6, tun2connect.DefaultPool6Bits))
		if err != nil {
			return err
		}
		if err := handle.AddrReplace(link, v6Addr); err != nil && !isFamilyUnsupported(err) {
			return fmt.Errorf("set IPv6 address on %s: %w", hostTunDeviceName, err)
		}

		if err := handle.LinkSetUp(link); err != nil {
			return fmt.Errorf("bring %s up: %w", hostTunDeviceName, err)
		}

		if preserveNICReturn {
			if err := preserveNICReturnRoutes(handle); err != nil {
				return fmt.Errorf("preserve NIC return routes: %w", err)
			}
		}

		v4Default := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Scope:     netlink.SCOPE_LINK,
			Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		}
		if err := handle.RouteReplace(v4Default); err != nil {
			return fmt.Errorf("set IPv4 default route on %s: %w", hostTunDeviceName, err)
		}
		v6Default := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Scope:     netlink.SCOPE_LINK,
			Dst:       &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		}
		if err := handle.RouteReplace(v6Default); err != nil && !isFamilyUnsupported(err) {
			return fmt.Errorf("set IPv6 default route on %s: %w", hostTunDeviceName, err)
		}

		cleanupFD = false
		tunFD = fd
		return nil
	})
	if err != nil {
		return -1, err
	}
	return tunFD, nil
}

func isDefaultRoute(dst *net.IPNet) bool {
	if dst == nil {
		return true
	}
	ones, _ := dst.Mask.Size()
	return ones == 0 && dst.IP.IsUnspecified()
}

// preserveNICReturnRoutes copies non-loopback NIC routes (e.g. eth0 default and
// connected routes under nicBlockMode=Disabled) into hostTunReturnTable and
// installs source-IP policy rules for Pod IPs so replies to inbound connections
// (such as sandbox-router or kubelet probes) still exit eth0 while all new
// outbound flows route through tun0.
func preserveNICReturnRoutes(handle *netlink.Handle) error {
	links, err := retryNetlinkDump(handle.LinkList)
	if err != nil {
		return fmt.Errorf("list links: %w", err)
	}
	for _, link := range links {
		if link.Attrs().Flags&net.FlagLoopback != 0 || link.Type() == "tuntap" {
			continue
		}
		for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
			routes, err := retryNetlinkDump(func() ([]netlink.Route, error) {
				return handle.RouteListFiltered(family, &netlink.Route{
					LinkIndex: link.Attrs().Index,
					Table:     unix.RT_TABLE_MAIN,
				}, netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
			})
			if err != nil {
				if family == netlink.FAMILY_V6 && isFamilyUnsupported(err) {
					continue
				}
				return fmt.Errorf("list routes on %q: %w", link.Attrs().Name, err)
			}
			// Copy connected/subnet routes into hostTunReturnTable before default/gateway
			// routes, constructing a clean Route struct so kernel-only dump flags such as
			// RTNH_F_LINKDOWN are never echoed back into RTM_NEWROUTE (which yields EINVAL).
			var defaultRoutes []netlink.Route
			for i := range routes {
				r := routes[i]
				if isDefaultRoute(r.Dst) {
					defaultRoutes = append(defaultRoutes, r)
					continue
				}
				copied := netlink.Route{
					LinkIndex: r.LinkIndex,
					Dst:       r.Dst,
					Src:       r.Src,
					Gw:        r.Gw,
					Scope:     r.Scope,
					Flags:     r.Flags & unix.RTNH_F_ONLINK,
					Priority:  r.Priority,
					Table:     hostTunReturnTable,
				}
				if err := handle.RouteReplace(&copied); err != nil {
					return fmt.Errorf("copy route %v to table %d: %w", r, hostTunReturnTable, err)
				}
			}
			for i := range defaultRoutes {
				r := defaultRoutes[i]
				copied := netlink.Route{
					LinkIndex: r.LinkIndex,
					Dst:       r.Dst,
					Src:       r.Src,
					Gw:        r.Gw,
					Scope:     r.Scope,
					Flags:     r.Flags & unix.RTNH_F_ONLINK,
					Priority:  r.Priority,
					Table:     hostTunReturnTable,
				}
				if err := handle.RouteReplace(&copied); err != nil {
					return fmt.Errorf("copy default route %v to table %d: %w", r, hostTunReturnTable, err)
				}
				if err := handle.RouteDel(&r); err != nil && !errors.Is(err, unix.ESRCH) {
					return fmt.Errorf("remove main default route on %q: %w", link.Attrs().Name, err)
				}
			}

			addrs, err := retryNetlinkDump(func() ([]netlink.Addr, error) {
				return handle.AddrList(link, family)
			})
			if err != nil {
				if family == netlink.FAMILY_V6 && isFamilyUnsupported(err) {
					continue
				}
				return fmt.Errorf("list addresses on %q: %w", link.Attrs().Name, err)
			}
			existingRules, err := retryNetlinkDump(func() ([]netlink.Rule, error) {
				return handle.RuleList(family)
			})
			if err != nil && (family != netlink.FAMILY_V6 || !isFamilyUnsupported(err)) {
				return fmt.Errorf("list ip rules: %w", err)
			}
			for _, a := range addrs {
				if a.IP == nil || a.IP.IsLoopback() || a.IP.IsLinkLocalUnicast() {
					continue
				}
				bits := 32
				ip := a.IP.To4()
				if ip == nil {
					bits = 128
					ip = a.IP.To16()
				}
				srcNet := &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
				if hasPolicyRule(existingRules, srcNet, hostTunReturnTable, hostTunReturnRulePriority) {
					continue
				}
				rule := netlink.NewRule()
				rule.Family = family
				rule.Src = srcNet
				rule.Table = hostTunReturnTable
				rule.Priority = hostTunReturnRulePriority
				if err := handle.RuleAdd(rule); err != nil && !errors.Is(err, unix.EEXIST) {
					return fmt.Errorf("add return-path rule for %s: %w", srcNet, err)
				}
			}
		}
	}
	return nil
}

func hasPolicyRule(rules []netlink.Rule, src *net.IPNet, table, priority int) bool {
	for _, r := range rules {
		if r.Table == table && r.Priority == priority && r.Src != nil && r.Src.String() == src.String() {
			return true
		}
	}
	return false
}
