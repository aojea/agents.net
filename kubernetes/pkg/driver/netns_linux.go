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
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/aojea/agents.net/kubernetes/pkg/socketat"
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
