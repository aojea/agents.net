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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"

	"github.com/aojea/agents.net/pkg/hosttun"
	"github.com/aojea/agents.net/pkg/socketat"
	"github.com/aojea/agents.net/pkg/tun2connect"
)

type linuxNetNSManager struct {
	hostTun     *hosttun.Manager
	ownsHostTun bool
}

// NewLinuxNetNSManager returns a NetNSManager backed by socketat, Linux netlink,
// and an isolated unprivileged HostTun worker manager (shared mode by default).
func NewLinuxNetNSManager() NetNSManager {
	return &linuxNetNSManager{
		hostTun:     hosttun.NewManager(hosttun.ManagerConfig{Isolation: hosttun.IsolationShared}),
		ownsHostTun: true,
	}
}

// NewLinuxNetNSManagerWithHostTun returns a NetNSManager that delegates HostTun
// packet processing to the caller-owned unprivileged hosttun.Manager.
func NewLinuxNetNSManagerWithHostTun(mgr *hosttun.Manager) NetNSManager {
	if mgr == nil {
		return NewLinuxNetNSManager()
	}
	return &linuxNetNSManager{
		hostTun:     mgr,
		ownsHostTun: false,
	}
}

// Close stops the internally-owned hosttun.Manager, if any.
func (m *linuxNetNSManager) Close() error {
	if m.ownsHostTun && m.hostTun != nil {
		return m.hostTun.Close()
	}
	return nil
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
// allowTunTap is true (host-side tun0), and administratively DOWN address-less
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

func (*linuxNetNSManager) VerifyLoopbackOnly(netnsPath string, allowTunTap bool) error {
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
func (*linuxNetNSManager) BlockNonLoopbackNICs(netnsPath string, allowTunTap bool) error {
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
func (*linuxNetNSManager) VerifyNonLoopbackNICsBlocked(netnsPath string, allowTunTap bool) (bool, error) {
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

func (*linuxNetNSManager) FlushNonLoopbackRoutes(netnsPath string) error {
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

func (*linuxNetNSManager) HasNonLoopbackRoutes(netnsPath string) (bool, error) {
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

const (
	vethIsoNetNSFile = "veth-netns"
	vethAddrsFile    = "veth-addrs"
)

// StartHostTun attaches a sandbox Pod to kube-netstack.
//
// For standard containers, it creates or re-attaches a persistent L3 tun0
// device inside req.NetNSPath. For L2 runtimes such as gVisor runsc, it moves
// the host veth peer into an empty isolated netns and hands an AF_PACKET
// descriptor to kube-netstack in TAP mode, returning the guest's primary IP.
func (m *linuxNetNSManager) StartHostTun(req HostTunRequest) (io.Closer, string, error) {
	if isL2VethRuntime(req.RuntimeHandler) {
		return m.startL2VethHostTun(req)
	}
	fd, err := openAndConfigureHostTun(req.NetNSPath, req.PreserveNICReturn)
	if err != nil {
		return nil, "", err
	}
	podID := string(req.PodUID)
	if podID == "" {
		podID = req.NetNSPath
	}
	closer, err := m.hostTun.Attach(hosttun.AttachConfig{
		PodID:            podID,
		TunFD:            fd,
		MTU:              hostTunMTU,
		MaxConnections:   req.MaxConnections,
		EnableUDP:        true,
		DNSMode:          req.DNSMode,
		ServeEgress:      req.ServeEgress,
		EgressSocketPath: req.EgressSocketPath,
		ReopenTun: func() (int, error) {
			return openAndConfigureHostTun(req.NetNSPath, req.PreserveNICReturn)
		},
	})
	return closer, "", err
}

// CleanupHostTun deletes the persistent tun0 interface from netnsPath and any
// persisted L2 isolated veth netns under podRootDir when the sandbox is removed.
func (*linuxNetNSManager) CleanupHostTun(netnsPath, podRootDir string) error {
	var errs []error
	if podRootDir != "" {
		isoPath := filepath.Join(podRootDir, vethIsoNetNSFile)
		if _, err := os.Stat(isoPath); err == nil {
			_ = unix.Unmount(isoPath, unix.MNT_DETACH)
			if err := os.Remove(isoPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
		}
		_ = os.Remove(filepath.Join(podRootDir, vethAddrsFile))
	}
	if netnsPath != "" {
		if _, err := os.Stat(netnsPath); !errors.Is(err, os.ErrNotExist) {
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
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

type podVethInfo struct {
	peerIdx   int
	mtu       int
	guestIP   string
	addresses []string
}

func inspectPodVeth(podNetNSPath string) (podVethInfo, error) {
	var info podVethInfo
	err := socketat.DoAtNSPath(podNetNSPath, func() error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return fmt.Errorf("open netlink handle in pod netns: %w", err)
		}
		defer handle.Close()

		var link netlink.Link
		if eth0, err := handle.LinkByName("eth0"); err == nil && eth0.Type() == "veth" {
			link = eth0
		} else {
			links, lerr := retryNetlinkDump(handle.LinkList)
			if lerr != nil {
				return fmt.Errorf("list links in pod netns: %w", lerr)
			}
			for _, l := range links {
				if l.Attrs().Flags&net.FlagLoopback != 0 {
					continue
				}
				if l.Type() == "veth" {
					link = l
					break
				}
			}
		}
		if link == nil {
			return errors.New("no veth interface found in pod netns")
		}

		info.peerIdx = link.Attrs().ParentIndex
		info.mtu = link.Attrs().MTU
		if info.mtu <= 0 {
			info.mtu = hostTunMTU
		}

		var v4Subnets []*net.IPNet
		var v6Subnets []*net.IPNet
		var guestV4, guestV6 string
		for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
			addrs, aerr := retryNetlinkDump(func() ([]netlink.Addr, error) {
				return handle.AddrList(link, family)
			})
			if aerr != nil {
				if family == netlink.FAMILY_V6 && isFamilyUnsupported(aerr) {
					continue
				}
				return fmt.Errorf("list addresses on %q: %w", link.Attrs().Name, aerr)
			}
			for _, a := range addrs {
				if a.IP == nil || a.IP.IsLoopback() || a.IP.IsLinkLocalUnicast() {
					continue
				}
				if ip4 := a.IP.To4(); ip4 != nil {
					if guestV4 == "" {
						guestV4 = ip4.String()
					}
					if a.IPNet != nil {
						v4Subnets = append(v4Subnets, a.IPNet)
					}
				} else if a.IP.To16() != nil {
					if guestV6 == "" {
						guestV6 = a.IP.String()
					}
					if a.IPNet != nil {
						v6Subnets = append(v6Subnets, a.IPNet)
					}
				}
			}
		}
		info.guestIP = guestV4
		if info.guestIP == "" {
			info.guestIP = guestV6
		}

		// Collect gateway addresses from the Pod's default routes so kube-netstack
		// answers ARP/NDP for the exact gateway the guest stack expects.
		filter := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Table:     unix.RT_TABLE_MAIN,
		}
		for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
			routes, rerr := retryNetlinkDump(func() ([]netlink.Route, error) {
				return handle.RouteListFiltered(family, filter, netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
			})
			if rerr != nil {
				if family == netlink.FAMILY_V6 && isFamilyUnsupported(rerr) {
					continue
				}
				return fmt.Errorf("list routes on %q: %w", link.Attrs().Name, rerr)
			}
			for _, r := range routes {
				if !isDefaultRoute(r.Dst) || r.Gw == nil {
					continue
				}
				if gw4 := r.Gw.To4(); gw4 != nil {
					bits := 32
					for _, sub := range v4Subnets {
						if sub.Contains(gw4) {
							ones, _ := sub.Mask.Size()
							bits = ones
							break
						}
					}
					info.addresses = append(info.addresses, fmt.Sprintf("%s/%d", gw4.String(), bits))
				} else if r.Gw.To16() != nil {
					bits := 128
					for _, sub := range v6Subnets {
						if sub.Contains(r.Gw) {
							ones, _ := sub.Mask.Size()
							bits = ones
							break
						}
					}
					info.addresses = append(info.addresses, fmt.Sprintf("%s/%d", r.Gw.String(), bits))
				}
			}
		}
		return nil
	})
	return info, err
}

func firstNonLoopbackIP(ips []string) string {
	var fallbackV6 string
	for _, raw := range ips {
		ip := net.ParseIP(raw)
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String()
		}
		if fallbackV6 == "" {
			fallbackV6 = ip.String()
		}
	}
	return fallbackV6
}

// collectHostPeerAddresses reads IPv4/IPv6 gateway addresses from hostVeth
// (ptp CNI) or its master bridge (bridge CNI) before moving hostVeth out of
// the host netns. This recovers the gateway IP even when runsc already called
// AddrDel on eth0 inside the Pod netns before NRI RunPodSandbox ran.
func collectHostPeerAddresses(peer netlink.Link) []string {
	var out []string
	appendLinkAddrs := func(l netlink.Link) {
		for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
			addrs, err := retryNetlinkDump(func() ([]netlink.Addr, error) {
				return netlink.AddrList(l, family)
			})
			if err != nil {
				continue
			}
			for _, a := range addrs {
				if a.IP == nil || a.IP.IsLoopback() || a.IP.IsLinkLocalUnicast() || a.IPNet == nil {
					continue
				}
				ones, _ := a.IPNet.Mask.Size()
				if ip4 := a.IP.To4(); ip4 != nil {
					out = append(out, fmt.Sprintf("%s/%d", ip4.String(), ones))
				} else if a.IP.To16() != nil {
					out = append(out, fmt.Sprintf("%s/%d", a.IP.String(), ones))
				}
			}
		}
	}
	appendLinkAddrs(peer)
	if len(out) == 0 && peer.Attrs().MasterIndex > 0 {
		if master, err := netlink.LinkByIndex(peer.Attrs().MasterIndex); err == nil {
			appendLinkAddrs(master)
		}
	}
	return out
}

func (m *linuxNetNSManager) startL2VethHostTun(req HostTunRequest) (io.Closer, string, error) {
	info, err := inspectPodVeth(req.NetNSPath)
	if err != nil {
		return nil, "", fmt.Errorf("inspect pod veth in %q: %w", req.NetNSPath, err)
	}
	// gVisor runsc removes IP addresses from Linux eth0 (AddrDel) after copying
	// them into Sentry before NRI RunPodSandbox runs. Fall back to containerd's
	// NRI PodSandbox.Ips for the guest IP.
	if info.guestIP == "" {
		info.guestIP = firstNonLoopbackIP(req.PodIPs)
	}

	var (
		isoNSPath  string
		isoHandle  netns.NsHandle = -1
		persisted  bool
		packetFD   = -1
		hostMAC    string
		reopenFunc func() (int, error)
	)
	if req.PodRootDir != "" {
		isoNSPath = filepath.Join(req.PodRootDir, vethIsoNetNSFile)
	}

	// Re-attach if the host veth was already moved into a persisted isolated
	// netns (for example after a kube-net-driver DaemonSet restart).
	if isoNSPath != "" {
		if existingFD, mac, err := openPacketOnVethInNSPath(isoNSPath); err == nil {
			persisted = true
			packetFD = existingFD
			hostMAC = mac
			if len(info.addresses) == 0 {
				if raw, rerr := os.ReadFile(filepath.Join(req.PodRootDir, vethAddrsFile)); rerr == nil {
					for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
						if line = strings.TrimSpace(line); line != "" {
							info.addresses = append(info.addresses, line)
						}
					}
				}
			}
		}
	}

	if packetFD < 0 {
		if info.peerIdx <= 0 {
			return nil, "", fmt.Errorf("pod veth in %q has no host peer index", req.NetNSPath)
		}
		peer, err := netlink.LinkByIndex(info.peerIdx)
		if err != nil {
			return nil, "", fmt.Errorf("lookup host veth peer index %d: %w", info.peerIdx, err)
		}
		if peer.Type() != "veth" {
			return nil, "", fmt.Errorf("host peer index %d (%s) is %q, want veth", info.peerIdx, peer.Attrs().Name, peer.Type())
		}
		hostMAC = peer.Attrs().HardwareAddr.String()
		if len(info.addresses) == 0 {
			info.addresses = collectHostPeerAddresses(peer)
		}
		if req.PodRootDir != "" && len(info.addresses) > 0 {
			_ = os.WriteFile(filepath.Join(req.PodRootDir, vethAddrsFile), []byte(strings.Join(info.addresses, "\n")+"\n"), 0o600)
		}

		nsHandle, bound, err := createIsolatedNetNS(isoNSPath)
		if err != nil {
			return nil, "", fmt.Errorf("create isolated veth netns: %w", err)
		}
		persisted = bound
		if err := netlink.LinkSetNsFd(peer, int(nsHandle)); err != nil {
			_ = nsHandle.Close()
			if bound {
				_ = unix.Unmount(isoNSPath, unix.MNT_DETACH)
				_ = os.Remove(isoNSPath)
			}
			return nil, "", fmt.Errorf("move host veth %q to isolated netns: %w", peer.Attrs().Name, err)
		}

		fd, _, err := bringUpAndOpenVethPacketFD(int(nsHandle))
		if err != nil {
			_ = nsHandle.Close()
			if bound {
				_ = unix.Unmount(isoNSPath, unix.MNT_DETACH)
				_ = os.Remove(isoNSPath)
			}
			return nil, "", err
		}
		packetFD = fd
		if bound {
			_ = nsHandle.Close()
		} else {
			isoHandle = nsHandle
		}
	}

	if len(info.addresses) == 0 {
		info.addresses = []string{
			fmt.Sprintf("%s/%d", tun2connect.DefaultResolverAddr, tun2connect.DefaultPool4Bits),
		}
	}

	if persisted {
		reopenFunc = func() (int, error) {
			fd, _, err := openPacketOnVethInNSPath(isoNSPath)
			return fd, err
		}
	} else {
		reopenFunc = func() (int, error) {
			fd, _, err := bringUpAndOpenVethPacketFD(int(isoHandle))
			return fd, err
		}
	}

	podID := string(req.PodUID)
	if podID == "" {
		podID = req.NetNSPath
	}
	htCloser, err := m.hostTun.Attach(hosttun.AttachConfig{
		PodID:            podID,
		TunFD:            packetFD,
		MTU:              info.mtu,
		MaxConnections:   req.MaxConnections,
		EnableUDP:        true,
		DNSMode:          req.DNSMode,
		LinkMode:         hosttun.LinkModeTAP,
		MAC:              hostMAC,
		Addresses:        info.addresses,
		ServeEgress:      req.ServeEgress,
		EgressSocketPath: req.EgressSocketPath,
		ReopenTun:        reopenFunc,
	})
	if err != nil {
		if isoHandle >= 0 {
			_ = isoHandle.Close()
		}
		return nil, "", err
	}
	klog.InfoS("attached L2 veth sandbox to kube-netstack",
		"podUID", req.PodUID, "guestIP", info.guestIP, "addresses", info.addresses, "mac", hostMAC)
	if isoHandle >= 0 {
		return &l2VethCloser{inner: htCloser, isoHandle: isoHandle}, info.guestIP, nil
	}
	return htCloser, info.guestIP, nil
}

type l2VethCloser struct {
	inner     io.Closer
	isoHandle netns.NsHandle
}

func (c *l2VethCloser) Close() error {
	var errs []error
	if c.inner != nil {
		if err := c.inner.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.isoHandle >= 0 {
		if err := c.isoHandle.Close(); err != nil {
			errs = append(errs, err)
		}
		c.isoHandle = -1
	}
	return errors.Join(errs...)
}

func createIsolatedNetNS(bindPath string) (netns.NsHandle, bool, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	orig, err := netns.Get()
	if err != nil {
		return -1, false, fmt.Errorf("get host netns: %w", err)
	}
	defer func() { _ = orig.Close() }()

	iso, err := netns.New()
	if err != nil {
		return -1, false, fmt.Errorf("unshare CLONE_NEWNET: %w", err)
	}

	persisted := false
	if bindPath != "" {
		if err := os.MkdirAll(filepath.Dir(bindPath), 0o711); err == nil {
			if f, ferr := os.OpenFile(bindPath, os.O_CREATE|os.O_RDWR, 0o600); ferr == nil {
				_ = f.Close()
				threadNS := fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid())
				if merr := unix.Mount(threadNS, bindPath, "", unix.MS_BIND, ""); merr == nil {
					persisted = true
				} else {
					_ = os.Remove(bindPath)
				}
			}
		}
	}

	if err := netns.Set(orig); err != nil {
		_ = iso.Close()
		if persisted {
			_ = unix.Unmount(bindPath, unix.MNT_DETACH)
			_ = os.Remove(bindPath)
		}
		return -1, false, fmt.Errorf("restore host netns: %w", err)
	}
	return iso, persisted, nil
}

func doAtNSFD(nsFD int, fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	orig, err := netns.Get()
	if err != nil {
		return fmt.Errorf("get current netns: %w", err)
	}
	defer func() { _ = orig.Close() }()

	if err := unix.Setns(nsFD, unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("setns(%d): %w", nsFD, err)
	}
	fnErr := fn()
	if err := netns.Set(orig); err != nil && fnErr == nil {
		return fmt.Errorf("restore host netns: %w", err)
	}
	return fnErr
}

func openPacketOnVethInNSPath(nsPath string) (int, string, error) {
	f, err := os.Open(nsPath)
	if err != nil {
		return -1, "", err
	}
	defer func() { _ = f.Close() }()
	return bringUpAndOpenVethPacketFD(int(f.Fd()))
}

func bringUpAndOpenVethPacketFD(nsFD int) (int, string, error) {
	packetFD := -1
	var mac string
	err := doAtNSFD(nsFD, func() error {
		// Prevent the isolated netns kernel from auto-configuring IPv6 link-local
		// addresses or emitting NDP/ICMPv6 traffic on the captured veth peer.
		_ = os.WriteFile("/proc/sys/net/ipv6/conf/all/disable_ipv6", []byte("1"), 0o644)

		handle, err := netlink.NewHandle()
		if err != nil {
			return fmt.Errorf("open netlink handle in isolated veth netns: %w", err)
		}
		defer handle.Close()

		links, err := retryNetlinkDump(handle.LinkList)
		if err != nil {
			return fmt.Errorf("list links in isolated veth netns: %w", err)
		}
		var vethLink netlink.Link
		for _, l := range links {
			if l.Type() == "veth" {
				vethLink = l
				break
			}
		}
		if vethLink == nil {
			return errors.New("no veth link found in isolated veth netns")
		}
		if err := handle.LinkSetUp(vethLink); err != nil {
			return fmt.Errorf("bring isolated veth %q up: %w", vethLink.Attrs().Name, err)
		}
		mac = vethLink.Attrs().HardwareAddr.String()

		proto := htons(unix.ETH_P_ALL)
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, int(proto))
		if err != nil {
			return fmt.Errorf("open AF_PACKET on isolated veth: %w", err)
		}
		cleanup := true
		defer func() {
			if cleanup {
				_ = unix.Close(fd)
			}
		}()

		// Ignore frames transmitted by this socket so kube-netstack never reads back its own TX traffic.
		if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_IGNORE_OUTGOING, 1); err != nil {
			return fmt.Errorf("set PACKET_IGNORE_OUTGOING on isolated veth: %w", err)
		}
		if err := unix.Bind(fd, &unix.SockaddrLinklayer{
			Protocol: proto,
			Ifindex:  vethLink.Attrs().Index,
		}); err != nil {
			return fmt.Errorf("bind AF_PACKET to isolated veth %q: %w", vethLink.Attrs().Name, err)
		}
		cleanup = false
		packetFD = fd
		return nil
	})
	if err != nil {
		return -1, "", err
	}
	return packetFD, mac, nil
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
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
