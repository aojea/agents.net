package netnsproxy

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func installRoutes(ipv6 bool) error {
	handle, err := netlink.NewHandle()
	if err != nil {
		return err
	}
	defer handle.Close()
	loopback, err := handle.LinkByName("lo")
	if err != nil {
		return err
	}
	families := []int{unix.AF_INET}
	if ipv6 {
		families = append(families, unix.AF_INET6)
	}
	var routes []netlink.Route
	var rules []*netlink.Rule
	complete := false
	defer func() {
		if !complete {
			for _, rule := range rules {
				handle.RuleDel(rule)
			}
			for _, route := range routes {
				handle.RouteDel(&route)
			}
		}
	}()
	for _, family := range families {
		existing, err := handle.RuleList(family)
		if err != nil {
			return err
		}
		for _, rule := range existing {
			if rule.Table == routingTable || rule.Priority == routingTable || rule.Mark == routingMark {
				return fmt.Errorf("netnsproxy: policy routing table, mark, or priority already in use")
			}
		}
		prefix := "0.0.0.0/0"
		if family == unix.AF_INET6 {
			prefix = "::/0"
		}
		_, destination, _ := net.ParseCIDR(prefix)
		route := netlink.Route{LinkIndex: loopback.Attrs().Index, Dst: destination,
			Table: routingTable, Scope: netlink.SCOPE_HOST, Type: unix.RTN_LOCAL}
		if err := handle.RouteAdd(&route); err != nil {
			return err
		}
		routes = append(routes, route)
		rule := netlink.NewRule()
		rule.Family, rule.Table, rule.Priority, rule.Mark = family, routingTable, routingTable, routingMark
		if err := handle.RuleAdd(rule); err != nil {
			return err
		}
		rules = append(rules, rule)
	}
	complete = true
	return nil
}
