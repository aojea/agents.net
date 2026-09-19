// Package netnsproxy redirects packets arriving on a workload-facing veth or
// TAP to a CONNECT boundary. TCP uses nftables REDIRECT and SO_ORIGINAL_DST;
// UDP uses TPROXY and namespace-local policy routing. Both use tun2connect's
// Forwarder and VirtualDNS to forward hostnames or literal IP destinations.
//
// The caller must start the proxy process in a dedicated network namespace
// containing only loopback and the configured ingress interface. The interface
// must be up and addressed; the workload routes traffic through it. Namespace
// creation, interface attachment, routes to the workload, filesystem access,
// and boundary authorization belong to the controller. Do not use this package
// in the host's root namespace or share its namespace with an untrusted process.
// Do not switch namespaces on a single Go thread around New: Run creates
// per-flow sockets on other threads in the same process.
//
// New requires CAP_NET_ADMIN in that namespace, including while UDP sessions
// create transparent reply sockets. New fails if its nftables table exists or
// its policy routing resources conflict. The namespace reserves routing table
// and priority 16666 and packet mark 0x616e. Close stops sockets and active
// sessions but deliberately retains rules and routes. Run waits for active
// sessions to exit. The controller must destroy the namespace after stopping
// the workload; restart requires a new namespace. Unrelated nftables tables
// are not modified.
package netnsproxy
