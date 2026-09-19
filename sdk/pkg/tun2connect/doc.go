// Package tun2connect terminates a sandbox's TCP/IP in userspace (gVisor)
// and carries each supported flow to a boundary as an HTTP tunnel request:
// CONNECT (RFC 9110) for TCP, connect-udp (RFC 9298) with capsules
// (RFC 9297) for UDP.
//
// VirtualDNS maps synthetic addresses back to hostnames at dial time.
// Destinations without a mapping are forwarded as IP literals. The boundary
// authorizes both forms; the adapter does not require a DNS lookup for access.
//
// The components can also be used independently:
//
//   - VirtualDNS: the name-preservation contract (resolve + reverse).
//   - BoundaryClient: HTTP/1.1 CONNECT and connect-udp dialers over any
//     stream transport (Unix socket, vsock, TCP).
//   - Forwarder: shared destination lookup and TCP/UDP socket relays.
//   - Engine: the TUN-to-tunnel datapath gluing a gVisor netstack to a
//     Dialer.
package tun2connect
