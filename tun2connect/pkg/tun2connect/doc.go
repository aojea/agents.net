// Package tun2connect terminates a sandbox's TCP/IP in userspace (gVisor)
// and carries every flow to a boundary as a named HTTP tunnel request:
// CONNECT (RFC 9110) for TCP, connect-udp (RFC 9298) with capsules
// (RFC 9297) for UDP.
//
// The destination reaches the boundary as a NAME, never a resolved IP:
// the embedded virtual DNS answers guest queries with synthetic addresses
// it invents, and the engine maps them back at dial time. A flow whose
// destination was never resolved through the virtual DNS has no name and
// is refused, so deny-by-default policy on names can be enforced entirely
// on the boundary side.
//
// The three pieces compose but are usable alone:
//
//   - VirtualDNS: the name-preservation contract (resolve + reverse).
//   - BoundaryClient: HTTP/1.1 CONNECT and connect-udp dialers over any
//     stream transport (Unix socket, vsock, TCP).
//   - Engine: the TUN-to-tunnel datapath gluing a gVisor netstack to a
//     Dialer.
package tun2connect
