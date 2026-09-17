# QEMU Packet-to-CONNECT Integration

This scenario boots two unmodified QEMU `microvm` machines on KVM. Each guest
uses ordinary sockets and a virtio-net NIC. No guest TUN adapter, proxy settings,
VSOCK device, host TAP, or bridge is used. This is a QEMU-compatible external
network backend, not a modification to QEMU or native socket interception.

```text
guest socket -> virtio-net -> QEMU -netdev stream
                                  |
                         packet Unix socket
                                  |
                  qemuproxy: Ethernet + gVisor netstack
                                  |
                      HTTP CONNECT on boundary Unix socket
                                  |
                   connect-proxy -> checked upstream address
```

The packet socket and boundary socket are different protocols and endpoints.
The packet stream contains a four-byte big-endian length followed by Ethernet
bytes, without FCS or virtio-net headers. The adapter terminates TCP and sends
one HTTP/1.1 CONNECT per flow. For example, a guest request to
`http://www.example.com:18080/ping` produces `CONNECT www.example.com:18080`;
the original HTTP GET then travels unchanged inside the established tunnel.
The adapter does not inspect HTTP Host or unwrap CONNECT-looking payloads.

## Run

Requirements: Linux x86_64, read/write access to `/dev/kvm`, QEMU with the
`microvm` machine and `stream` backend, Go, static BusyBox, cpio, Bubblewrap,
unprivileged user/network namespaces, iproute2, jq, curl, and file. On Debian
or Ubuntu, the relevant packages include `qemu-system-x86`, `busybox-static`,
`bubblewrap`, `cpio`, `iproute2`, `jq`, `curl`, and `file`.

```bash
./scenarios/10-qemu-stream/run.sh
```

`BUSYBOX` can select a static binary. The script downloads and verifies the
same pinned guest kernel as scenario 09 when it is absent from
`AGENTS_NET_CACHE` (default `~/.cache/agents.net`). It builds a small initramfs
from BusyBox and the guest test, and rebuilds all host commands into a unique
temporary directory. No Docker image or root filesystem download is needed.
The test has no public-network dependency after fetching the kernel.

`KEEP_RUN_DIR=1` retains consoles, boundary audit records, and process logs.
Failures always retain them. The script prints the artifact directory.

## Configuration

Build the adapter:

```bash
go -C sdk build -o /tmp/qemuproxy ./cmd/qemuproxy
```

In a controller-prepared, restricted adapter environment, start it with:

```bash
/tmp/qemuproxy \
    -listen /run/packets/nic.sock \
    -proxy unix:///run/boundary/egress.sock
```

The packet path must not already exist. Its directory must be controller-owned
and accessible only to the assigned QEMU and adapter. The command creates a
`0600` socket, accepts one connection, closes its listener, and exits when that
connection ends. Socket mode alone does not isolate processes sharing a UID.
There is no reconnection or listener reuse within a VM generation.

With the pinned Firecracker guest kernel, use
`-machine microvm,pit=off,pic=off,rtc=off`. Leaving legacy interrupt devices
enabled can cause an early guest exception before its normal serial console
starts. The scenario enables early serial output and reports a terminated VM
immediately, including its console and adapter logs, rather than waiting for
the guest marker timeout.

Attach this networking fragment to an otherwise configured QEMU `microvm`:

```bash
-netdev stream,id=net0,server=off,addr.type=unix,addr.path=/run/packets/nic.sock \
-device virtio-net-device,netdev=net0,mac=02:00:00:00:00:02,host_mtu=1500,mq=off,csum=off,gso=off,guest_csum=off,guest_tso4=off,guest_tso6=off,guest_ecn=off,guest_ufo=off,host_tso4=off,host_tso6=off,host_ecn=off,host_ufo=off
```

Do not add other network backends or enable stream reconnect. The `q35`
equivalent uses `virtio-net-pci`; that machine configuration has not been
executed here. QEMU's packet backend is not an HTTP proxy and cannot connect
directly to the boundary socket.

Default guest configuration is `10.0.2.2/24`, gateway and DNS `10.0.2.1`,
and optionally `fd00::2/64`, gateway and DNS `fd00::1`. The adapter's
`-addresses` and `-mac` flags configure its own gateway addresses and MAC;
they do not configure the guest. The two test VMs deliberately reuse the
same guest addresses and MAC. Identity comes from their separate endpoints.

The adapter has a 1500-byte IP MTU, a 256-frame output queue, a 15-second
partial-frame/read and write deadline, and a combined TCP/UDP/DNS session
limit (`-max-connections`, default 1024). Idle packet channels are not timed
out. Boundary setup has a 15-second deadline. Active tunnel idle limits are
enforced by the boundary. Ethernet, ARP and IPv6 neighbor handling use gVisor;
VLAN frames and unsupported EtherTypes are dropped. Invalid or oversized
stream lengths terminate the packet channel without allocating the claimed
length. Non-DNS UDP is off unless `-udp` is selected at both ends; that optional
QEMU path is not covered by the live scenario.

## Confinement And Lifetime

Each test adapter runs in Bubblewrap with private user, network, mount, PID and
IPC namespaces, no capabilities, its static binary, a private proc/dev/tmp,
and only its assigned packet directory and read-only boundary directory mount.
Its namespace has no external interface. A compromised adapter must still
use its assigned boundary policy; it has no direct upstream connection path.
Filesystem and process isolation are required in addition to network isolation.

QEMU runs in a separate user/network namespace. Its guest receives only the
NIC attached to its packet socket. The fixture boundaries and local IPv4/IPv6
targets run in another namespace with no external interface. The script changes
no routes or firewall rules in the host network namespace. Its serial pipes are
test coordination channels, not production ingress or an external network path.

The supervisor ends the VM generation when either QEMU or its adapter exits,
then terminates and reaps both children. Engine shutdown cancels pending dials,
closes active relays and joins workers. Policy revocation terminates the
boundary process and all its upstream sockets before starting a replacement.

Do not restart a fresh adapter against a surviving guest: its cached synthetic
addresses could name different destinations in a fresh DNS allocation state.
Snapshot/restore, live migration, backend handoff, and in-place VM reset are
unsupported. A production controller must reject these operations or treat
them as teardown and fresh launch, with no retained guest DNS/socket state.

## Executed Checks

The scenario passed locally on QEMU 11.0.3 with guest kernel 6.18.41:

- Ordinary HTTP GET through synthetic DNS becomes a named CONNECT.
- IPv4 and IPv6 literal TCP destinations use the same boundary path.
- DNS queries reach the synthetic resolver over IPv4 and IPv6.
- An allowed name can connect to a checked IPv6 upstream address.
- Name, port, and literal-IP refusals fail guest requests.
- The same guest configuration cannot obtain access under VM B's empty policy.
- Killing VM A's boundary interrupts an active large transfer; a replacement
  with empty policy refuses its next request under the new audit policy version.
- Killing VM B's packet adapter terminates and reaps its QEMU process.

The package tests additionally exercise Ethernet ARP/NDP with dual-stack TCP,
unchanged HTTP payload bytes, fragmented/truncated/oversized stream framing,
idle-channel cancellation, and shutdown of active connections. Shared engine
tests cover cancellation of a stalled boundary handshake.

The GitHub QEMU workflow executes the scenario separately from Firecracker.
Hosted QEMU results are unverified until that workflow runs. These are
integration tests, not an implementation-independent conformance suite or proof
of complete runtime isolation. DHCP, ingress, explicit guest proxy endpoints,
HTTP/2 selection, descriptor provisioning, and snapshot/migration are deferred.