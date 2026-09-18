# QEMU Packet-to-CONNECT Integration

This scenario boots two unmodified QEMU `microvm` machines on KVM. Each guest
has a virtio-net NIC and uses ordinary sockets. The guest needs no TUN adapter
or proxy settings, and the host needs no vsock device, TAP, or bridge. The
integration is an external network backend attached through QEMU's `stream`
netdev: QEMU itself is unpatched, and there is no native interception of the
guest's sockets.

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

The packet socket and the boundary socket are separate endpoints speaking
different protocols. On the packet socket, each frame is a four-byte
big-endian length followed by the Ethernet bytes, with no FCS and no
virtio-net header. The adapter terminates the guest's TCP in its own netstack
and opens one HTTP/1.1 CONNECT tunnel per flow. A guest request to
`http://www.example.com:18080/ping`, for example, produces
`CONNECT www.example.com:18080`, and the original HTTP GET then travels
unchanged inside the tunnel. The adapter doesn't inspect the HTTP Host header
or unwrap payloads that happen to look like CONNECT requests.

## Run

You need Linux on x86_64, read/write access to `/dev/kvm`, QEMU with the
`microvm` machine and `stream` backend, Go, a static BusyBox, cpio, Bubblewrap,
unprivileged user and network namespaces, iproute2, jq, curl, and file. On
Debian or Ubuntu the packages are `qemu-system-x86`, `busybox-static`,
`bubblewrap`, `cpio`, `iproute2`, `jq`, `curl`, and `file`.

```bash
./scenarios/10-qemu-stream/run.sh
```

Set `BUSYBOX` to a static binary if the one on `PATH` isn't static. The
script uses the same pinned guest kernel as scenario 09, downloading it into
`AGENTS_NET_CACHE` (default `~/.cache/agents.net`) when it is missing and
checking its digest either way. It then builds a small initramfs from BusyBox
and the guest test script, and builds fresh copies of the host commands into a
unique temporary directory. There is no Docker image or root filesystem to
download, and once the kernel is cached the test doesn't touch the public
network.

The run directory holds the guest consoles, the boundary audit records, and
the process logs. It is deleted after a passing run unless you set
`KEEP_RUN_DIR=1`; a failing run always keeps it. The script prints its path
in either case.

## Configuration

Build the adapter:

```bash
go -C sdk build -o /tmp/qemuproxy ./cmd/qemuproxy
```

Start it inside the restricted environment the controller has prepared for it:

```bash
/tmp/qemuproxy \
    -listen /run/packets/nic.sock \
    -proxy unix:///run/boundary/egress.sock
```

The packet socket path must not exist yet. Its directory must be owned by
the controller and reachable only by the QEMU and adapter assigned to it. The
adapter creates the socket with mode `0600`, accepts exactly one connection,
closes the listener, and exits when that connection ends, but the mode on its
own doesn't keep out other processes running under the same UID. The adapter
never reconnects or reuses the listener within a VM generation.

With the pinned Firecracker guest kernel, use
`-machine microvm,pit=off,pic=off,rtc=off`. If the legacy interrupt devices
stay enabled, the guest can take an exception early in boot, before its
serial console is up. To make that visible, the scenario turns on early serial
output, and when a VM exits it prints the console and adapter logs right away
instead of waiting for the guest marker timeout.

Add this networking fragment to an otherwise complete QEMU `microvm` command
line:

```bash
-netdev stream,id=net0,server=off,addr.type=unix,addr.path=/run/packets/nic.sock \
-device virtio-net-device,netdev=net0,mac=02:00:00:00:00:02,host_mtu=1500,mq=off,csum=off,gso=off,guest_csum=off,guest_tso4=off,guest_tso6=off,guest_ecn=off,guest_ufo=off,host_tso4=off,host_tso6=off,host_ecn=off,host_ufo=off
```

Don't add other network backends, and don't enable stream reconnect. On a
`q35` machine the device would be `virtio-net-pci`, but that configuration
hasn't been run here. QEMU's `stream` backend only carries packets, so it
can't be pointed at the boundary socket directly; the adapter has to sit in
between.

The guest's default configuration is `10.0.2.2/24` with gateway and DNS at
`10.0.2.1`, plus, if you want IPv6, `fd00::2/64` with gateway and DNS at
`fd00::1`. The adapter's `-addresses` and `-mac` flags set the adapter's own
gateway addresses and MAC; they don't configure the guest. The two test VMs
use identical guest addresses and MACs on purpose; each is identified by its
own packet and boundary sockets.

The adapter has a 1500-byte IP MTU, a 256-frame output queue, a 15-second
deadline for reading the rest of a partially received frame and for each
write, and a combined cap on TCP, UDP, and DNS sessions (`-max-connections`,
default 1024). An idle packet channel is never timed out. Setting up a tunnel
with the boundary has its own 15-second deadline; once a tunnel is active,
idle limits are the boundary's job. Ethernet, ARP, and IPv6 neighbor
discovery are handled by gVisor, and VLAN frames and unsupported EtherTypes
are dropped. A frame length that is invalid or too large ends the packet
channel before any buffer of that size is allocated. UDP other than DNS stays
off unless `-udp` is enabled on the adapter and UDP is enabled on the boundary
as well; the live scenario doesn't exercise that path.

## Confinement And Lifetime

Each test adapter runs under Bubblewrap in its own user, network, mount, PID,
and IPC namespaces with every capability dropped. Its filesystem holds the
static adapter binary, a private `/proc`, `/dev`, and `/tmp`, its assigned
packet directory, and a read-only mount of its boundary directory, and
nothing else. The network namespace has no interface to the outside, so even
a compromised adapter can only reach upstream through its assigned boundary
and that boundary's policy. Isolating the network isn't sufficient on its
own; the filesystem and process isolation are required too.

QEMU runs in a separate user and network namespace, and the guest gets a
single NIC, the one attached to its packet socket. The fixture boundaries and
the local IPv4 and IPv6 targets run in yet another namespace without an
external interface. The script doesn't touch routes or firewall rules in the
host network namespace. The serial pipes exist so the test can drive the
guest; they aren't a production ingress path or a way out to a network.

When either QEMU or its adapter exits, the supervisor ends that VM
generation: it terminates and reaps both children. Shutting down the engine
cancels pending dials, closes active relays, and waits for its workers to
finish. Revoking a policy means killing the boundary process, and with it
every upstream socket it held, before a replacement is started.

Don't start a fresh adapter against a guest that is still running. The guest
may have cached synthetic addresses from the old adapter, and in the new
adapter's DNS allocation state those same addresses could map to different
destinations. Snapshot and restore, live migration, backend handoff, and
in-place VM reset are all unsupported. A production controller has to reject
those operations or treat them as a teardown followed by a fresh launch, with
no guest DNS or socket state carried over.

## Executed Checks

The scenario passed locally on QEMU 11.0.3 with guest kernel 6.18.41:

- An ordinary HTTP GET, resolved through the synthetic DNS, reaches the
  boundary as a CONNECT that names the host.
- IPv4 and IPv6 literal TCP destinations take the same boundary path.
- DNS queries reach the synthetic resolver over both IPv4 and IPv6.
- An allowed name connects to a checked IPv6 upstream address.
- Refusals by name, by port, and by literal IP each fail the guest's request.
- The same guest configuration gets no access under VM B's empty policy.
- Killing VM A's boundary cuts off a large transfer in progress, and a
  replacement boundary with an empty policy refuses the guest's next request,
  with the new policy version in its audit record.
- Killing VM B's packet adapter terminates and reaps its QEMU process.

The Go package tests cover more ground: ARP and NDP with dual-stack TCP,
byte-for-byte unchanged HTTP payloads, stream framing that is fragmented,
truncated, or oversized, cancellation of an idle channel, and shutdown while
connections are active. The shared engine tests cover cancelling a boundary
handshake that has stalled.

A separate GitHub workflow runs this scenario apart from the Firecracker one.
Until that workflow has run, the hosted QEMU results are unverified. These
are integration tests. They aren't an implementation-independent conformance
suite, and they don't prove that the runtime isolation is complete. DHCP,
ingress, explicit proxy endpoints for the guest, HTTP/2 selection, descriptor
provisioning, and snapshot and migration are all deferred.