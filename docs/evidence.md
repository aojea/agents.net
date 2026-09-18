<!-- Informative. Not part of the specification. -->
# Test Evidence

**Informative.** What has been executed, where, and what it does not prove. The conformance suite that turns these into repeatable claims is [conformance/](../conformance/README.md).

The scenario suite tests containers, namespaces, local VSOCK connections, and
two Firecracker microVMs. It does not measure native runtime interception.

- [scenarios/data/results.md](../scenarios/data/results.md) - Historical 100-flow HTTPS summaries; not remeasured during the design correction.
- [scenarios/README.md](../scenarios/README.md) - Actual scenario inventory, prerequisites, and measurement limitations.
- [conformance/README.md](../conformance/README.md) - Conformance suite: profiles per role, black-box fixtures with expected status, reason token, upstream dial count, and audit record, a driver contract for any boundary implementation, and the runtime audit checklist. Its README records the reference's current pass/fail count.

## 1. Security Verification Matrix

Each test must assert both the decision and the absence of an unauthorized
side effect, such as an upstream dial, credential use, or successful tunnel.
The following matrix separates existing evidence from required follow-up work.

The local model's acceptance checks are:

1. Run two isolated sandboxes with different dedicated sockets and policies. Neither the workloads nor their adapters can access the other endpoint or host management sockets, including under the runtime's guest-root and UID-mapping configuration.
2. Send equivalent requests through each adapter and directly to its assigned socket. Allowed destinations succeed and denied destinations fail regardless of identity headers or adapter replacement. Include hostname and IPv4/IPv6 literal destinations.
3. Reject malformed requests and forbidden resolved addresses before any upstream connection or payload delivery. Check ports, UDP enablement, retries, and resource bounds.
4. Stop either adapter and change guest routes. No direct external path becomes available. For namespace mode, verify confinement beyond the network namespace as well as redirection behavior.
5. Terminate a dedicated boundary while tunnels and dials are active. No flow survives completed revocation, and restarting or reusing a sandbox name does not give old connections access to the replacement endpoint.

These are required checks, not a statement of completed test coverage. FD
registration, mTLS identity dispatch, attestation, credential injection, and
ingress checks apply only when those extensions are used.

| Property | Check | Current coverage |
| --- | --- | --- |
| Dedicated endpoint binding | Two isolated sandboxes cannot reach each other's sockets or select each other's policies | Firecracker scenario (Section 2): two VMs with disjoint policies; the same request succeeds in one and is refused in the other, and an unbound boundary port is reset by the VMM. Container and namespace variants not tested end to end |
| Channel attribution | Forge tenant headers in an actual CONNECT request; verify trusted identity and unchanged policy | Firecracker scenario sends a raw CONNECT with a forged `Sandbox-Id` over the VM channel and receives 403 under the listener's policy; scenario Unix-socket test verifies kernel-derived audit identity |
| Mutual authentication | Valid client succeeds; anonymous, wrong issuer, wrong server identity, invalid validity period, wrong key usage, wrong key, and wrong ALPN fail before tunnel delivery | [mTLS tests](../sdk/pkg/tun2connect/connect_tls_test.go); authorized-tenant identity mapping remains unimplemented |
| Authentication configuration | Incomplete certificate/key settings or client CA without TLS fail at startup | [Reference boundary tests](../sdk/cmd/connect-proxy/main_test.go) |
| Transport integrity | Modify a protected TLS record; the tunnel fails without echoing modified application data | TLS record-corruption test in the mTLS suite |
| Destination authorization | Named and literal IPv4/IPv6 allow/deny cases over TCP and UDP | Engine, boundary, and live namespace tests; hostname requests are resolved and address-checked by the reference boundary; per-port rules tested on names, literals, prefixes, and the wildcard, and live in the Firecracker scenario |
| CONNECT parser safety | Conflicting authorities, malformed ports, duplicate framing, unsupported extended protocols, URI encoding, fragmented heads | [Negative corpus](../sdk/cmd/connect-proxy/corpus_test.go): missing, duplicate, and conflicting `Host`; no, zero, out-of-range, and named ports; userinfo, path, query, absolute-form, empty and unbracketed IPv6 authorities; HTTP/2.0 and HTTP/0.9 request lines; extra spaces, tab in method, whitespace before a header colon, oversized head; trailing bytes on a denied request; bad upgrade tokens and templates. Each asserts the status, reason, and upstream dial count. Fuzz targets for the head parser, authorization, policy parsers, template, capsule reader, and DNS handler run with [test_fuzz.sh](../sdk/test_fuzz.sh); HTTP/2 framing is not fuzzed here |
| Payload separation | Send nested CONNECT and forged identity-looking bytes inside an authorized tunnel; verify unchanged opaque delivery and no new authority | Reference boundary test over HTTP/1.1 and HTTP/2 with a real upstream socket |
| DNS/address safety | Rebinding, mixed permitted/forbidden A/AAAA results, mapped addresses, retries, redirects, static mappings | Reference boundary tests with a substituted resolver: loopback, private, link-local/metadata, mapped, NAT64, shared, reserved, multicast, and mixed answers are denied or filtered and the checked address is dialed; gateway redirect and retry tests required |
| Optional FD registration | Wrong registrant, wrong descriptor type/count, truncation, inherited copies, stale generation, restart | Not implemented; not required by the local model |
| Tenant separation | A cannot use B's endpoint, policy, key, signing service, or ingress route | Endpoint and policy separation shown for two Firecracker VMs; keys, signing services, and ingress route binding not implemented |
| Credentials | No key in guest, logs, errors, or redirects; every reused request reauthorized | Demo injection unit tests only; production gateway checks required |
| Failure and revocation | Proxy loss, missing policy, channel closure, retained FDs, policy update, certificate expiry, draining | Firecracker scenario: killing one VM's boundary during a rate-limited download ends the transfer partway (curl exit 55 after about 6 MB), the old socket refuses connections, the other VM's boundary keeps enforcing, and a replacement boundary on the same path with an empty policy decides the guest's next request (audit shows the new policy version). Refusal and namespace shutdown tests. Draining, certificate expiry, and controller-driven policy update are not implemented |
| Resource limits | Slow heads, oversized capsules, stream floods, DNS growth, stalled peers, UDP amplification | Request-head deadline, connection budget (503 before the head is read, slot released on close), tunnel idle timeout on HTTP/1.1 and HTTP/2, HTTP/2 stream cap, capsule bounds, synthetic-name limit; multi-tenant overload tests required |
| Software integrity | Wrong signer/digest, modified policy, stale update, replayed attestation, wrong session key | Not implemented; depends on deployment verifier |
| Ingress | Caller auth, authorized service only, stale route rejection, port restrictions, namespace return path | Demo and Firecracker deliveries reach the guest loopback listener; the launcher joins streams only to its pinned port (unit test and Firecracker scenario); caller authentication and stale-route rejection are not implemented; namespace reverse channel is not implemented |

Live namespace tests exercise Linux veth redirection, not a VM hypervisor or
confidential-computing boundary. The Firecracker scenario exercises the KVM and
virtio-vsock boundary on one host; it does not attest the guest or test other
VMMs. A full security review must also cover the
controller, credential service, runtime configuration, and deployed proxy.

Run the authentication, integrity, payload, and literal-destination checks:

```bash
go -C sdk test -race -count=1 ./pkg/tun2connect ./cmd/connect-proxy
```

Run the fuzz targets for a bounded time each (regression inputs under
`testdata/fuzz` are replayed by ordinary `go test`):

```bash
FUZZTIME=1m sdk/test_fuzz.sh
```

These tests create temporary test certificates and local sockets. They do not
exercise a production issuer, software attestation service, or tenant controller.

## 2. Firecracker Two-Sandbox Test

[scenarios/09-firecracker-vsock/run.sh](../scenarios/09-firecracker-vsock/run.sh)
boots two Firecracker microVMs on KVM from a shared read-only Alpine root
filesystem with the launcher as `/sbin/init`. Neither VM has a network device.
Each VM has its own `uds_path`, and its boundary is one `connect-proxy`
process listening on `<uds_path>_1024`, which is where Firecracker delivers
guest connections to CID 2 port 1024. VM A's policy permits
`test.example.com` on port 9443 only, statically mapped to a host loopback
HTTPS server; VM B's policy is empty. The guest workload runs `curl` through
the TUN adapter and `socat` directly on the vsock channel.

| Check | VM A (permitted) | VM B (empty policy) |
| --- | --- | --- |
| `curl https://test.example.com:9443/ping` through the adapter | 200; audit records the dial to the checked address | Connection refused; audit `not-on-allowlist` |
| `curl https://denied.example:9443/ping` | Refused | Refused |
| `curl http://test.example.com:80/ping` (allowed name, unlisted port) | Refused; audit `port-not-allowed` | Refused |
| `curl https://192.0.2.10:9443/ping` (literal, unlisted) | Refused; audit `ip-not-on-allowlist` | Refused |
| Raw `CONNECT denied.example:443` with `Sandbox-Id: forged-admin` on vsock port 1024 | `403 Forbidden` | `403 Forbidden` |
| Raw connect to vsock port 1025 (never bound on the host) | Reset by the VMM | Reset by the VMM |
| Host delivers `GET /index.html` through `<uds_path>` → guest vsock 5000 → loopback 8081 | 200, guest body | 200, guest body |
| Same handshake naming loopback port 22 | `ERR port not permitted` from the launcher | `ERR port not permitted` |
| Boundary process killed during a 2 MB/s download of a 4 GiB body | Transfer ends after a few megabytes with a curl error; the old socket path refuses connections | Unaffected: a raw `CONNECT` to VM B's socket still receives `403` |
| Replacement boundary started on the same path with an empty policy descriptor and a new `version` | Guest's next `curl` to the previously allowed name is refused; the replacement's audit records the block under the new version | Refused as before |

Every boundary record carries the `sandbox` and `version` values of the
descriptor the script installed on that VM's listener; the test checks that
no record is missing them.

The test passes on Firecracker v1.16.1 with guest kernel 6.18.41 from the
Firecracker CI artifacts. It does not test guest attestation, snapshot and
restore, other VMMs, draining, or resource exhaustion.
