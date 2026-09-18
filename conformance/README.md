# agents.net Conformance Suite

**Suite version:** 0.1  
**Tests:** [agents.net specification, version 1 (draft)](../spec/draft/index.md)  
**Fixtures:** [fixtures/](fixtures/) — **Schemas:** [spec/draft/schema/](../spec/draft/schema/) — **Harness:** [harness/](harness/)

A conformance claim names a role, one or more profiles, and this suite
version, and is accompanied by the results file and the implementation
statement of [registries.md §4](../spec/draft/registries.md#4-implementation-statement).
"Conformant" means every case of the claimed profiles whose result is not
`skip` has the result `pass`, and every item of the runtime audit checklist
that applies to the role is recorded.

## 1. Terms

| Term | Meaning |
| --- | --- |
| IUT | Implementation under test: a boundary, adapter, controller, or ingress gateway |
| Harness | The test program: supplies upstreams, a resolver where needed, request clients, and audit capture; never trusts the IUT's own account of a decision |
| Driver | An executable supplied by the implementer that starts and stops the IUT from a policy descriptor and reports unsupported descriptors |
| Fixture | A JSON file of cases with policies, requests, and expected observations |
| Case | One test with an identifier `<ROLE>-<GROUP>-<NN>` |
| Observation | A fact the harness can see from outside the IUT: status, fields, bytes relayed, upstream accepts, audit lines, process state, packets |

## 2. Profiles and Groups

| Profile | Group | Cases | Fixture | Automated in 0.1 |
| --- | --- | --- | --- | --- |
| `boundary-core` | B-CORE | 01–60 | [boundary.json](fixtures/boundary.json) | HTTP/1.1 cases; `dns` and `manual` cases are not |
| `boundary-h2` | B-H2 | 01–08 | boundary.json | No |
| `boundary-udp` | B-UDP | 01–08 | boundary.json | No |
| `boundary-tls` | B-TLS | 01–09 | boundary.json | No |
| `boundary-multi` | B-MULTI | 01–04 | boundary.json | No |
| `adapter-packet` | A-PKT | 01–14 | [adapter.json](fixtures/adapter.json) | No |
| `adapter-udp` | A-UDP | 01–02 | adapter.json | No |
| `adapter-explicit` | A-EXP | 01–05 | adapter.json | No |
| `adapter-diagnostics` | A-DIAG | 01–02 | adapter.json | No |
| `controller-local` | C-LOCAL | 01–07 | [controller.json](fixtures/controller.json) | No |
| `controller-vm` | C-VM | 01–03 | controller.json | No |
| `controller-snapshot` | C-SNAP | 01–02 | controller.json | No |
| `ingress-gateway` | I-ING | 01–06 | [ingress.json](fixtures/ingress.json) | No |

A profile's prerequisite profiles ([registries.md §1](../spec/draft/registries.md#1-roles-and-profiles)) must be claimed with it. Cases
with `requires` are `skip` when the named capability is absent from the
environment or the implementation statement (`ipv6`, `udp_enabled`,
`synthetic_dns`, `socks5`, `diagnostics`, `snapshot`,
`two_sandboxes`).

## 3. Harness Architecture

```text
                       +----------------------------+
   fixtures ---------> |          harness           | ---- results (JSON lines)
                       |  h1 / h2 / capsule client  |
                       |  resolver (dns cases)      |
                       |  upstream echo v4 + v6     |
                       |  audit reader              |
                       +------+--------------+------+
                              |              ^
              start/stop      |              | audit lines
                              v              |
                       +------+--------------+------+
                       | driver  -->  IUT (boundary) |
                       +-----------------------------+
```

### 3.1 Boundary Role

The harness owns:

- **Upstream**: an echo listener on `127.0.0.1` and, when available, `[::1]`
  on one port `{port}`. It counts accepted connections. A case's `dials` is
  the number of accepts attributable to that case.
- **Resolver**: for `harness: dns` cases, a DNS server the IUT is configured
  to use; the driver receives its address in the hints file as
  `{"dns": "127.0.0.1:PORT"}`. Cases without a resolver steer names with
  the descriptor's `resolve` lists and with `localhost`, which the system
  resolver maps to loopback.
- **Audit capture**: the driver writes the IUT's audit lines to a file; the
  harness reads the lines appended during each case and validates each
  against [audit.schema.json](../spec/draft/schema/audit.schema.json).
- **Clients**: raw HTTP/1.1 over TCP; HTTP/2 prior knowledge; connect-udp
  capsule client; TLS client with the certificate set named by the case.

The driver owns the IUT. Its contract:

```text
driver start <policy.json> <listen-url> <audit-path> <hints.json>
    exit 0   listener answers requests under the descriptor
    exit 3   descriptor uses a feature the IUT cannot express
    exit 1   failure (stderr explains)
driver stop
    IUT exited; audit file complete
```

`listen-url` is `tcp://127.0.0.1:PORT` or `unix:///path`. The hints object
may contain `max_connections`, `max_streams`, `wire` (`h1` or `h2`), `dns`,
and `tls` (paths of server certificate, key, and client CA for `boundary-tls`).

### 3.2 Adapter Role

The harness plays the boundary. It listens on the channel the controller
assigned to the sandbox, runs the workload probe inside the sandbox through
the IUT's normal launch path, records audit lines for its own decisions, and
where a case says `harness_boundary`, produces the named response. Packet
counts on host interfaces other than the boundary channel are observations
for `external_packets`.

### 3.3 Controller and Ingress Roles

The harness drives the controller's public interface (command line, API, or
SDK) to create sandboxes A and B with the fixture's policies, then observes
sockets, processes, audit files, and packet captures as each case states.
For the ingress role the harness plays the gateway on the ingress channel.

## 4. Fixture Format

```json
{
  "id": "B-CORE-37",
  "group": "boundary-core",
  "title": "Hostname matching no rule is denied without resolution or dial",
  "spec": ["README 2.1(5)", "design 4.4"],
  "policy": "core",
  "harness": "h1",
  "requires": [],
  "request": {"raw": "CONNECT denied.test:{port} HTTP/1.1\r\nHost: denied.test:{port}\r\n\r\n"},
  "expect": {"status": 403, "reason": "not-on-allowlist", "dials": 0,
             "audit": {"decision": "block", "reason": "not-on-allowlist", "destination": "denied.test:{port}"}}
}
```

| Field | Content |
| --- | --- |
| `policy` | Key into the file's `policies`; each entry has a `descriptor` ([policy.md](../spec/draft/policy.md)) and optional `iut` hints |
| `harness` | `h1`, `h1-busy`, `h1-proxystatus`, `dns`, `h2`, `udp`, `tls`, `multi`, `manual` |
| `request.raw` | Bytes sent after connecting; `\r\n` as written; placeholders substituted |
| `request.dns` | For `dns` cases: name to address list, or list of successive answers for rebinding |
| `expect.status` | Integer, list of acceptable integers, `"2xx"`, or a frame outcome such as `RST_STREAM:REFUSED_STREAM` |
| `expect.reason` | Reason token, list of acceptable tokens, or `null` for none; read from the `reason` parameter of `Proxy-Status` |
| `expect.dials` / `dials_max` | Upstream accepts attributable to the case |
| `expect.echoed` | Bytes after the head were relayed and returned by the echo upstream |
| `expect.audit` | Subset of the last audit record written during the case; `address_not_in` lists prefixes the dialed address must not start with |
| `expect.proxy_status` | Parameters the `Proxy-Status` member must carry |

Placeholders: `{port}`, `{upstream4}`, `{upstream6}`, `{payload}`, `{nested}`,
`{pad}` as listed in each fixture's `placeholders`. Adapter and controller
fixtures use `{target4}`, `{target6}`, `{udp_enabled}` for the harness
boundary's upstream and configuration.

## 5. Pass Criteria

For every automated case:

1. The status matches `expect.status`.
2. Every non-2xx response carries exactly one `Proxy-Status` field with one
   member, an `error` parameter, and a `reason` parameter; the reason token
   matches `expect.reason`.
3. Upstream accepts equal `expect.dials` (or do not exceed `dials_max`).
4. For 2xx with `expect.echoed`, the bytes sent after the head come back
   unchanged; for non-2xx no bytes follow the response head.
5. Every audit line written during the case validates against the schema,
   and the last one contains `expect.audit`.

A case whose driver reported exit 3 is `unsupported`, which counts as `fail`
for a conformance claim of that profile.

## 6. Runtime Audit Checklist

These properties are not observable through the wire and are recorded per
deployment by inspection. A controller or adapter claim lists each item with
the evidence used.

| # | Item | Evidence |
| --- | --- | --- |
| 1 | The sandbox has no network interface other than one terminating in the adapter (packet) or none (explicit) | `ip link`, VMM configuration |
| 2 | Only the assigned boundary socket (or channel ports) is visible to the adapter; no other sandbox's socket, runtime socket, or management socket | Mount table, socket directory listing, VMM vsock configuration |
| 3 | Socket directory ownership and mode, UID/GID mapping, and capability set prevent another workload from connecting or replacing the endpoint | `stat`, `/proc/<pid>/status` capabilities, user namespace mapping |
| 4 | The adapter and workload cannot open raw or packet sockets, `ptrace` other processes, or read other processes' memory | seccomp profile, `CapBnd` |
| 5 | The adapter drops `CAP_NET_ADMIN` after device setup and cannot regain it | `CapBnd` after start |
| 6 | Inherited descriptors are closed; the boundary socket is not passed to the workload | `/proc/<pid>/fd` of the workload |
| 7 | Abstract Unix sockets outside the assigned endpoint are unreachable from the adapter | Network namespace inspection |
| 8 | Boundary policy, binaries, configuration, and audit files are not writable by any sandbox | Mounts and modes |
| 9 | Revocation waits for process exit or flow termination before the path or identity is reused | Controller logs against audit timestamps |
| 10 | Audit sink is append-only from the boundary's view and protected from sandboxes | Sink configuration |

## 7. Running the Harness

Version 0.1 automates the HTTP/1.1 boundary groups. Against the reference
boundary:

```bash
python3 conformance/harness/run_boundary.py \
    --driver conformance/harness/drivers/connect-proxy.sh \
    --results /tmp/agents-net-results.jsonl --keep-going
```

The [reference driver](harness/drivers/connect-proxy.sh) builds
`connect-proxy` on first use (or uses `$CONNECT_PROXY`) and starts it with
`-policy <descriptor>`; the hints `max_connections`, `max_streams`, `wire`,
`generation`, and `tls` map to the corresponding flags. Another
implementation conforms to the same contract with its own driver; nothing
else in the harness is specific to the reference.

Result at this revision of the reference: every automated `boundary-core`
case passes (52); the `dns` cases and B-CORE-49 are not automated by
harness 0.1.

## 8. Reporting

The results file has one JSON object per case:

```json
{"id": "B-CORE-37", "group": "boundary-core", "result": "pass", "detail": ""}
```

`result` is `pass`, `fail`, `skip`, `unsupported`, or `manual`. A claim
consists of the results file, the implementation statement, and the suite
version. Claims are stated as "conforms to agents.net `boundary-core`,
`boundary-h2` at suite 0.1". A `manual` case is reported with the procedure
followed and the observation, in the implementation statement's `results`.

## 9. Existing Evidence

| Cases | Repository evidence |
| --- | --- |
| B-CORE-01–28, 30, 31, 50–52 | [corpus_test.go](../sdk/cmd/connect-proxy/corpus_test.go) negative corpus |
| B-CORE-33–45, 60 | [main_test.go](../sdk/cmd/connect-proxy/main_test.go) policy and resolver tests |
| B-CORE-46, B-H2-08 | Payload-separation tests over HTTP/1.1 and HTTP/2 |
| B-CORE-47, B-H2-04, C-LOCAL-02 | Firecracker scenario forged `Sandbox-Id` |
| B-CORE-48 | Connection budget test (503 before head) |
| B-H2-01, 02, 07 | HTTP/2 client and stream budget tests; Envoy interop |
| B-UDP-01, 02, 05 | Capsule and connect-udp tests |
| B-TLS-02–05, 07–09 | [connect_tls_test.go](../sdk/pkg/tun2connect/connect_tls_test.go) |
| A-PKT-01–07, 14 | Engine tests, live namespace integration, Firecracker and QEMU scenarios |
| A-PKT-09, 10 | None; the reference client accepts only 200 and reads one response |
| C-LOCAL-03, 04, C-VM-01, 02 | Firecracker scenario 09 revocation, unbound port, disjoint policies |
| C-LOCAL-05 | Route-flush smoke script; packet-capture assertion not implemented |
| I-ING-01, 02 | Firecracker scenario with the textual handshake; HTTP CONNECT form not implemented |
| B-MULTI, A-EXP, A-DIAG, C-SNAP, I-ING-03–06 | None |
