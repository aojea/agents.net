# agents.net Conformance Suite

**Suite version:** 0.1  
**Tests:** [agents.net specification, version 1 (draft)](../spec/draft/index.md)  
**Fixtures:** [fixtures/](fixtures/) — **Schemas:** [spec/draft/schema/](../spec/draft/schema/) — **Harness:** [harness/](harness/)

This suite tests an implementation of one agents.net role (boundary,
adapter, controller, or ingress gateway) against the draft specification.
A conformance claim names the role, the profiles, and the suite version,
and comes with two documents: the results file the harness writes and
the implementation statement described in
[registries.md §4](../spec/draft/registries.md#4-implementation-statement).
The implementation is conformant when every case in the claimed profiles
has the result `pass` or `skip` and you have recorded every item of the
runtime audit checklist that applies to the role.

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

Each profile is tested by one group of cases. The last column shows
which of them harness 0.1 automates.

| Profile | Group | Cases | Fixture | Automated in 0.1 |
| --- | --- | --- | --- | --- |
| `boundary-core` | B-CORE | 01–62 | [boundary.json](fixtures/boundary.json) | All except B-CORE-49 (`manual`) |
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

A profile's prerequisite profiles, listed in
[registries.md §1](../spec/draft/registries.md#1-roles-and-profiles),
must be claimed along with it. Some cases carry a `requires` list naming
a capability (`ipv6`, `udp_enabled`, `synthetic_dns`, `socks5`,
`diagnostics`, `snapshot`, or `two_sandboxes`). When the environment or
your implementation statement lacks that capability, the case's result
is `skip`.

## 3. Harness Architecture

The harness reads the fixtures, starts and stops the IUT through the
driver, sends requests, and writes one result line per case:

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

The harness runs the upstream, the resolver, the audit reader, and the
request clients described below. You write the driver that starts and
stops the IUT.

The upstream is an echo listener on `127.0.0.1` and, when IPv6 loopback
is available, on `[::1]`, both on the same port `{port}`. It counts the
connections it accepts; a case's `dials` is the number of accepts
attributable to that case.

The resolver is a DNS server the harness runs. The driver receives its
address in the hints file as `{"dns": "127.0.0.1:PORT"}` and configures
the IUT to use it. The resolver answers A and AAAA queries for the names
a `dns` case defines, and when the case tests rebinding it returns the
successive answers the case lists. Other record types get no data, and
unknown names get NXDOMAIN. It counts queries per name and type so the
harness can check `dns_queries_max`. The other cases steer names without
the resolver: the descriptor's `resolve` lists map names to addresses,
and `localhost` reaches loopback through the system hosts file.

The driver writes the IUT's audit lines to the file the harness names.
After each case the harness reads the lines appended during that case
and validates each one against
[audit.schema.json](../spec/draft/schema/audit.schema.json).

The clients are raw HTTP/1.1 over TCP, HTTP/2 with prior knowledge, a
connect-udp capsule client, and a TLS client that presents the
certificate set the case names.

The driver follows this contract:

```text
driver start <policy.json> <listen-url> <audit-path> <hints.json>
    exit 0   listener answers requests under the descriptor
    exit 3   descriptor uses a feature the IUT cannot express
    exit 1   failure (stderr explains)
driver stop
    IUT exited; audit file complete
```

`listen-url` is either `tcp://127.0.0.1:PORT` or `unix:///path`. The
hints file is a JSON object that may contain `max_connections`,
`max_streams`, `wire` (`h1` or `h2`), `dns`, and `tls` (the paths of the
server certificate, key, and client CA that `boundary-tls` uses).

### 3.2 Adapter Role

For the adapter role the harness stands in for the boundary. It listens
on the channel the controller assigned to the sandbox and launches the
workload probe inside the sandbox through the IUT's normal launch path.
It writes audit lines for its own decisions, and when a case sets
`harness_boundary` it returns the response that field names. For
`external_packets` it counts packets on every host interface other than
the boundary channel.

The probe runs inside the sandbox and exercises the adapter. Any
executable that follows this contract can serve as the probe, which lets
every provider run the same cases:

| Input | Meaning |
| --- | --- |
| `AGENTS_NET_PROBE_CASES` | Comma-separated case ids to run, default all |
| `AGENTS_NET_PROBE_TARGET4`, `AGENTS_NET_PROBE_TARGET6` | The harness boundary's upstream addresses (`{target4}`, `{target6}`) |
| `AGENTS_NET_PROBE_DENIAL_BOUND_MS` | The adapter's declared denial latency bound; a denial slower than this fails A-PKT-02 |
| `AGENTS_NET_PROBE_FEATURES` | Comma-separated capabilities present: `ipv6`, `udp_enabled`, `synthetic_dns`, `socks5`, `diagnostics` |

| Output | Meaning |
| --- | --- |
| Exit 0 | Every selected case passed or was skipped |
| Exit 1 | At least one case failed |
| Exit 3 | The probe could not run (missing inputs) |
| Standard output | One JSON object per case: `{"id", "result": "pass"\|"fail"\|"skip", "elapsed_ms", "detail"}` |

The harness combines the probe's output lines with its own audit records
to produce the case results.

### 3.3 Controller and Ingress Roles

For the controller role the harness drives whatever public interface the
controller offers (command line, API, or SDK) to create two sandboxes, A
and B, with the fixture's policies. It then inspects sockets, processes,
audit files, and packet captures as each case directs. For the ingress
role the harness plays the gateway on the ingress channel. Two controller
cases are procedures you run and report yourself, because harness 0.1
does not automate them: C-LOCAL-05 needs a packet capture, and
C-LOCAL-07 inspects the adapter's process environment.

## 4. Fixture Format

A fixture is a JSON file of cases. Each case looks like this:

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
| `expect.status` | Integer, list of acceptable values, `"2xx"`, `"4xx"` (400-499 other than 403), or a frame outcome such as `RST_STREAM:REFUSED_STREAM` |
| `expect.reason` | Reason token, list of acceptable tokens, or `null` for none; read from the `reason` parameter of `Proxy-Status`. Malformed-request cases accept the specific token or `malformed-request` |
| `expect.dials` / `dials_max` | Upstream accepts attributable to the case |
| `expect.echoed` | Bytes after the head were relayed and returned by the echo upstream |
| `expect.audit` | Subset of the last audit record written during the case; a list value accepts any member; `address_not_in` lists prefixes the dialed address must not start with |
| `expect.proxy_status` | Parameters the `Proxy-Status` member must carry |

The harness substitutes placeholders before it sends a request or renders
a descriptor. The boundary cases use `{port}`, `{upstream4}`,
`{upstream6}`, `{payload}`, `{nested}`, and `{pad}`, listed in the
fixture's `placeholders` object. Adapter and controller fixtures use
`{target4}`, `{target6}`, and `{udp_enabled}` for the harness boundary's
upstream addresses and configuration.

## 5. Pass Criteria

The harness marks an automated case `pass` when all of the following hold:

1. The status matches `expect.status`.
2. Every non-2xx response carries exactly one `Proxy-Status` field with one
   member whose name is an sf-token, an `error` parameter from the HTTP
   Proxy Error Types registry, and a `reason` parameter matching
   `[a-z0-9-]{1,32}`; the reason token matches `expect.reason`.
3. Upstream accepts equal `expect.dials` (or do not exceed `dials_max`).
4. For 2xx with `expect.echoed`, the bytes sent after the head come back
   unchanged; for non-2xx no bytes follow the response head.
5. Every audit line written during the case validates against the schema,
   and the last one contains `expect.audit`.

If the driver exits 3 for a case's descriptor, the case is
`unsupported`. In a conformance claim for that profile, `unsupported`
counts as `fail`.

## 6. Runtime Audit Checklist

The wire tests can't observe these properties, so you verify them by
inspecting the deployment. A controller or adapter claim lists each item
together with the evidence used. Each item names a control rather than a
platform mechanism; the evidence column gives Linux and macOS examples,
and on another platform you supply the equivalent.

| # | Item | Evidence |
| --- | --- | --- |
| 1 | The sandbox has no network interface other than one terminating in the adapter (packet) or none (explicit) | `ip link`, VMM configuration; macOS: sandbox profile denies `network-outbound` except the endpoint |
| 2 | Only the assigned boundary socket (or channel ports) is visible to the adapter; no other sandbox's socket, runtime socket, or management socket | Mount table, socket directory listing, VMM vsock configuration; macOS: sandbox profile file-read/write rules |
| 3 | Socket directory ownership and mode, UID/GID mapping, and privileges prevent another workload from connecting or replacing the endpoint | `stat`, `/proc/<pid>/status` capabilities, user namespace mapping; macOS: `stat`, per-sandbox user |
| 4 | The adapter and workload cannot open raw or packet sockets, trace other processes, or read other processes' memory | seccomp profile and `CapBnd`; macOS: sandbox profile denies `network-raw`, `process-info`, `mach-*` |
| 5 | Privileges the adapter needed only for setup are dropped and cannot be regained | Linux: `CapBnd` without `CAP_NET_ADMIN` after start; macOS: no elevated setup step, or the setup helper exits |
| 6 | Inherited descriptors are closed; the boundary socket is not passed to the workload | `/proc/<pid>/fd` of the workload; macOS: `lsof -p` |
| 7 | No Unix socket other than the assigned endpoint is reachable from the adapter, including abstract-namespace sockets where the platform has them | Network namespace inspection; macOS: sandbox profile |
| 8 | Boundary policy, binaries, configuration, and audit files are not writable by any sandbox | Mounts and modes |
| 9 | Revocation waits for process exit or flow termination before the path or identity is reused | Controller logs against audit timestamps |
| 10 | Audit sink is append-only from the boundary's view and protected from sandboxes | Sink configuration |

## 7. Running the Harness

Harness 0.1 automates the HTTP/1.1 boundary cases (`h1`, `h1-busy`, and
`h1-proxystatus`) and the `dns` resolver cases. To run it against the
reference boundary:

```bash
python3 conformance/harness/run_boundary.py \
    --driver conformance/harness/drivers/connect-proxy.sh \
    --results /tmp/agents-net-results.jsonl --keep-going
```

The [reference driver](harness/drivers/connect-proxy.sh) builds
`connect-proxy` on first use, or uses the binary named by
`$CONNECT_PROXY`, and starts it with `-policy <descriptor>`. It translates
the hints `dns`, `max_connections`, `max_streams`, `wire`, `generation`,
and `tls` into the corresponding flags. The driver is the only part of
the harness that is specific to the reference. To test your own
implementation, write a driver that follows the contract in section 3.1
and pass it with `--driver`.

[check_fixtures.py](harness/check_fixtures.py) validates every fixture
descriptor and the audit examples against the schemas. It needs the
`jsonschema` package. The [conformance workflow](../.github/workflows/conformance.yml)
runs the harness and the fixture check on every change to the suite, the
schemas, or the reference.

At this revision of the reference, all 60 automated `boundary-core` cases
pass and B-CORE-49 is reported as `manual`.

## 8. Reporting

The harness writes one JSON object per case to the results file:

```json
{"id": "B-CORE-37", "group": "boundary-core", "result": "pass", "detail": ""}
```

`result` is one of `pass`, `fail`, `skip`, `unsupported`, or `manual`. A
claim is worded "conforms to agents.net `boundary-core`, `boundary-h2` at
suite 0.1" and comes with the results file and the implementation
statement. For each `manual` case, record in the implementation
statement's `results` the procedure you followed and what you observed.

## 9. Existing Evidence

Where a case is also exercised by a test or scenario in this repository,
this table names it.

| Cases | Repository evidence |
| --- | --- |
| B-CORE-01–28, 30, 31, 50–52 | [corpus_test.go](../sdk/cmd/connect-proxy/corpus_test.go) negative corpus |
| B-CORE-33–45, 60 | [main_test.go](../sdk/cmd/connect-proxy/main_test.go) policy and resolver tests |
| B-CORE-54–59, 61, 62 | [policy_test.go](../sdk/cmd/connect-proxy/policy_test.go) suffix, depth, mixed-answer, and IDNA tests; harness resolver cases |
| B-CORE-46, B-H2-08 | Payload-separation tests over HTTP/1.1 and HTTP/2 |
| B-CORE-47, B-H2-04, C-LOCAL-02 | Firecracker scenario forged `Sandbox-Id` |
| B-CORE-48 | Connection budget test (503 before head) |
| B-H2-01, 02, 07 | HTTP/2 client and stream budget tests; Envoy interop |
| B-UDP-01, 02, 05 | Capsule and connect-udp tests |
| B-TLS-02–05, 07–09 | [connect_tls_test.go](../sdk/pkg/tun2connect/connect_tls_test.go) |
| A-PKT-01–07, 14 | Engine tests, live namespace integration, Firecracker and QEMU scenarios |
| A-PKT-09, 10 | [connect_test.go](../sdk/pkg/tun2connect/connect_test.go): any 2xx accepted, interim responses skipped and bounded |
| C-LOCAL-03, 04, C-VM-01, 02 | Firecracker scenario 09 revocation, unbound port, disjoint policies |
| C-LOCAL-05 | Route-flush smoke script; packet-capture assertion not implemented |
| I-ING-01–04 | [dialer_test.go](../sdk/cmd/tun2connect/dialer_test.go) ingress handshake test; Firecracker scenario delivery and unpinned-port refusal |
| B-MULTI, A-EXP, A-DIAG, C-SNAP, I-ING-05, 06 | None |
