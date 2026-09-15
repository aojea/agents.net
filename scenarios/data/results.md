# Historical Component Measurements

**Original report timestamp:** 2026-09-12T19:45:46Z

**Interpretation corrected:** September 15, 2026; measurements not rerun

**Reported host:** Linux x86_64, 96 logical CPUs, 236 GiB RAM

These values are retained from the previous checked-in report. Raw per-request
samples were not retained in that report, and the figures have not been
independently reproduced during the design review. The old MicroVM and native
runtime labels were inaccurate. See the [actual topologies](../README.md).

## Reported HTTPS Transfers

The reported workload was a local HTTPS `/ping`, using five rounds of 20 fresh
curl requests, five warmups, and three 50 MiB `/stream` transfers. Milestone
columns are cumulative curl times from transfer start. They are not separate
protocol phase durations; proxy cases also have different milestone semantics.

| ID | Actual experiment | Name lookup milestone (ms) | Connect milestone (ms) | TLS milestone (ms) | Total p50 (ms) | Total p99 (ms) | Throughput (MiB/s) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 01 | Container TUN + UDS | 0.67 | 1.14 | 3.98 | 4.42 | 5.98 | 175.27 |
| 02 | Host explicit TCP proxy | 0.02 | 0.10 | 2.33 | 2.67 | 4.30 | 592.09 |
| 03 | Docker bridge | 0.34 | 0.43 | 3.05 | 3.39 | 4.84 | 579.27 |
| 04 | Namespace TUN + local VSOCK | 0.72 | 1.24 | 3.58 | 4.09 | 6.18 | 181.27 |
| 07 | Namespace forwarder + local VSOCK | 0.02 | 0.09 | 2.77 | 3.21 | 5.33 | 603.44 |
| 05 | Namespace slirp4netns | 0.57 | 0.86 | 2.86 | 3.18 | 4.54 | 403.02 |
| 06 | Docker bridge with unused TAP | 0.33 | 0.42 | 3.03 | 3.30 | 4.45 | 602.14 |

Scenario 08 was a host TAP permission probe, not a transfer benchmark. No eBPF
scenario was measured. There was no native Sentry implementation or booted VM.

## Reported Round Summaries

| ID | Round 1 p50 (ms) | Round 2 | Round 3 | Round 4 | Round 5 | Reported CV (%) |
| --- | --- | --- | --- | --- | --- | --- |
| 01 | 4.79 | 4.38 | 4.29 | 4.42 | 4.50 | 4.29 |
| 02 | 2.83 | 2.67 | 2.61 | 2.71 | 2.61 | 3.34 |
| 03 | 3.25 | 3.50 | 3.41 | 3.39 | 3.35 | 2.67 |
| 04 | 4.00 | 4.11 | 3.82 | 4.23 | 4.03 | 3.75 |
| 07 | 3.35 | 3.13 | 3.24 | 3.21 | 3.27 | 2.51 |
| 05 | 3.10 | 3.15 | 3.11 | 3.21 | 3.31 | 2.75 |
| 06 | 3.45 | 3.32 | 3.32 | 3.27 | 3.30 | 2.10 |

Variation across rounds is descriptive, not proof of architectural causality or
production tail latency. No host-state or cryptographic-identity conclusions
follow from these numbers.
