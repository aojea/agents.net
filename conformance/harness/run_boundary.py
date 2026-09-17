#!/usr/bin/env python3
"""agents.net conformance harness: boundary role, HTTP/1.1 groups.

Runs the fixture cases whose "harness" is h1, h1-busy, or h1-proxystatus
against an implementation under test (IUT) started by a driver script.
The harness provides the upstream echo listener, renders each policy
descriptor, captures the IUT's audit output, and checks status, reason
token, upstream dial count, relayed bytes, and audit records.

Driver contract (executable, called with AGENTS_NET_DRIVER_STATE set to a
private directory):
  driver start <policy.json> <listen-url> <audit-path> <hints.json>
      Start the IUT listening on <listen-url> with the descriptor and
      hints, writing one audit JSON object per line to <audit-path>.
      Return 0 once the listener answers requests; return 3 if the
      descriptor uses features the IUT cannot express.
  driver stop
      Stop the IUT and wait for it to exit.
"""

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

PAYLOAD = "after-head"
NESTED = "CONNECT evil.test:443 HTTP/1.1\r\nHost: evil.test:443\r\nSandbox-Id: admin\r\n\r\n"
PAD = "a" * 70000
HEAD_LIMIT = 1 << 16
AUTOMATED = ("h1", "h1-busy", "h1-proxystatus")
AUDIT_FIELDS = {
    "agents_net_audit", "ts", "listener", "sandbox", "generation", "policy", "wire",
    "transport", "direction", "destination", "address", "peer", "rule", "decision",
    "reason", "meta",
}


class Upstream:
    """Echo listener on 127.0.0.1 and, when available, [::1] on one port."""

    def __init__(self):
        self.lock = threading.Lock()
        self.accepts = 0
        v4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        v4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        v4.bind(("127.0.0.1", 0))
        v4.listen(16)
        self.port = v4.getsockname()[1]
        self.listeners = [v4]
        self.ipv6 = False
        try:
            v6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            v6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            v6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            v6.bind(("::1", self.port))
            v6.listen(16)
            self.listeners.append(v6)
            self.ipv6 = True
        except OSError:
            pass
        for ln in self.listeners:
            threading.Thread(target=self._serve, args=(ln,), daemon=True).start()

    def _serve(self, ln):
        while True:
            try:
                conn, _ = ln.accept()
            except OSError:
                return
            with self.lock:
                self.accepts += 1
            threading.Thread(target=self._echo, args=(conn,), daemon=True).start()

    @staticmethod
    def _echo(conn):
        conn.settimeout(10)
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()

    def count(self):
        with self.lock:
            return self.accepts


class Audit:
    """Incremental reader of the IUT's audit file."""

    def __init__(self, path):
        self.path = path
        self.offset = 0

    def mark(self):
        try:
            self.offset = os.path.getsize(self.path)
        except OSError:
            self.offset = 0

    def new_records(self, wait_for_one, deadline=2.0):
        end = time.monotonic() + deadline
        while True:
            try:
                with open(self.path, "rb") as f:
                    f.seek(self.offset)
                    data = f.read()
            except OSError:
                data = b""
            lines = [ln for ln in data.split(b"\n") if ln.strip()]
            if lines or not wait_for_one or time.monotonic() > end:
                break
            time.sleep(0.05)
        records = []
        for ln in lines:
            try:
                records.append(json.loads(ln))
            except ValueError:
                records.append({"_unparsable": ln.decode("utf-8", "replace")})
        return records


def audit_violations(rec):
    problems = []
    if "_unparsable" in rec:
        return ["audit line is not JSON: " + rec["_unparsable"][:80]]
    for key in ("ts", "sandbox", "policy", "wire", "decision"):
        if not rec.get(key):
            problems.append("missing " + key)
    for key in rec:
        if key not in AUDIT_FIELDS:
            problems.append("unknown field " + key)
    if rec.get("wire") not in ("h1", "h2"):
        problems.append("wire must be h1 or h2")
    decision = rec.get("decision")
    if decision not in ("allow", "block", "fail"):
        problems.append("decision must be allow, block, or fail")
    if "transport" in rec and rec["transport"] not in ("tcp", "udp"):
        problems.append("transport must be tcp or udp")
    if decision in ("block", "fail") and not rec.get("reason"):
        problems.append("reason required for " + str(decision))
    if decision == "allow":
        for key in ("address", "transport", "destination"):
            if not rec.get(key):
                problems.append("allow record missing " + key)
    reason = rec.get("reason")
    if reason and not re.fullmatch(r"[a-z0-9-]{1,32}", reason):
        problems.append("reason token syntax: " + reason)
    for key, value in rec.items():
        if key != "meta" and key != "agents_net_audit" and not isinstance(value, str):
            problems.append(key + " must be a string")
    return problems


def render(value, ctx):
    if isinstance(value, str):
        if value == "{port}":
            return ctx["port"]
        for key, repl in ctx.items():
            value = value.replace("{" + key + "}", str(repl))
        return value
    if isinstance(value, list):
        return [render(v, ctx) for v in value]
    if isinstance(value, dict):
        return {k: render(v, ctx) for k, v in value.items()}
    return value


def parse_head(head):
    text = head.decode("latin-1")
    lines = text.split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/1."):
        raise ValueError("bad status line: " + lines[0])
    status = int(parts[1])
    headers = {}
    for line in lines[1:]:
        if not line:
            continue
        name, _, val = line.partition(":")
        headers.setdefault(name.strip().lower(), []).append(val.strip())
    return status, headers


def parse_proxy_status(value):
    member, _, params = value.partition(";")
    out = {"name": member.strip()}
    for param in params.split(";"):
        key, _, val = param.strip().partition("=")
        if key:
            out[key] = val.strip().strip('"')
    return out


def read_head(sock):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("connection closed before a response head (%d bytes)" % len(buf))
        buf += chunk
        if len(buf) > HEAD_LIMIT:
            raise ValueError("response head exceeds limit")
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head, rest


def read_exact(sock, n, already):
    buf = already
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def one_of(expected, actual):
    if isinstance(expected, list):
        return actual in expected
    return actual == expected


def check_common(case, ctx, status, headers, upstream, before, audit, problems):
    expect = case["expect"]
    if not one_of(expect.get("status"), status):
        problems.append("status %s, want %s" % (status, expect.get("status")))
    values = headers.get("proxy-status", [])
    proxy_status = parse_proxy_status(values[0]) if values else {}
    token = proxy_status.get("reason")
    if not 200 <= status < 300:
        if len(values) != 1:
            problems.append("%d Proxy-Status fields, want exactly one" % len(values))
        elif "," in values[0]:
            problems.append("Proxy-Status has more than one member")
        if values and not proxy_status.get("error"):
            problems.append("Proxy-Status lacks an error parameter")
        if values and not token:
            problems.append("Proxy-Status lacks a reason parameter")
    elif values:
        problems.append("Proxy-Status on a 2xx response")
    want_reason = expect.get("reason")
    if want_reason is None or want_reason == [None]:
        if token:
            problems.append("unexpected reason token %r" % token)
    elif not one_of(want_reason, token):
        problems.append("reason %r, want %s" % (token, want_reason))
    if "proxy_status" in expect:
        for key, val in expect["proxy_status"].items():
            if proxy_status.get(key) != val:
                problems.append("Proxy-Status %s=%r, want %r" % (key, proxy_status.get(key), val))
    # Upstream dials: allow the accept loop a moment to catch up.
    want_dials = expect.get("dials")
    max_dials = expect.get("dials_max")
    end = time.monotonic() + 2.0
    while want_dials is not None and upstream.count() - before < want_dials and time.monotonic() < end:
        time.sleep(0.02)
    if want_dials is None:
        time.sleep(0.3)
    dials = upstream.count() - before
    if want_dials is not None and dials != want_dials:
        problems.append("upstream dials %d, want %d" % (dials, want_dials))
    if max_dials is not None and dials > max_dials:
        problems.append("upstream dials %d, want at most %d" % (dials, max_dials))
    # Audit.
    want_audit = expect.get("audit")
    records = audit.new_records(wait_for_one=want_audit is not None)
    for rec in records:
        for violation in audit_violations(rec):
            problems.append("audit: " + violation)
    if want_audit is not None:
        if not records:
            problems.append("no audit record written")
        else:
            rec = records[-1]
            for key, val in render(want_audit, ctx).items():
                if key == "address_not_in":
                    addr = rec.get("address", "")
                    for banned in val:
                        if addr.startswith(banned):
                            problems.append("audit address %r is a denied address" % addr)
                elif rec.get(key) != val:
                    problems.append("audit %s=%r, want %r" % (key, rec.get(key), val))


def run_h1(case, ctx, boundary, upstream, audit):
    problems = []
    raw = render(case["request"]["raw"], ctx)
    before = upstream.count()
    audit.mark()
    sock = socket.create_connection(boundary, timeout=30)
    try:
        sock.sendall(raw.encode("latin-1"))
        head, rest = read_head(sock)
        status, headers = parse_head(head)
        if 200 <= status < 300 and case["expect"].get("echoed"):
            _, _, after = raw.partition("\r\n\r\n")
            want = after.encode("latin-1")
            sock.settimeout(5)
            got = read_exact(sock, len(want), rest)
            if got != want:
                problems.append("relayed bytes differ (%d of %d bytes)" % (len(got), len(want)))
        elif rest:
            problems.append("%d unexpected bytes after a non-2xx head" % len(rest))
    finally:
        sock.close()
    check_common(case, ctx, status, headers, upstream, before, audit, problems)
    return problems


def run_h1_busy(case, ctx, boundary, upstream, audit):
    problems = []
    held = []
    before = upstream.count()
    audit.mark()
    try:
        for _ in range(int(case["request"].get("hold", 1))):
            held.append(socket.create_connection(boundary, timeout=10))
        time.sleep(0.2)
        sock = socket.create_connection(boundary, timeout=10)
        try:
            head, _ = read_head(sock)
            status, headers = parse_head(head)
        finally:
            sock.close()
    finally:
        for h in held:
            h.close()
    check_common(case, ctx, status, headers, upstream, before, audit, problems)
    return problems


RUNNERS = {"h1": run_h1, "h1-proxystatus": run_h1, "h1-busy": run_h1_busy}


class Driver:
    def __init__(self, path, state_dir):
        self.path = path
        self.env = dict(os.environ, AGENTS_NET_DRIVER_STATE=state_dir)
        self.running = False

    def start(self, policy_path, listen_url, audit_path, hints_path):
        proc = subprocess.run([self.path, "start", policy_path, listen_url, audit_path, hints_path],
                              env=self.env, capture_output=True, text=True)
        self.running = proc.returncode == 0
        return proc.returncode, (proc.stderr or proc.stdout).strip()

    def stop(self):
        if self.running:
            subprocess.run([self.path, "stop"], env=self.env, capture_output=True, text=True)
            self.running = False


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fixtures", default=os.path.join(os.path.dirname(__file__), "..", "fixtures", "boundary.json"))
    ap.add_argument("--driver", required=True, help="IUT driver executable")
    ap.add_argument("--results", help="write JSON lines results here")
    ap.add_argument("--case", help="regular expression on case id")
    ap.add_argument("--group", help="run only this group")
    ap.add_argument("--keep-going", action="store_true", help="continue after a driver start failure")
    args = ap.parse_args()

    with open(args.fixtures) as f:
        fixtures = json.load(f)
    upstream = Upstream()
    ctx = {
        "port": upstream.port,
        "upstream4": "127.0.0.1:%d" % upstream.port,
        "upstream6": "[::1]:%d" % upstream.port,
        "payload": PAYLOAD,
        "nested": NESTED,
        "pad": PAD,
    }
    state_dir = tempfile.mkdtemp(prefix="agents-net-conformance.")
    driver = Driver(os.path.abspath(args.driver), state_dir)
    results = []
    current_policy = None
    audit = None
    boundary = None
    start_failure = None

    def record(case, result, detail=""):
        results.append({"id": case["id"], "group": case["group"], "result": result, "detail": detail})
        print("%-12s %-11s %s%s" % (case["id"], result, case["title"], (" -- " + detail) if detail else ""))

    try:
        for case in fixtures["cases"]:
            if args.case and not re.search(args.case, case["id"]):
                continue
            if args.group and case["group"] != args.group:
                continue
            if case.get("harness") not in AUTOMATED:
                record(case, "manual", "harness type %r not automated" % case.get("harness"))
                continue
            if "ipv6" in case.get("requires", []) and not upstream.ipv6:
                record(case, "skip", "no IPv6 loopback")
                continue
            if case["policy"] != current_policy:
                driver.stop()
                start_failure = None
                policy = fixtures["policies"][case["policy"]]
                descriptor = render(policy["descriptor"], ctx)
                hints = policy.get("iut", {})
                policy_path = os.path.join(state_dir, case["policy"] + ".json")
                hints_path = os.path.join(state_dir, case["policy"] + ".hints.json")
                audit_path = os.path.join(state_dir, case["policy"] + ".audit.jsonl")
                with open(policy_path, "w") as f:
                    json.dump(descriptor, f, indent=2)
                with open(hints_path, "w") as f:
                    json.dump(hints, f)
                open(audit_path, "w").close()
                port = free_port()
                boundary = ("127.0.0.1", port)
                code, msg = driver.start(policy_path, "tcp://127.0.0.1:%d" % port, audit_path, hints_path)
                current_policy = case["policy"]
                audit = Audit(audit_path)
                if code == 3:
                    start_failure = ("unsupported", "driver: " + msg)
                elif code != 0:
                    start_failure = ("fail", "driver start exit %d: %s" % (code, msg))
                    if not args.keep_going:
                        record(case, *start_failure)
                        break
            if start_failure:
                record(case, *start_failure)
                continue
            try:
                problems = RUNNERS[case["harness"]](case, ctx, boundary, upstream, audit)
            except Exception as exc:  # report, do not abort the run
                problems = ["exception: %r" % (exc,)]
            record(case, "pass" if not problems else "fail", "; ".join(problems))
    finally:
        driver.stop()

    counts = {}
    for r in results:
        counts[r["result"]] = counts.get(r["result"], 0) + 1
    print("\n" + ", ".join("%s=%d" % kv for kv in sorted(counts.items())))
    if args.results:
        with open(args.results, "w") as f:
            for r in results:
                f.write(json.dumps(r) + "\n")
    shutil.rmtree(state_dir, ignore_errors=True)
    return 1 if counts.get("fail") else 0


if __name__ == "__main__":
    sys.exit(main())
