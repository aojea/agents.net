#!/usr/bin/env bash
# agents.net conformance driver for the reference boundary
# (sdk/cmd/connect-proxy). Translates a policy descriptor into
# command-line flags; exits 3 when the descriptor uses features the flags
# cannot express (suffix rules, port ranges, per-rule transports).
#
#   connect-proxy.sh start <policy.json> <listen-url> <audit-path> <hints.json>
#   connect-proxy.sh stop
set -euo pipefail

state="${AGENTS_NET_DRIVER_STATE:?AGENTS_NET_DRIVER_STATE must be set by the harness}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
bin="${CONNECT_PROXY:-$state/connect-proxy}"

translate() {
	python3 - "$1" "$2" <<'PY'
import json, sys

policy = json.load(open(sys.argv[1]))
hints = json.load(open(sys.argv[2])) if sys.argv[2] else {}

def unsupported(msg):
    sys.stderr.write("unsupported descriptor: " + msg + "\n")
    sys.exit(3)

def ports_of(rule):
    ports = rule.get("ports")
    if ports is None:
        return [None]
    out = []
    for p in ports:
        if isinstance(p, str) and "-" in p:
            unsupported("port range " + p)
        out.append(int(p))
    return out

def with_port(host, port):
    if ":" in host and not host.startswith("["):
        host = "[" + host + "]"
    return host if port is None else "%s:%d" % (host, port)

udp = bool(policy.get("features", {}).get("udp"))
allow, allow_ip, resolve = [], [], []
for rule in policy.get("rules", []):
    transports = rule.get("transports", ["tcp"])
    if udp and sorted(transports) != ["tcp", "udp"]:
        unsupported("per-rule transport restriction with UDP enabled")
    if "suffix" in rule:
        unsupported("suffix rule " + rule["suffix"])
    for port in ports_of(rule):
        if "name" in rule:
            allow.append(with_port(rule["name"], port))
            for addr in rule.get("resolve", []):
                allow_ip.append(with_port(addr, port))
        elif "ip" in rule:
            allow_ip.append(with_port(rule["ip"], port))
        elif "cidr" in rule:
            allow_ip.append(with_port(rule["cidr"], port))
    if rule.get("resolve"):
        resolve.append(rule["name"] + "=" + "+".join(rule["resolve"]))
for exc in policy.get("resolved_addresses", []):
    for port in ports_of(exc):
        allow_ip.append(with_port(exc["cidr"], port))

args = ["-sandbox", policy.get("sandbox", ""), "-policy-version", policy["version"]]
if allow:
    args += ["-allow", ",".join(allow)]
if allow_ip:
    args += ["-allow-ip", ",".join(allow_ip)]
if resolve:
    args += ["-resolve", ",".join(resolve)]
if udp:
    args.append("-udp")
if hints.get("wire") == "h2":
    args.append("-h2")
if "max_connections" in hints:
    args += ["-max-connections", str(hints["max_connections"])]
if "max_streams" in hints:
    args += ["-max-streams", str(hints["max_streams"])]
sys.stdout.write("".join(a + "\0" for a in args))
PY
}

case "${1:-}" in
start)
	policy=$2 listen=$3 audit=$4 hints=${5:-}
	if [[ ! -x "$bin" ]]; then
		go -C "$repo/sdk" build -o "$bin" ./cmd/connect-proxy
	fi
	args=()
	if ! translate "$policy" "$hints" >"$state/flags"; then
		exit 3
	fi
	while IFS= read -r -d '' arg; do args+=("$arg"); done <"$state/flags"
	"$bin" -listen "$listen" "${args[@]}" >"$audit" 2>"$state/connect-proxy.log" &
	echo $! >"$state/pid"
	host_port=${listen#tcp://}
	host=${host_port%:*} port=${host_port##*:}
	for _ in $(seq 1 100); do
		if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then
			exit 0
		fi
		if ! kill -0 "$(cat "$state/pid")" 2>/dev/null; then
			cat "$state/connect-proxy.log" >&2
			exit 1
		fi
		sleep 0.05
	done
	echo "boundary did not become ready" >&2
	exit 1
	;;
stop)
	if [[ -f "$state/pid" ]]; then
		pid=$(cat "$state/pid")
		kill "$pid" 2>/dev/null || true
		for _ in $(seq 1 100); do
			kill -0 "$pid" 2>/dev/null || break
			sleep 0.05
		done
		rm -f "$state/pid"
	fi
	;;
*)
	echo "usage: $0 start <policy.json> <listen-url> <audit-path> <hints.json> | stop" >&2
	exit 2
	;;
esac
