#!/usr/bin/env bash
# agents.net conformance driver for the reference boundary
# (sdk/cmd/connect-proxy). The boundary loads the policy descriptor
# directly; hints map to listener flags.
#
#   connect-proxy.sh start <policy.json> <listen-url> <audit-path> <hints.json>
#   connect-proxy.sh stop
set -euo pipefail

state="${AGENTS_NET_DRIVER_STATE:?AGENTS_NET_DRIVER_STATE must be set by the harness}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
bin="${CONNECT_PROXY:-$state/connect-proxy}"

hint_flags() {
	python3 - "$1" <<'PY'
import json, sys
hints = json.load(open(sys.argv[1])) if sys.argv[1] else {}
args = []
if hints.get("wire") == "h2":
    args.append("-h2")
if "max_connections" in hints:
    args += ["-max-connections", str(hints["max_connections"])]
if "max_streams" in hints:
    args += ["-max-streams", str(hints["max_streams"])]
if "generation" in hints:
    args += ["-generation", str(hints["generation"])]
tls = hints.get("tls") or {}
for key, flag in (("cert", "-tls-cert"), ("key", "-tls-key"), ("client_ca", "-tls-client-ca")):
    if key in tls:
        args += [flag, tls[key]]
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
	while IFS= read -r -d '' arg; do args+=("$arg"); done < <(hint_flags "$hints")
	"$bin" -listen "$listen" -policy "$policy" "${args[@]}" >"$audit" 2>"$state/connect-proxy.log" &
	echo $! >"$state/pid"
	host_port=${listen#tcp://}
	host=${host_port%:*} port=${host_port##*:}
	for _ in $(seq 1 100); do
		if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then
			exit 0
		fi
		if ! kill -0 "$(cat "$state/pid")" 2>/dev/null; then
			# A rejected descriptor is a conformance failure, not an unsupported feature.
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
