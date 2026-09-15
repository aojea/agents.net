#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

metric() {
    local log_path="$1" key="$2"
    awk -F= -v key="${key}" '
        $1 == key && $2 ~ /^-?[0-9]+([.][0-9]+)?$/ { print $2; found=1; exit }
        END { if (!found) print "unknown" }
    ' "${log_path}"
}

write_report() {
    local run_dir="$1" index log_path
    local ids=(01 02 03 04 05 06 07)
    local labels=(
        "Container TUN + UDS"
        "Host explicit TCP proxy"
        "Docker bridge"
        "Namespace TUN + local VSOCK"
        "Namespace slirp4netns"
        "Docker bridge with unused TAP"
        "Namespace forwarder + local VSOCK"
    )
    {
        printf '# Component Experiment Results\n\n'
        printf 'Run metadata: [metadata.txt](metadata.txt). Raw samples and diagnostics are in the linked logs.\n\n'
        printf 'These experiments do not run VMs or native Sentry interception. Scenario 08 is only a TAP permission probe.\n\n'
        printf '| ID | Actual experiment | Samples | Lookup milestone p50 (ms) | Connect milestone p50 (ms) | TLS milestone p50 (ms) | Total p50 (ms) | Total p99 (ms) | Throughput (MiB/s) | Round p50 CV (%%) |\n'
        printf '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n'
        for index in "${!ids[@]}"; do
            log_path="${run_dir}/${ids[index]}.log"
            printf '| [%s](%s.log) | %s |' "${ids[index]}" "${ids[index]}" "${labels[index]}"
            for key in SAMPLE_COUNT DNS_P50_MS TCP_P50_MS TLS_P50_MS LATENCY_P50_MS LATENCY_P99_MS THROUGHPUT_MB_S P50_STABILITY_CV_PCT; do
                printf ' %s |' "$(metric "${log_path}" "${key}")"
            done
            printf '\n'
        done
        printf '\nCurl timings are cumulative milestones, not independent protocol phase durations. Explicit-proxy connection times refer to the proxy.\n'
        printf '\nCV describes observed variation, not statistical proof or a stability verdict. Missing values are unknown, never zero.\n'
        printf '\nNo host-state, cryptographic identity, security, or density conclusions are inferred from these measurements. See the scenario inventory for topology limitations.\n'
        printf '\nPermission probe: [08.log](08.log).\n'
    } > "${run_dir}/results.md"
}

run_scenario() {
    local run_dir="$1" id="$2" driver="$3"
    printf 'Running %s; output: %s/%s.log\n' "${driver}" "${run_dir}" "${id}"
    if "${SCRIPT_DIR}/${driver}/run.sh" > "${run_dir}/${id}.log" 2>&1; then
        if [[ "${id}" != 08 && "$(metric "${run_dir}/${id}.log" SAMPLE_COUNT)" == unknown ]]; then
            printf 'FAILED: %s returned no sample count; retaining raw output.\n' "${driver}" >&2
            return 1
        fi
    else
        printf 'FAILED: %s; retaining raw output in %s/%s.log\n' "${driver}" "${run_dir}" "${id}" >&2
        return 1
    fi
}

main() {
    local run_dir helper
    mkdir -p "${SCRIPT_DIR}/data" "${SCRIPT_DIR}/bin"
    run_dir=$(mktemp -d "${SCRIPT_DIR}/data/run-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")
    printf 'Component experiments only. Artifacts: %s\n' "${run_dir}"
    {
        date -u +%Y-%m-%dT%H:%M:%SZ
        uname -a
        go version
        python3 --version
        curl --version
        docker version --format '{{.Client.Version}} / {{.Server.Version}}'
        docker image inspect agentsnet-demo:latest --format '{{.Id}}'
        git -C "${REPO_ROOT}" rev-parse HEAD
        git -C "${REPO_ROOT}" status --short
    } > "${run_dir}/metadata.txt" 2>&1
    git -C "${REPO_ROOT}" diff HEAD -- > "${run_dir}/working-tree.patch"

    for helper in boundary-proxy target-server vsock-forwarder; do
        go -C "${REPO_ROOT}" build -o "${SCRIPT_DIR}/bin/${helper}" "./scenarios/cmd/${helper}"
    done
    CGO_ENABLED=0 go -C "${REPO_ROOT}" build -o "${REPO_ROOT}/demo/tun2connect" ./tun2connect/cmd/tun2connect

    run_scenario "${run_dir}" 01 01-container-in-capsule
    run_scenario "${run_dir}" 02 02-container-boundary
    run_scenario "${run_dir}" 03 03-container-out-capsule
    run_scenario "${run_dir}" 04 04-microvm-vsock
    run_scenario "${run_dir}" 05 05-microvm-userspace-nic
    run_scenario "${run_dir}" 06 06-microvm-tap-netns
    run_scenario "${run_dir}" 07 07-microvm-vsock-boundary
    run_scenario "${run_dir}" 08 08-microvm-tap-host

    write_report "${run_dir}"
    printf 'Report: %s/results.md\n' "${run_dir}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
