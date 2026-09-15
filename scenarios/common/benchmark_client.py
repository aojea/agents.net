import argparse
import json
import subprocess
import sys

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True)
    p.add_argument("--cacert", default="")
    p.add_argument("--proxy", default="")
    p.add_argument("--rounds", type=int, default=3)
    p.add_argument("--requests", type=int, default=10)
    p.add_argument("--warmup", type=int, default=3)
    p.add_argument("--throughput-url", default="")
    p.add_argument("--throughput-trials", type=int, default=2)
    args = p.parse_args()
    if args.rounds < 1 or args.requests < 1 or args.warmup < 0 or args.throughput_trials < 1:
        p.error("rounds, requests, and throughput-trials must be positive; warmup must be nonnegative")
    return args

def run_curl(url, cacert="", proxy=""):
    cmd = ["curl", "-q", "-sS", "--fail", "--connect-timeout", "10", "--max-time", "60", "--noproxy", "", "--proxy", proxy, "-o", "/dev/null", "-w", "%{time_namelookup} %{time_connect} %{time_appconnect} %{time_total} %{http_code}\n"]
    if cacert:
        cmd.extend(["--cacert", cacert])
    cmd.append(url)
    res = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=65)
    parts = res.stdout.strip().split()
    if len(parts) < 5:
        raise ValueError(f"unexpected curl output: {res.stdout}")
    dns, tcp, tls, total, code = float(parts[0])*1000, float(parts[1])*1000, float(parts[2])*1000, float(parts[3])*1000, int(parts[4])
    if code != 200:
        raise ValueError(f"HTTP code {code}")
    return dns, tcp, tls, total

def calc_stats(arr):
    if not arr:
        raise ValueError("at least one sample is required")
    arr = sorted(arr)
    n = len(arr)
    def p(pct):
        idx = (n - 1) * pct
        low = int(idx)
        high = min(low + 1, n - 1)
        w = idx - low
        return arr[low] * (1.0 - w) + arr[high] * w
    mean = sum(arr) / n
    stddev = (sum((x - mean) ** 2 for x in arr) / (n - 1)) ** 0.5 if n > 1 else 0.0
    cv = (stddev / mean) * 100.0 if mean > 0 else 0.0
    return {
        "min": arr[0],
        "p50": p(0.50),
        "p90": p(0.90),
        "p95": p(0.95),
        "p99": p(0.99),
        "max": arr[-1],
        "mean": mean,
        "stddev": stddev,
        "cv_pct": cv,
    }

def main():
    args = parse_args()
    print("CLIENT_CONFIG=" + json.dumps(vars(args), sort_keys=True), flush=True)
    version = subprocess.run(["curl", "--version"], capture_output=True, text=True, check=True, timeout=10)
    print("CURL_VERSION=" + version.stdout.splitlines()[0], flush=True)
    for _ in range(args.warmup):
        try:
            run_curl(args.url, args.cacert, args.proxy)
        except (subprocess.SubprocessError, ValueError) as error:
            print(f"WARMUP_FAILURE={error}", file=sys.stderr, flush=True)

    all_dns, all_tcp, all_tls, all_total = [], [], [], []
    rounds_p50 = []

    for r in range(args.rounds):
        r_totals = []
        for request_index in range(args.requests):
            dns, tcp, tls, total = run_curl(args.url, args.cacert, args.proxy)
            print("SAMPLE=" + json.dumps({
                "round": r + 1,
                "request": request_index + 1,
                "namelookup_ms": dns,
                "connect_ms": tcp,
                "appconnect_ms": tls,
                "total_ms": total,
            }, sort_keys=True), flush=True)
            all_dns.append(dns)
            all_tcp.append(tcp)
            all_tls.append(tls)
            all_total.append(total)
            r_totals.append(total)
        st = calc_stats(r_totals)
        rounds_p50.append(st["p50"])
        print(f"ROUND_{r+1}_P50_MS={st['p50']:.2f}")

    tot_st = calc_stats(all_total)
    dns_st = calc_stats(all_dns)
    tcp_st = calc_stats(all_tcp)
    tls_st = calc_stats(all_tls)

    mean_p50 = sum(rounds_p50) / len(rounds_p50)
    var_p50 = sum((x - mean_p50) ** 2 for x in rounds_p50) / (len(rounds_p50) - 1) if len(rounds_p50) > 1 else 0.0
    stddev_p50 = var_p50 ** 0.5
    stab_cv = (stddev_p50 / mean_p50) * 100.0 if mean_p50 > 0 else 0.0

    print(f"SAMPLE_COUNT={len(all_total)}")
    print(f"DNS_P50_MS={dns_st['p50']:.2f}")
    print(f"DNS_P90_MS={dns_st['p90']:.2f}")
    print(f"TCP_P50_MS={tcp_st['p50']:.2f}")
    print(f"TCP_P90_MS={tcp_st['p90']:.2f}")
    print(f"TLS_P50_MS={tls_st['p50']:.2f}")
    print(f"TLS_P90_MS={tls_st['p90']:.2f}")
    print(f"LATENCY_MIN_MS={tot_st['min']:.2f}")
    print(f"LATENCY_P50_MS={tot_st['p50']:.2f}")
    print(f"LATENCY_P90_MS={tot_st['p90']:.2f}")
    print(f"LATENCY_P95_MS={tot_st['p95']:.2f}")
    print(f"LATENCY_P99_MS={tot_st['p99']:.2f}")
    print(f"LATENCY_MAX_MS={tot_st['max']:.2f}")
    print(f"LATENCY_MEAN_MS={tot_st['mean']:.2f}")
    print(f"LATENCY_STDDEV_MS={tot_st['stddev']:.2f}")
    print(f"LATENCY_CV_PCT={tot_st['cv_pct']:.2f}")
    print(f"P50_STABILITY_CV_PCT={stab_cv:.2f}")

    if args.throughput_url:
        tp_trials = []
        for i in range(args.throughput_trials):
            cmd = ["curl", "-q", "-sS", "--fail", "--connect-timeout", "10", "--max-time", "120", "--noproxy", "", "--proxy", args.proxy, "-o", "/dev/null", "-w", "%{speed_download} %{http_code} %{size_download}\n"]
            if args.cacert:
                cmd.extend(["--cacert", args.cacert])
            cmd.append(args.throughput_url)
            res = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=125)
            speed, status, size = res.stdout.split()
            if int(status) != 200 or float(size) <= 0:
                raise ValueError(f"invalid download: status={status}, bytes={size}")
            bytes_sec = float(speed)
            print("DOWNLOAD=" + json.dumps({"trial": i + 1, "bytes": float(size), "bytes_per_second": bytes_sec}), flush=True)
            mb_s = bytes_sec / (1024.0 * 1024.0)
            tp_trials.append(mb_s)
            print(f"TRIAL_{i+1}_THROUGHPUT_MB_S={mb_s:.2f}")
        mean_tp = sum(tp_trials) / len(tp_trials)
        std_tp = (sum((x - mean_tp) ** 2 for x in tp_trials) / (len(tp_trials) - 1)) ** 0.5 if len(tp_trials) > 1 else 0.0
        tp_cv = (std_tp / mean_tp) * 100.0 if mean_tp > 0 else 0.0
        print(f"THROUGHPUT_MB_S={mean_tp:.2f}")
        print(f"THROUGHPUT_STDDEV_MB_S={std_tp:.2f}")
        print(f"THROUGHPUT_CV_PCT={tp_cv:.2f}")

if __name__ == "__main__":
    main()
