import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import benchmark_client


class BenchmarkClientTest(unittest.TestCase):
    def test_report_uses_observations_and_actual_topologies(self):
        runner = Path(__file__).resolve().parents[1] / "benchmark.sh"
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            for index in range(1, 8):
                (run_dir / f"{index:02}.log").write_text("SAMPLE_COUNT=100\nLATENCY_P50_MS=2.50\nP50_STABILITY_CV_PCT=9.00\n")
            subprocess.run(["bash", "-c", 'source "$1"; write_report "$2"', "test", str(runner), directory], check=True, timeout=10)
            report = (run_dir / "results.md").read_text()
            self.assertIn("Host explicit TCP proxy", report)
            self.assertIn("Namespace TUN + local VSOCK", report)
            self.assertIn("Docker bridge with unused TAP", report)
            self.assertIn("| 100 | unknown | unknown | unknown | 2.50 | unknown | unknown | 9.00 |", report)
            self.assertNotIn("Highly Stable", report)
            self.assertFalse((run_dir / "metadata.txt").exists())

    def test_runner_preserves_failed_scenario_output(self):
        runner = Path(__file__).resolve().parents[1] / "benchmark.sh"
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            fixture = run_dir / "fixture"
            fixture.mkdir()
            driver = fixture / "run.sh"
            driver.write_text("#!/usr/bin/env bash\nprintf 'SAMPLE=partial\\n'\nexit 1\n")
            driver.chmod(0o700)
            result = subprocess.run(["bash", "-c", 'source "$1"; SCRIPT_DIR="$2"; run_scenario "$2" 01 fixture', "test", str(runner), directory], capture_output=True, text=True, timeout=10, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((run_dir / "01.log").read_text(), "SAMPLE=partial\n")
            self.assertFalse((run_dir / "results.md").exists())

    def test_cumulative_timings_and_explicit_proxy(self):
        result = subprocess.CompletedProcess([], 0, "0.001 0.003 0.009 0.012 200\n")
        with mock.patch.object(benchmark_client.subprocess, "run", return_value=result) as run:
            self.assertEqual(benchmark_client.run_curl("https://test.example"), (1, 3, 9, 12))
        command = run.call_args.args[0]
        self.assertEqual(command[1], "-q")
        self.assertEqual(command[command.index("--proxy") + 1], "")
        self.assertEqual(command[command.index("--noproxy") + 1], "")
        self.assertIn("--fail", command)
        self.assertEqual(run.call_args.kwargs["timeout"], 65)

    def test_non_success_status_is_rejected(self):
        result = subprocess.CompletedProcess([], 0, "0 0 0 0.001 302\n")
        with mock.patch.object(benchmark_client.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(ValueError, "HTTP code 302"):
                benchmark_client.run_curl("https://test.example")

    def test_stats_require_samples(self):
        with self.assertRaises(ValueError):
            benchmark_client.calc_stats([])
        stats = benchmark_client.calc_stats([3, 1, 2])
        self.assertEqual(stats["p50"], 2)
        self.assertEqual(stats["stddev"], 1)

    def test_raw_sample_is_retained(self):
        output = io.StringIO()
        version = subprocess.CompletedProcess([], 0, "curl test-version\n")
        arguments = ["client", "--url", "https://test.example", "--rounds", "1", "--requests", "1", "--warmup", "0"]
        with mock.patch.object(benchmark_client.sys, "argv", arguments), \
                mock.patch.object(benchmark_client, "run_curl", return_value=(1, 3, 9, 12)), \
                mock.patch.object(benchmark_client.subprocess, "run", return_value=version), \
                contextlib.redirect_stdout(output):
            benchmark_client.main()
        samples = [json.loads(line.removeprefix("SAMPLE=")) for line in output.getvalue().splitlines() if line.startswith("SAMPLE=")]
        self.assertEqual(samples, [{"round": 1, "request": 1, "namelookup_ms": 1, "connect_ms": 3, "appconnect_ms": 9, "total_ms": 12}])
        self.assertIn("SAMPLE_COUNT=1", output.getvalue())

    def test_failed_download_is_not_throughput(self):
        version = subprocess.CompletedProcess([], 0, "curl test-version\n")
        download = subprocess.CompletedProcess([], 0, "1000000 403 100\n")
        arguments = ["client", "--url", "https://test.example", "--rounds", "1", "--requests", "1", "--warmup", "0", "--throughput-url", "https://test.example/stream"]
        with mock.patch.object(benchmark_client.sys, "argv", arguments), \
                mock.patch.object(benchmark_client, "run_curl", return_value=(1, 3, 9, 12)), \
                mock.patch.object(benchmark_client.subprocess, "run", side_effect=[version, download]), \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, "invalid download"):
                benchmark_client.main()


if __name__ == "__main__":
    unittest.main()
