"""Regression tests for the pinned external replay."""

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "erc8350_sepolia.py"

spec = importlib.util.spec_from_file_location("erc8350_sepolia", SCRIPT)
replay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(replay)


class FakeRpc:
    def __init__(self, head):
        self.head = head
        self.calls = []

    def __call__(self, method, params):
        if method == "eth_blockNumber":
            return hex(self.head)
        if method == "eth_getLogs":
            self.calls.append(params[0])
            return []
        raise AssertionError(f"unexpected RPC method: {method}")


class CollectSpacesTest(unittest.TestCase):
    def test_observation_height_caps_the_log_scan(self):
        rpc = FakeRpc(100)
        log_count, spaces = replay.collect_spaces(
            rpc,
            "0x0000000000000000000000000000000000000000",
            from_block=0,
            log_range=45,
            to_block=90,
        )
        self.assertEqual(log_count, 0)
        self.assertEqual(spaces, {})
        self.assertEqual(
            [(call["fromBlock"], call["toBlock"]) for call in rpc.calls],
            [("0x0", "0x2c"), ("0x2d", "0x59"), ("0x5a", "0x5a")],
        )


class CliValidationTest(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            capture_output=True,
            text=True,
        )

    def test_zero_log_range_is_rejected_before_rpc(self):
        result = self.run_cli("--log-range", "0")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--log-range must be a positive integer", result.stderr)

    def test_negative_from_block_is_rejected(self):
        result = self.run_cli("--from-block", "-1")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--from-block must be >= 0", result.stderr)


if __name__ == "__main__":
    unittest.main()
