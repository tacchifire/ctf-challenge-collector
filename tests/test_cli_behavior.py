from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import unittest
from unittest.mock import patch

from ctf_collector import cli
from ctf_collector.errors import CollectorError


class SyncCliBehaviorTests(unittest.TestCase):
    def call_sync(self, results):
        stdout = StringIO()
        stderr = StringIO()
        with (
            patch("ctf_collector.cli.load_config", return_value=[{"name": "x"}]),
            patch("ctf_collector.cli.collect_all", return_value=results),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            code = cli.main(["sync", "--config", "unused.json"])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_partial_is_nonzero_by_default(self):
        code, stdout, stderr = self.call_sync(
            [
                {
                    "name": "x",
                    "partial": True,
                    "fail_on_partial": True,
                    "error": None,
                }
            ]
        )
        self.assertEqual(code, 1)
        self.assertIn("x: partial", stdout)
        self.assertEqual(stderr, "")

    def test_partial_opt_out_is_zero(self):
        code, stdout, stderr = self.call_sync(
            [
                {
                    "name": "x",
                    "partial": True,
                    "fail_on_partial": False,
                    "error": None,
                }
            ]
        )
        self.assertEqual(code, 0)
        self.assertIn("x: partial", stdout)
        self.assertEqual(stderr, "")

    def test_ctf_failure_is_nonzero_and_concise(self):
        code, stdout, stderr = self.call_sync(
            [
                {
                    "name": "x",
                    "partial": True,
                    "fail_on_partial": True,
                    "error": CollectorError("network_error", "GET failed"),
                }
            ]
        )
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertIn("x: failed: GET failed", stderr)


if __name__ == "__main__":
    unittest.main()
