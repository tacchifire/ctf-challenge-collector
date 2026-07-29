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

    def test_terminal_approver_requires_exact_yes_and_writes_to_stderr(self):
        request = {
            "ctf_name": "event",
            "local_path": "web/1-One/files/large.bin",
            "exceeded": "both",
            "required_file_bytes": 6,
            "required_total_bytes": 10,
            "current_file_limit": 5,
            "current_total_limit": 9,
        }
        for answer, expected in (
            ("yes\n", True),
            ("y\n", False),
            ("YES\n", False),
            ("", False),
        ):
            with self.subTest(answer=answer):
                stderr = StringIO()
                with (
                    patch.object(cli.sys, "stdin", StringIO(answer)),
                    redirect_stderr(stderr),
                ):
                    approved = cli._terminal_limit_approver(request)
                self.assertIs(approved, expected)
                self.assertIn("large.bin", stderr.getvalue())
                self.assertIn("10 bytes", stderr.getvalue())

    def test_non_tty_sync_does_not_enable_limit_approval(self):
        stdin = StringIO("yes\n")
        stderr = StringIO()
        with (
            patch.object(cli.sys, "stdin", stdin),
            patch.object(cli.sys, "stderr", stderr),
            patch("ctf_collector.cli.load_config", return_value=[{"name": "x"}]),
            patch("ctf_collector.cli.collect_all", return_value=[]) as collect_all,
        ):
            code = cli.main(["sync", "--config", "unused.json"])

        self.assertEqual(code, 0)
        self.assertIsNone(collect_all.call_args.kwargs["limit_approver"])
        self.assertEqual(stdin.tell(), 0)

    def test_tty_sync_enables_terminal_limit_approval(self):
        stdin = StringIO("yes\n")
        stderr = StringIO()
        stdin.isatty = lambda: True
        stderr.isatty = lambda: True
        with (
            patch.object(cli.sys, "stdin", stdin),
            patch.object(cli.sys, "stderr", stderr),
            patch("ctf_collector.cli.load_config", return_value=[{"name": "x"}]),
            patch("ctf_collector.cli.collect_all", return_value=[]) as collect_all,
        ):
            code = cli.main(["sync", "--config", "unused.json"])

        self.assertEqual(code, 0)
        self.assertIs(
            collect_all.call_args.kwargs["limit_approver"],
            cli._terminal_limit_approver,
        )


if __name__ == "__main__":
    unittest.main()
