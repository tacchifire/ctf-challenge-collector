from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import unittest
from unittest.mock import patch

from ctf_collector import cli
from ctf_collector.errors import CollectorError


MIB = 1024 * 1024


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


class OversizePromptTests(unittest.TestCase):
    """The prompt states the overage in sizes a person reads, then asks once.

    An operator staring at a terminal answers with a keystroke, so the
    figures have to be legible at a glance and the question has to say that
    the one answer covers the whole run. Byte counts and a paragraph of
    English did neither.
    """

    QUESTION = "この実行中、同様の超過をまとめて許可しますか？ [Y/N]: "

    FILE_ONLY = {
        "ctf_name": "grcon-2025",
        "local_path": "web/1-One/files/dump.zip",
        "exceeded": "file",
        "required_file_bytes": 600 * MIB,
        "required_total_bytes": 600 * MIB,
        "current_file_limit": 100 * MIB,
        "current_total_limit": 1024 * MIB,
    }
    BOTH = {
        **FILE_ONLY,
        "exceeded": "both",
        "required_total_bytes": 800 * MIB,
        "current_total_limit": 512 * MIB,
    }
    TOTAL_ONLY = {
        **BOTH,
        "exceeded": "total",
        "required_file_bytes": 50 * MIB,
    }

    def prompt(self, request, answer="y\n"):
        stderr = StringIO()
        with (
            patch.object(cli.sys, "stdin", StringIO(answer)),
            redirect_stderr(stderr),
        ):
            cli._terminal_limit_approver(dict(request))
        return stderr.getvalue()

    def test_a_file_overage_is_stated_in_one_line_of_human_sizes(self):
        self.assertEqual(
            self.prompt(self.FILE_ONLY),
            "grcon-2025: web/1-One/files/dump.zip はファイル上限を500.0 MiB"
            "超えます（600.0 MiB / 上限100.0 MiB）。\n" + self.QUESTION,
        )

    def test_overage_units_stay_mib_even_above_one_gib(self):
        self.assertEqual(
            cli._overage("ファイル上限を", 2048 * MIB, 1024 * MIB),
            "ファイル上限を1024.0 MiB超えます（2048.0 MiB / 上限1024.0 MiB）。",
        )

    def test_a_total_overage_is_named_beside_the_file_overage(self):
        self.assertEqual(
            self.prompt(self.BOTH),
            "grcon-2025: web/1-One/files/dump.zip はファイル上限を500.0 MiB"
            "超えます（600.0 MiB / 上限100.0 MiB）。合計上限も288.0 MiB"
            "超えます（800.0 MiB / 上限512.0 MiB）。\n" + self.QUESTION,
        )

    def test_a_total_only_overage_names_the_total_alone(self):
        self.assertEqual(
            self.prompt(self.TOTAL_ONLY),
            "grcon-2025: web/1-One/files/dump.zip は合計上限を288.0 MiB"
            "超えます（800.0 MiB / 上限512.0 MiB）。\n" + self.QUESTION,
        )

    def test_the_prompt_says_the_answer_covers_the_whole_run(self):
        prompt = self.prompt(self.BOTH)
        self.assertIn("この実行中", prompt)
        self.assertIn("まとめて", prompt)

    def test_the_english_disclosure_paragraph_is_gone(self):
        prompt = self.prompt(self.BOTH)
        self.assertEqual(prompt.count("\n"), 1, prompt)
        self.assertTrue(prompt.endswith("[Y/N]: "), prompt)
        for fragment in ("bytes", "rest of this sync run", "absolute hard caps"):
            self.assertNotIn(fragment, prompt)

    def test_only_y_approves_and_everything_else_declines(self):
        for answer, expected in (
            ("y\n", True),
            ("Y\n", True),
            (" y\n", False),
            ("y \n", False),
            ("\ty\n", False),
            ("yes\n", False),
            ("n\n", False),
            ("N\n", False),
            ("\n", False),
            ("", False),
        ):
            with self.subTest(answer=answer):
                stderr = StringIO()
                with (
                    patch.object(cli.sys, "stdin", StringIO(answer)),
                    redirect_stderr(stderr),
                ):
                    approved = cli._terminal_limit_approver(dict(self.BOTH))
                self.assertIs(approved, expected)
                self.assertIn("dump.zip", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
