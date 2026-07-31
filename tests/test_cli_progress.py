from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ctf_collector import cli
from ctf_collector.progress import ProgressReporter

from .support import FakeOpener
from .test_collector_progress import ATTACHMENT_BODY, ctfd_responder


TOKEN = "ctfd-secret-value"


class SyncProgressWiringTests(unittest.TestCase):
    def call_sync(self, **stream_overrides):
        stdout = StringIO()
        stderr = StringIO()
        for stream, attribute in ((stdout, "stdout"), (stderr, "stderr")):
            stream.isatty = (
                lambda attribute=attribute: stream_overrides.get(attribute, False)
            )
        with (
            patch.object(cli.sys, "stdin", StringIO()),
            patch("ctf_collector.cli.load_config", return_value=[{"name": "x"}]),
            patch("ctf_collector.cli.collect_all", return_value=[]) as collect_all,
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            code = cli.main(["sync", "--config", "unused.json"])
        return code, collect_all, stdout, stderr

    def test_non_tty_sync_still_reports_progress(self):
        code, collect_all, _stdout, _stderr = self.call_sync()

        self.assertEqual(code, 0)
        self.assertIsInstance(
            collect_all.call_args.kwargs["progress"],
            ProgressReporter,
        )

    def test_tty_sync_reports_progress_on_stderr_too(self):
        # A terminal run gets the same narration a piped one does, so the
        # reporter is never gated on isatty.
        code, collect_all, stdout, stderr = self.call_sync(stdout=True, stderr=True)

        self.assertEqual(code, 0)
        reporter = collect_all.call_args.kwargs["progress"]
        self.assertIsInstance(reporter, ProgressReporter)

        reporter({"event": "ctf_start", "ctf": "probe", "index": 1, "total": 1})

        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("[probe] (1/1) starting", stderr.getvalue())

    def test_progress_is_enabled_without_enabling_limit_approval(self):
        # A long non-interactive job must stay observable, but silence on
        # stdin is never an answer to an oversized-attachment prompt.
        _code, collect_all, _stdout, _stderr = self.call_sync()

        self.assertIsNotNone(collect_all.call_args.kwargs["progress"])
        self.assertIsNone(collect_all.call_args.kwargs["limit_approver"])

    def download(self, reporter, received=32 * 1024 * 1024):
        """A download far past every default throttle, start to finish."""
        path = "web/1-One/files/a.bin"
        declared = 64 * 1024 * 1024
        for event in (
            {"event": "attachment_start", "declared": declared},
            {"event": "attachment_progress", "received": received, "declared": declared},
            {"event": "attachment_done", "size": declared, "status": "downloaded"},
        ):
            reporter({"ctf": "probe", "local_path": path, **event})

    def test_a_captured_stderr_gets_no_in_flight_download_line(self):
        # The wired reporter carries the real thresholds, and 32 MiB clears
        # them, so a line here would be a line every redirected run keeps.
        _code, collect_all, stdout, stderr = self.call_sync()

        self.download(collect_all.call_args.kwargs["progress"])

        lines = stderr.getvalue().splitlines()
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            lines[0],
            "[probe] downloading web/1-One/files/a.bin (64.0 MiB)",
        )
        self.assertTrue(
            lines[-1].startswith("[probe] saved web/1-One/files/a.bin (64.0 MiB in "),
            lines,
        )
        self.assertEqual(len(lines), 2, lines)

    def test_a_terminal_still_watches_the_download_in_flight(self):
        # The suppression is about what a log keeps, not about what an
        # operator can see, so the terminal run keeps its live percentage.
        _code, collect_all, _stdout, stderr = self.call_sync(stdout=True, stderr=True)

        self.download(collect_all.call_args.kwargs["progress"])

        # The rate is measured against the real clock the CLI wires in, so the
        # gauge and the counts are what can be named exactly here.
        self.assertIn(
            f"[probe] [{'=' * 10}>{' ' * 9}]  50% 32.0 MiB/64.0 MiB",
            stderr.getvalue(),
        )

    def test_the_reporter_writes_to_stderr_and_never_to_stdout(self):
        _code, collect_all, stdout, stderr = self.call_sync()

        collect_all.call_args.kwargs["progress"](
            {"event": "ctf_start", "ctf": "probe", "index": 1, "total": 1}
        )

        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("[probe] (1/1) starting", stderr.getvalue())


class SyncProgressEndToEndTests(unittest.TestCase):
    def run_sync(self, tmp):
        token_file = Path(tmp) / "ctfd.token"
        token_file.write_text(f"{TOKEN}\n", encoding="utf-8")
        config_path = Path(tmp) / "config.json"
        config_path.write_text(
            json.dumps(
                {
                    "ctfs": [
                        {
                            "name": "sample-ctfd",
                            "platform": "ctfd",
                            "base_url": "https://base.example",
                            "token_file": str(token_file),
                            "output_root": str(Path(tmp) / "out"),
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        fake = FakeOpener(
            ctfd_responder(headers={"Content-Length": len(ATTACHMENT_BODY)})
        )
        stdout = StringIO()
        stderr = StringIO()
        with (
            patch("ctf_collector.http.build_opener", return_value=fake),
            patch.object(cli.sys, "stdin", StringIO()),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            code = cli.main(["sync", "--config", str(config_path)])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_stderr_narrates_the_run_while_stdout_stays_machine_readable(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, stdout, stderr = self.run_sync(tmp)

        self.assertEqual(code, 0, stderr)
        self.assertEqual(stdout, "sample-ctfd: complete\n")
        for expected in (
            "[sample-ctfd] (1/1) starting",
            "[sample-ctfd] listing challenges (ctfd)",
            "[sample-ctfd] 1 challenges to process",
            "[sample-ctfd] (1/1) Web / First",
            "[sample-ctfd] downloading Web/1-First/files/a.bin (18 B)",
            "[sample-ctfd] saved Web/1-First/files/a.bin (18 B in ",
            "[sample-ctfd] complete",
        ):
            self.assertIn(expected, stderr)

    def test_progress_output_leaks_no_token_url_or_control_sequence(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, stdout, stderr = self.run_sync(tmp)

        self.assertEqual(code, 0, stderr)
        combined = stdout + stderr
        for forbidden in (
            TOKEN,
            "signature",
            "do-not-show",
            "fragment",
            "base.example",
            "https://",
            "Authorization",
            "Token ",
            "Cookie",
            ATTACHMENT_BODY.decode("ascii"),
        ):
            self.assertNotIn(forbidden, combined)
        self.assertFalse(any(character in combined for character in "\x1b\r\x07"))

    def test_hostile_challenge_names_cannot_forge_progress_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            token_file = Path(tmp) / "ctfd.token"
            token_file.write_text(f"{TOKEN}\n", encoding="utf-8")
            config_path = Path(tmp) / "config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "ctfs": [
                            {
                                "name": "sample-ctfd",
                                "platform": "ctfd",
                                "base_url": "https://base.example",
                                "token_file": str(token_file),
                                "output_root": str(Path(tmp) / "out"),
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            fake = FakeOpener(
                ctfd_responder(
                    files=(),
                    name="pwned\n[sample-ctfd] complete\n[sample-ctfd] fake",
                )
            )
            stderr = StringIO()
            with (
                patch("ctf_collector.http.build_opener", return_value=fake),
                patch.object(cli.sys, "stdin", StringIO()),
                redirect_stdout(StringIO()),
                redirect_stderr(stderr),
            ):
                cli.main(["sync", "--config", str(config_path)])

        lines = stderr.getvalue().splitlines()
        # The name is scrubbed onto a single line, so it can add text to a
        # line we own but can never forge a line of its own.
        self.assertEqual(len([line for line in lines if line == "[sample-ctfd] complete"]), 1)
        self.assertEqual(
            [line for line in lines if line.startswith("[sample-ctfd] fake")],
            [],
        )
        self.assertEqual(len(lines), 5, lines)


if __name__ == "__main__":
    unittest.main()
