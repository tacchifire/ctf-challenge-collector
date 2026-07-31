from io import StringIO
import unittest

from ctf_collector.progress import ProgressReporter
from ctf_collector.safety import display_text


class FakeClock:
    """A monotonic clock the test drives, so pacing never depends on wall time."""

    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


class DisplayTextTests(unittest.TestCase):
    def test_newlines_and_escape_sequences_cannot_forge_output_lines(self):
        self.assertEqual(
            display_text("Web\r\n[other] forged\x1b[31m"),
            "Web__[other] forged_[31m",
        )

    def test_ordinary_text_and_path_separators_survive(self):
        self.assertEqual(display_text("Buffer Overflow"), "Buffer Overflow")
        self.assertEqual(
            display_text("web/1-One/files/a.bin"),
            "web/1-One/files/a.bin",
        )

    def test_tabs_and_exotic_whitespace_become_underscores(self):
        # A plain space stays readable; every other whitespace form is scrubbed.
        self.assertEqual(display_text("a\tb\vc\u2028d e"), "a_b_c_d e")

    def test_long_values_are_truncated_with_a_marker(self):
        self.assertEqual(display_text("A" * 100, max_length=10), "AAAAAAA...")


class ReporterHarness(unittest.TestCase):
    def make(self, **kwargs):
        stream = StringIO()
        clock = FakeClock()
        reporter = ProgressReporter(stream, now=clock, **kwargs)
        return reporter, stream, clock

    @staticmethod
    def lines(stream):
        return stream.getvalue().splitlines()


class ReporterStructureTests(ReporterHarness):
    def test_ctf_listing_and_challenge_lines_describe_the_current_work(self):
        reporter, stream, _clock = self.make()

        reporter({"event": "ctf_start", "ctf": "grcon-2024", "index": 1, "total": 2})
        reporter({"event": "listing_start", "ctf": "grcon-2024", "platform": "ctfd"})
        reporter({"event": "listing_done", "ctf": "grcon-2024", "count": 12})
        reporter(
            {
                "event": "challenge",
                "ctf": "grcon-2024",
                "index": 3,
                "total": 12,
                "name": "Buffer Overflow",
                "category": "pwn",
            }
        )
        reporter(
            {
                "event": "ctf_done",
                "ctf": "grcon-2024",
                "status": "partial",
                "failures": 2,
            }
        )

        self.assertEqual(
            self.lines(stream),
            [
                "[grcon-2024] (1/2) starting",
                "[grcon-2024] listing challenges (ctfd)",
                "[grcon-2024] 12 challenges to process",
                "[grcon-2024] (3/12) pwn / Buffer Overflow",
                "[grcon-2024] partial (2 failures)",
            ],
        )

    def test_completed_ctf_reports_completion(self):
        reporter, stream, _clock = self.make()

        reporter({"event": "ctf_done", "ctf": "x", "status": "complete", "failures": 0})

        self.assertEqual(self.lines(stream), ["[x] complete"])

    def test_failed_ctf_reports_only_the_error_code(self):
        reporter, stream, _clock = self.make()

        reporter({"event": "ctf_failed", "ctf": "x", "code": "network_error"})

        self.assertEqual(self.lines(stream), ["[x] failed (network_error)"])

    def test_hostile_names_cannot_forge_additional_lines(self):
        reporter, stream, _clock = self.make()

        reporter(
            {
                "event": "challenge",
                "ctf": "ctf\nname",
                "index": 1,
                "total": 1,
                "name": "boom\n[ctf] (9/9) forged / line",
                "category": "web\r\x1b[2J",
            }
        )

        lines = self.lines(stream)
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("[ctf_name] (1/1) "), lines[0])
        self.assertNotIn("\x1b", stream.getvalue())
        self.assertNotIn("\r", stream.getvalue())

    def test_unknown_events_are_ignored(self):
        reporter, stream, _clock = self.make()

        reporter({"event": "something_new", "ctf": "x"})

        self.assertEqual(stream.getvalue(), "")


MIB = 1024 * 1024


class AttachmentProgressTests(ReporterHarness):
    def make_download(self, declared=10 * MIB, **kwargs):
        reporter, stream, clock = self.make(**kwargs)
        reporter(
            {
                "event": "attachment_start",
                "ctf": "x",
                "local_path": "pwn/1-One/files/big.bin",
                "declared": declared,
            }
        )
        return reporter, stream, clock

    def progress(self, reporter, received, declared=10 * MIB):
        reporter(
            {
                "event": "attachment_progress",
                "ctf": "x",
                "local_path": "pwn/1-One/files/big.bin",
                "received": received,
                "declared": declared,
            }
        )

    def test_start_announces_the_path_and_declared_size(self):
        _reporter, stream, _clock = self.make_download()

        self.assertEqual(
            self.lines(stream),
            ["[x] downloading pwn/1-One/files/big.bin (10.0 MiB)"],
        )

    def test_chunk_spam_between_thresholds_prints_nothing(self):
        reporter, stream, _clock = self.make_download(
            min_interval=1.0,
            min_bytes=4 * MIB,
        )

        for chunk in range(1, 201):
            self.progress(reporter, chunk * 1024)

        self.assertEqual(len(self.lines(stream)), 1, stream.getvalue())

    def test_elapsed_time_releases_one_progress_line(self):
        reporter, stream, clock = self.make_download(
            min_interval=1.0,
            min_bytes=4 * MIB,
        )
        self.progress(reporter, 1024)
        clock.advance(2.0)

        self.progress(reporter, 2 * MIB)
        self.progress(reporter, 2 * MIB + 1024)

        self.assertEqual(len(self.lines(stream)), 2, stream.getvalue())
        self.assertEqual(
            self.lines(stream)[1],
            "[x] pwn/1-One/files/big.bin 2.0 MiB/10.0 MiB (20%) 1.0 MiB/s",
        )

    def test_transferred_bytes_release_a_progress_line_without_the_clock(self):
        reporter, stream, _clock = self.make_download(
            min_interval=60.0,
            min_bytes=4 * MIB,
        )

        self.progress(reporter, 4 * MIB)

        self.assertEqual(len(self.lines(stream)), 2, stream.getvalue())
        self.assertIn("4.0 MiB/10.0 MiB (40%)", self.lines(stream)[1])

    def test_completion_always_prints_even_when_throttled(self):
        reporter, stream, _clock = self.make_download(
            min_interval=3600.0,
            min_bytes=1024 * MIB,
        )
        self.progress(reporter, 1024)

        reporter(
            {
                "event": "attachment_done",
                "ctf": "x",
                "local_path": "pwn/1-One/files/big.bin",
                "size": 10 * MIB,
                "status": "downloaded",
            }
        )

        self.assertEqual(
            self.lines(stream)[-1],
            "[x] saved pwn/1-One/files/big.bin (10.0 MiB in 0.0s)",
        )

    def test_failure_always_prints_and_names_only_the_error_code(self):
        reporter, stream, _clock = self.make_download(
            min_interval=3600.0,
            min_bytes=1024 * MIB,
        )
        self.progress(reporter, 1024)

        reporter(
            {
                "event": "attachment_failed",
                "ctf": "x",
                "local_path": "pwn/1-One/files/big.bin",
                "code": "file_too_large",
            }
        )

        self.assertEqual(
            self.lines(stream)[-1],
            "[x] failed pwn/1-One/files/big.bin (file_too_large)",
        )

    def test_verified_reuse_is_reported_without_a_download(self):
        reporter, stream, _clock = self.make()

        reporter(
            {
                "event": "attachment_done",
                "ctf": "x",
                "local_path": "pwn/1-One/files/big.bin",
                "size": 512,
                "status": "verified",
            }
        )

        self.assertEqual(
            self.lines(stream),
            ["[x] verified pwn/1-One/files/big.bin (512 B)"],
        )


class UnknownLengthTests(ReporterHarness):
    def test_start_without_content_length_says_the_size_is_unknown(self):
        reporter, stream, _clock = self.make()

        reporter(
            {
                "event": "attachment_start",
                "ctf": "x",
                "local_path": "misc/2-Two/files/stream.bin",
                "declared": None,
            }
        )

        self.assertEqual(
            self.lines(stream),
            ["[x] downloading misc/2-Two/files/stream.bin (size unknown)"],
        )

    def test_received_bytes_stay_visible_without_content_length(self):
        reporter, stream, clock = self.make(min_interval=1.0, min_bytes=4 * MIB)
        reporter(
            {
                "event": "attachment_start",
                "ctf": "x",
                "local_path": "misc/2-Two/files/stream.bin",
                "declared": None,
            }
        )
        clock.advance(4.0)

        reporter(
            {
                "event": "attachment_progress",
                "ctf": "x",
                "local_path": "misc/2-Two/files/stream.bin",
                "received": 8 * MIB,
                "declared": None,
            }
        )

        self.assertEqual(
            self.lines(stream)[1],
            "[x] misc/2-Two/files/stream.bin 8.0 MiB 2.0 MiB/s",
        )


class BackwardsClockTests(ReporterHarness):
    """A clock that moves backwards must not stall or misreport a download.

    `time.monotonic` is per-process, so a reporter handed any other clock can
    see a reading earlier than the one before it.
    """

    def start_download(self, **kwargs):
        reporter, stream, clock = self.make(**kwargs)
        clock.advance(10.0)
        reporter(
            {
                "event": "attachment_start",
                "ctf": "x",
                "local_path": "pwn/1-One/files/big.bin",
                "declared": 10 * MIB,
            }
        )
        clock.advance(-5.0)
        return reporter, stream, clock

    def progress(self, reporter, received):
        reporter(
            {
                "event": "attachment_progress",
                "ctf": "x",
                "local_path": "pwn/1-One/files/big.bin",
                "received": received,
                "declared": 10 * MIB,
            }
        )

    def done(self, reporter):
        reporter(
            {
                "event": "attachment_done",
                "ctf": "x",
                "local_path": "pwn/1-One/files/big.bin",
                "size": 10 * MIB,
                "status": "downloaded",
            }
        )

    def test_completion_after_a_backwards_clock_reports_no_negative_duration(self):
        reporter, stream, _clock = self.start_download()

        self.done(reporter)

        self.assertEqual(
            self.lines(stream)[-1],
            "[x] saved pwn/1-One/files/big.bin (10.0 MiB in 0.0s)",
        )

    def test_time_after_a_backwards_clock_is_measured_from_the_new_reading(self):
        reporter, stream, clock = self.start_download()
        # The callback at the backwards reading is what lets the reporter
        # observe and rebase to it; an unobserved clock value is unknowable.
        self.progress(reporter, 1024)
        clock.advance(3.0)

        self.done(reporter)

        self.assertEqual(
            self.lines(stream)[-1],
            "[x] saved pwn/1-One/files/big.bin (10.0 MiB in 3.0s)",
        )

    def test_time_based_progress_resumes_after_a_backwards_clock(self):
        reporter, stream, clock = self.start_download(
            min_interval=1.0,
            min_bytes=4 * MIB,
        )
        self.progress(reporter, 1024)
        clock.advance(1.5)

        self.progress(reporter, 3 * MIB)

        self.assertEqual(len(self.lines(stream)), 2, stream.getvalue())
        self.assertEqual(
            self.lines(stream)[1],
            "[x] pwn/1-One/files/big.bin 3.0 MiB/10.0 MiB (30%) 2.0 MiB/s",
        )

    def test_the_byte_threshold_still_releases_a_line_after_a_backwards_clock(self):
        reporter, stream, _clock = self.start_download(
            min_interval=1.0,
            min_bytes=4 * MIB,
        )

        self.progress(reporter, 4 * MIB)

        self.assertEqual(len(self.lines(stream)), 2, stream.getvalue())
        self.assertEqual(
            self.lines(stream)[1],
            "[x] pwn/1-One/files/big.bin 4.0 MiB/10.0 MiB (40%)",
        )

    def test_a_backwards_clock_never_prints_a_negative_number(self):
        reporter, stream, clock = self.start_download(
            min_interval=1.0,
            min_bytes=1024,
        )
        self.progress(reporter, 8 * MIB)
        clock.advance(-1.0)
        self.progress(reporter, 9 * MIB)

        self.done(reporter)

        # No elapsed time, rate or percentage may come out signed.
        self.assertNotRegex(stream.getvalue(), r"-[0-9]")


if __name__ == "__main__":
    unittest.main()
