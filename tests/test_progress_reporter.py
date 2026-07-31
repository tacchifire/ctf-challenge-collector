import fcntl
from io import StringIO
import os
import struct
import termios
import unicodedata
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


class FakeTerminal(StringIO):
    """A stream that claims to be a terminal, so raw control bytes stay visible."""

    def isatty(self):
        return True


class TerminalHarness(ReporterHarness):
    """In-flight updates exist only on a terminal, so their pacing is tested there."""

    def make(self, **kwargs):
        stream = FakeTerminal()
        clock = FakeClock()
        reporter = ProgressReporter(stream, now=clock, **kwargs)
        return reporter, stream, clock


TERMINAL_PATH = "pwn/1-One/files/big.bin"


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


class TerminalProgressLineTests(TerminalHarness):
    """On a terminal one download owns one line until that line is settled."""

    def start(self, reporter, path=TERMINAL_PATH, declared=10 * MIB):
        reporter(
            {
                "event": "attachment_start",
                "ctf": "x",
                "local_path": path,
                "declared": declared,
            }
        )

    def progress(self, reporter, received, path=TERMINAL_PATH, declared=10 * MIB):
        reporter(
            {
                "event": "attachment_progress",
                "ctf": "x",
                "local_path": path,
                "received": received,
                "declared": declared,
            }
        )

    def test_elapsed_time_releases_one_update(self):
        reporter, stream, clock = self.make(min_interval=1.0, min_bytes=4 * MIB)
        self.start(reporter)
        self.progress(reporter, 1024)
        clock.advance(2.0)

        self.progress(reporter, 2 * MIB)
        self.progress(reporter, 2 * MIB + 1024)

        self.assertEqual(len(self.lines(stream)), 2, stream.getvalue())
        self.assertEqual(
            self.lines(stream)[1].rstrip(),
            f"[x] [====>{' ' * 15}]  20% 2.0 MiB/10.0 MiB 1.0 MiB/s",
        )

    def test_transferred_bytes_release_an_update_without_the_clock(self):
        reporter, stream, _clock = self.make(min_interval=60.0, min_bytes=4 * MIB)
        self.start(reporter)

        self.progress(reporter, 4 * MIB)

        self.assertEqual(len(self.lines(stream)), 2, stream.getvalue())
        self.assertIn(
            f"[========>{' ' * 11}]  40% 4.0 MiB/10.0 MiB",
            self.lines(stream)[1],
        )

    def test_repeated_progress_rewrites_one_line_instead_of_adding_lines(self):
        reporter, stream, clock = self.make(min_interval=1.0, min_bytes=4 * MIB)
        self.start(reporter)

        for received in (1 * MIB, 2 * MIB, 3 * MIB):
            clock.advance(1.0)
            self.progress(reporter, received)

        raw = stream.getvalue()
        # Only the start line ends; the three updates share the line below it.
        self.assertEqual(raw.count("\n"), 1, raw)
        self.assertEqual(raw.count("\r"), 2, raw)
        self.assertEqual(
            raw.rpartition("\r")[2].rstrip(),
            f"[x] [======>{' ' * 13}]  30% 3.0 MiB/10.0 MiB 1.0 MiB/s",
        )


    def test_a_shorter_update_erases_the_tail_of_the_longer_one(self):
        # A download of unknown size has no gauge to hold its width steady, so
        # it is where an update can be narrower than the one it replaces.
        reporter, stream, clock = self.make(min_interval=1.0, min_bytes=4 * MIB)
        self.start(reporter, declared=None)
        clock.advance(1.0)
        self.progress(reporter, MIB - 1, declared=None)
        clock.advance(1.0)

        self.progress(reporter, 2 * MIB, declared=None)

        long_line = "[x] 1024.0 KiB 1024.0 KiB/s"
        short_line = "[x] 2.0 MiB 1.0 MiB/s"
        self.assertGreater(len(long_line), len(short_line))
        head, _, tail = stream.getvalue().rpartition("\r")
        self.assertTrue(head.endswith(long_line), head)
        # Spaces, not cursor control: the reporter adds no escape vocabulary.
        self.assertEqual(
            tail,
            short_line + " " * (len(long_line) - len(short_line)),
        )
        self.assertNotIn("\x1b", stream.getvalue())


    def live_download(self):
        """A download with one update already drawn on the live line."""
        reporter, stream, clock = self.make(min_interval=1.0, min_bytes=4 * MIB)
        self.start(reporter)
        clock.advance(1.0)
        self.progress(reporter, MIB)
        clock.advance(1.0)
        return reporter, stream, clock

    def test_completion_settles_the_live_line_with_one_newline(self):
        reporter, stream, _clock = self.live_download()

        reporter(
            {
                "event": "attachment_done",
                "ctf": "x",
                "local_path": TERMINAL_PATH,
                "size": 10 * MIB,
                "status": "downloaded",
            }
        )

        raw = stream.getvalue()
        # The start line, the settled progress line and the saved line.
        self.assertEqual(raw.count("\n"), 3, raw)
        self.assertNotIn("\n\n", raw)
        self.assertEqual(
            self.lines(stream)[-1],
            f"[x] saved {TERMINAL_PATH} (10.0 MiB in 2.0s)",
        )

    def test_failure_settles_the_live_line_with_one_newline(self):
        reporter, stream, _clock = self.live_download()

        reporter(
            {
                "event": "attachment_failed",
                "ctf": "x",
                "local_path": TERMINAL_PATH,
                "code": "file_too_large",
            }
        )

        raw = stream.getvalue()
        self.assertEqual(raw.count("\n"), 3, raw)
        self.assertEqual(
            self.lines(stream)[1].rstrip(),
            f"[x] [==>{' ' * 17}]  10% 1.0 MiB/10.0 MiB 1.0 MiB/s",
        )
        self.assertEqual(
            self.lines(stream)[-1],
            f"[x] failed {TERMINAL_PATH} (file_too_large)",
        )

    def test_the_next_attachment_settles_the_previous_line_once(self):
        reporter, stream, _clock = self.live_download()

        self.start(reporter, path="pwn/2-Two/files/other.bin")

        raw = stream.getvalue()
        self.assertEqual(raw.count("\n"), 3, raw)
        self.assertEqual(raw.count("\r"), 0, raw)
        self.assertEqual(
            self.lines(stream)[-1],
            "[x] downloading pwn/2-Two/files/other.bin (10.0 MiB)",
        )


class FinalGaugeTests(TerminalHarness):
    """A download that finished leaves a full gauge behind, not a stalled one.

    The updates are paced, so the last one drawn is whatever happened to fall
    on a threshold - 89%, 99%, whatever the chunks landed on - and settling
    the line there freezes that figure on screen above a line saying the file
    was saved. The two disagree, and the gauge is the one that is wrong, so
    completion fills it before the line is given up.
    """

    def live_download(self, declared=100 * MIB, received=89 * MIB):
        """A download with an unfinished update already drawn on the live line."""
        reporter, stream, clock = self.make(min_interval=1.0, min_bytes=4 * MIB)
        reporter(
            {
                "event": "attachment_start",
                "ctf": "x",
                "local_path": TERMINAL_PATH,
                "declared": declared,
            }
        )
        clock.advance(1.0)
        reporter(
            {
                "event": "attachment_progress",
                "ctf": "x",
                "local_path": TERMINAL_PATH,
                "received": received,
                "declared": declared,
            }
        )
        clock.advance(1.0)
        return reporter, stream, clock

    @staticmethod
    def done(reporter, size=10 * MIB, status="downloaded"):
        reporter(
            {
                "event": "attachment_done",
                "ctf": "x",
                "local_path": TERMINAL_PATH,
                "size": size,
                "status": status,
            }
        )

    def test_completion_fills_the_gauge_before_it_settles_the_line(self):
        reporter, stream, _clock = self.live_download()

        self.done(reporter, size=100 * MIB)

        raw = stream.getvalue()
        # The start line, the settled live line and the saved line: the full
        # gauge is drawn over the update it replaces, not below it.
        self.assertEqual(raw.count("\n"), 3, raw)
        live = raw.split("\n")[1]
        self.assertIn(" 89% ", live)
        self.assertEqual(
            live.rpartition("\r")[2].rstrip(),
            f"[x] [{'=' * 20}] 100% 100.0 MiB/100.0 MiB",
        )
        self.assertLess(raw.index("100%"), raw.index("saved"), raw)
        self.assertEqual(
            self.lines(stream)[-1],
            f"[x] saved {TERMINAL_PATH} (100.0 MiB in 2.0s)",
        )

    def test_a_throttled_run_still_gets_the_full_gauge(self):
        # The pacing decides which updates are drawn in flight; it has no say
        # over the one draw that reports the download as finished.
        reporter, stream, clock = self.make(min_interval=1.0, min_bytes=4 * MIB)
        reporter(
            {
                "event": "attachment_start",
                "ctf": "x",
                "local_path": TERMINAL_PATH,
                "declared": 10 * MIB,
            }
        )
        clock.advance(1.0)
        reporter(
            {
                "event": "attachment_progress",
                "ctf": "x",
                "local_path": TERMINAL_PATH,
                "received": MIB,
                "declared": 10 * MIB,
            }
        )
        for received in (2 * MIB, 3 * MIB, 4 * MIB):
            reporter(
                {
                    "event": "attachment_progress",
                    "ctf": "x",
                    "local_path": TERMINAL_PATH,
                    "received": received,
                    "declared": 10 * MIB,
                }
            )

        self.done(reporter)

        raw = stream.getvalue()
        self.assertEqual(raw.count("\n"), 3, raw)
        self.assertIn(f"[{'=' * 20}] 100% 10.0 MiB/10.0 MiB", raw)

    def test_an_unknown_size_is_not_given_a_percentage_it_never_had(self):
        # Nothing declared a length, so there is no share to complete: a
        # gauge here would be filled from a number the server never sent.
        reporter, stream, _clock = self.live_download(declared=None, received=MIB)

        self.done(reporter, size=2 * MIB)

        raw = stream.getvalue()
        self.assertNotIn("%", raw)
        self.assertEqual(raw.count("\n"), 3, raw)
        self.assertEqual(
            self.lines(stream)[-1],
            f"[x] saved {TERMINAL_PATH} (2.0 MiB in 2.0s)",
        )

    def test_a_download_with_no_live_line_still_gets_a_full_gauge(self):
        # Completion is the one unthrottled progress update: even a short file
        # must visibly reach 100% before the saved result is printed.
        reporter, stream, clock = self.make(min_interval=1.0, min_bytes=4 * MIB)
        reporter(
            {
                "event": "attachment_start",
                "ctf": "x",
                "local_path": TERMINAL_PATH,
                "declared": 10 * MIB,
            }
        )
        clock.advance(2.0)

        self.done(reporter)

        raw = stream.getvalue()
        self.assertEqual(raw.count("\n"), 3, raw)
        self.assertIn(f"[{'=' * 20}] 100% 10.0 MiB/10.0 MiB", raw)
        self.assertLess(raw.index("100%"), raw.index("saved"), raw)

    def test_verified_reuse_draws_no_gauge(self):
        reporter, stream, _clock = self.make()

        self.done(reporter, size=512, status="verified")

        self.assertEqual(
            self.lines(stream),
            [f"[x] verified {TERMINAL_PATH} (512 B)"],
        )
        self.assertNotIn("\r", stream.getvalue())


class RecordingStream:
    """The whole stream interface the reporter uses, and no isatty at all."""

    def __init__(self):
        self.text = ""

    def write(self, value):
        self.text += value

    def flush(self):
        pass


class ClosedStream(RecordingStream):
    def isatty(self):
        raise ValueError("I/O operation on closed file")


class NonTerminalStreamTests(ReporterHarness):
    """Off a terminal an attachment shows its start and its result, nothing between.

    Redrawing a line needs a terminal, so an in-flight update off one could
    only be appended as a line of its own, and a log, a pipe or a captured
    run would then keep one line per throttle tick for the whole of a long
    download. Everything that outlives the transfer is on the two lines that
    bracket it, so the updates are dropped rather than accumulated.
    """

    def start(self, reporter, declared=10 * MIB):
        reporter(
            {
                "event": "attachment_start",
                "ctf": "x",
                "local_path": TERMINAL_PATH,
                "declared": declared,
            }
        )

    def progress(self, reporter, received, declared=10 * MIB):
        reporter(
            {
                "event": "attachment_progress",
                "ctf": "x",
                "local_path": TERMINAL_PATH,
                "received": received,
                "declared": declared,
            }
        )

    def flood(self, reporter, clock, *, ticks=6):
        """Every reason the reporter has to speak, spent at once.

        The thresholds are off, minutes pass between chunks and megabytes
        arrive with them, so anything printed here is printed by the contract
        rather than by the pacing.
        """
        self.start(reporter)
        for tick in range(1, ticks + 1):
            clock.advance(60.0)
            self.progress(reporter, tick * MIB)

    def done(self, reporter):
        reporter(
            {
                "event": "attachment_done",
                "ctf": "x",
                "local_path": TERMINAL_PATH,
                "size": 10 * MIB,
                "status": "downloaded",
            }
        )

    def test_no_update_reaches_a_captured_stream_between_start_and_done(self):
        reporter, stream, clock = self.make(min_interval=0.0, min_bytes=0)

        self.flood(reporter, clock)
        self.done(reporter)

        self.assertEqual(
            self.lines(stream),
            [
                f"[x] downloading {TERMINAL_PATH} (10.0 MiB)",
                f"[x] saved {TERMINAL_PATH} (10.0 MiB in 360.0s)",
            ],
        )
        self.assertNotIn("\r", stream.getvalue())

    def test_no_update_reaches_a_captured_stream_before_a_failure(self):
        reporter, stream, clock = self.make(min_interval=0.0, min_bytes=0)

        self.flood(reporter, clock)
        reporter(
            {
                "event": "attachment_failed",
                "ctf": "x",
                "local_path": TERMINAL_PATH,
                "code": "file_too_large",
            }
        )

        self.assertEqual(
            self.lines(stream),
            [
                f"[x] downloading {TERMINAL_PATH} (10.0 MiB)",
                f"[x] failed {TERMINAL_PATH} (file_too_large)",
            ],
        )

    def test_an_unknown_size_does_not_earn_an_update_either(self):
        # Without a declared size there is no percentage to withhold, and the
        # received count is still not worth a line of log per tick.
        reporter, stream, clock = self.make(min_interval=0.0, min_bytes=0)

        self.start(reporter, declared=None)
        for tick in range(1, 4):
            clock.advance(60.0)
            self.progress(reporter, tick * MIB, declared=None)

        self.assertEqual(
            self.lines(stream),
            [f"[x] downloading {TERMINAL_PATH} (size unknown)"],
        )

    def test_a_pipe_carries_the_start_and_the_result_only(self):
        read_fd, write_fd = os.pipe()
        clock = FakeClock()
        writer = open(write_fd, "w", encoding="utf-8")
        try:
            reporter = ProgressReporter(
                writer,
                now=clock,
                min_interval=0.0,
                min_bytes=0,
            )
            self.flood(reporter, clock)
            self.done(reporter)
        finally:
            writer.close()
        with open(read_fd, "r", encoding="utf-8") as reader:
            text = reader.read()

        self.assertEqual(
            text.splitlines(),
            [
                f"[x] downloading {TERMINAL_PATH} (10.0 MiB)",
                f"[x] saved {TERMINAL_PATH} (10.0 MiB in 360.0s)",
            ],
        )

    def test_a_stream_that_cannot_answer_isatty_is_not_a_terminal(self):
        """A stream that has not said yes is written to as a log, so it stays quiet."""
        for stream in (RecordingStream(), ClosedStream()):
            with self.subTest(stream=type(stream).__name__):
                clock = FakeClock()
                reporter = ProgressReporter(
                    stream,
                    now=clock,
                    min_interval=0.0,
                    min_bytes=0,
                )

                self.flood(reporter, clock)

                self.assertNotIn("\r", stream.text)
                self.assertEqual(
                    stream.text.splitlines(),
                    [f"[x] downloading {TERMINAL_PATH} (10.0 MiB)"],
                )

    def test_a_silent_download_is_still_measured_from_the_clock_it_observed(self):
        # Dropping the updates drops what they printed, not what they taught
        # the reporter: a backwards clock is still rebased at the callback.
        reporter, stream, clock = self.make(min_interval=0.0, min_bytes=0)
        clock.advance(10.0)
        self.start(reporter)
        clock.advance(-5.0)
        self.progress(reporter, 1024)
        clock.advance(3.0)

        self.done(reporter)

        self.assertEqual(
            self.lines(stream)[-1],
            f"[x] saved {TERMINAL_PATH} (10.0 MiB in 3.0s)",
        )


class UnknownLengthTests(TerminalHarness):
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
        # No declared size is no share and no gauge: inventing either would
        # claim a distance to the end that nothing here knows.
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

        self.assertEqual(self.lines(stream)[1], "[x] 8.0 MiB 2.0 MiB/s")


class BackwardsClockTests(TerminalHarness):
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
            self.lines(stream)[1].rstrip(),
            f"[x] [======>{' ' * 13}]  30% 3.0 MiB/10.0 MiB 2.0 MiB/s",
        )

    def test_the_byte_threshold_still_releases_a_line_after_a_backwards_clock(self):
        reporter, stream, _clock = self.start_download(
            min_interval=1.0,
            min_bytes=4 * MIB,
        )

        self.progress(reporter, 4 * MIB)

        self.assertEqual(len(self.lines(stream)), 2, stream.getvalue())
        self.assertEqual(
            self.lines(stream)[1].rstrip(),
            f"[x] [========>{' ' * 11}]  40% 4.0 MiB/10.0 MiB",
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


def cells(text):
    """The columns a terminal spends on `text`, the way a terminal counts them.

    A wide or fullwidth character advances the cursor twice and a combining
    mark does not advance it at all, so a line measured in characters says
    nothing about the line the user is shown.
    """
    width = 0
    for character in text:
        if unicodedata.combining(character):
            continue
        width += 2 if unicodedata.east_asian_width(character) in {"W", "F"} else 1
    return width


class PseudoTerminal:
    """A stream whose width is the width the kernel reports for a real pty.

    The reporter has to ask the stream it was handed how wide it is, so the
    test answers the way a terminal does rather than by handing over a number:
    `fileno` is a pty, and a resize is the same `TIOCSWINSZ` a window manager
    sends. The text is kept in memory instead of written to the pty, because
    nothing reads the other end and a full pty would block the test.
    """

    def __init__(self, columns=80):
        self._master, self._slave = os.openpty()
        self.text = ""
        self.resize(columns)

    def resize(self, columns, lines=24):
        fcntl.ioctl(
            self._slave,
            termios.TIOCSWINSZ,
            struct.pack("HHHH", lines, columns, 0, 0),
        )

    def fileno(self):
        return self._slave

    def isatty(self):
        return True

    def write(self, value):
        self.text += value

    def flush(self):
        pass

    def close(self):
        os.close(self._master)
        os.close(self._slave)


CTF_NAME = "grcon-2025"
LONG_PATH = (
    "Always_the_Same_Color/15-Flag_1/files/"
    "GRCon25-CTF-Always-the-Same-Color.zip"
)
DECLARED_BYTES = 628248813


class LiveLineWidthHarness(ReporterHarness):
    """One download of one long attachment, on a terminal of a stated width."""

    def make(self, columns=80, **kwargs):
        terminal = PseudoTerminal(columns)
        self.addCleanup(terminal.close)
        clock = FakeClock()
        reporter = ProgressReporter(terminal, now=clock, **kwargs)
        return reporter, terminal, clock

    @staticmethod
    def lines(stream):
        return stream.text.splitlines()

    @staticmethod
    def redraws(terminal):
        """Every draw the live line was asked for, one per carriage return.

        A carriage return returns to the start of the line, so what follows one
        is the whole of what the reporter wrote for that draw.
        """
        return terminal.text.rsplit("\n", 1)[-1].split("\r")

    @classmethod
    def screens(cls, terminal):
        """What the live line actually showed after each draw.

        A carriage return moves to the first column without erasing anything,
        so a draw overwrites the row from there and whatever it does not reach
        is still on screen from the draw before it. The row is rebuilt that
        way here - by column, which for these ASCII lines is by character -
        so that a tail left standing shows up as text the assertion did not
        ask for.
        """
        row = ""
        shown = []
        for redraw in cls.redraws(terminal):
            row = redraw + row[len(redraw):]
            shown.append(row.rstrip())
        return shown

    def start(
        self,
        reporter,
        path=LONG_PATH,
        declared=DECLARED_BYTES,
        ctf=CTF_NAME,
    ):
        reporter(
            {
                "event": "attachment_start",
                "ctf": ctf,
                "local_path": path,
                "declared": declared,
            }
        )

    def progress(
        self,
        reporter,
        received,
        path=LONG_PATH,
        declared=DECLARED_BYTES,
        ctf=CTF_NAME,
    ):
        reporter(
            {
                "event": "attachment_progress",
                "ctf": ctf,
                "local_path": path,
                "received": received,
                "declared": declared,
            }
        )

    def download(
        self,
        columns=80,
        path=LONG_PATH,
        declared=DECLARED_BYTES,
        ctf=CTF_NAME,
        **kwargs,
    ):
        kwargs.setdefault("min_interval", 1.0)
        kwargs.setdefault("min_bytes", 4 * MIB)
        reporter, terminal, clock = self.make(columns, **kwargs)
        self.start(reporter, path=path, declared=declared, ctf=ctf)
        return reporter, terminal, clock

    def tick(self, reporter, clock, received, **kwargs):
        clock.advance(2.0)
        self.progress(reporter, received, **kwargs)


EMPTY_BAR = f"[>{' ' * 19}]"
SEVEN_BAR = f"[=>{' ' * 18}]"
HALF_BAR = f"[{'=' * 10}>{' ' * 9}]"
FULL_BAR = f"[{'=' * 20}]"


class LiveLineWidthTests(LiveLineWidthHarness):
    """The redrawn line has to fit the terminal it is redrawn on.

    A carriage return only returns to the start of the last screen row, so a
    line wider than the terminal is never reclaimed: the wrapped head of it
    stays behind and every update after it is appended to that wreckage
    instead of replacing it. The line is therefore composed for the width the
    terminal reports now, and what a narrow line has to drop it drops in
    order - the rate first, the name of the CTF next, the byte counts after
    that - before the gauge narrows and the share of the file is given up last.
    """

    def test_every_redraw_fits_the_width_the_terminal_reports(self):
        reporter, terminal, clock = self.download(columns=80)

        for received in (7_000_000, 44_000_000, 90_000_000):
            self.tick(reporter, clock, received)

        redraws = self.redraws(terminal)
        self.assertEqual(len(redraws), 3, terminal.text)
        for redraw in redraws:
            self.assertLessEqual(cells(redraw), 80, redraw)

    def test_every_update_on_an_eighty_column_terminal_draws_the_whole_gauge(self):
        reporter, terminal, clock = self.download(columns=80)

        for received in (1_000_000, 7_000_000, 14_000_000, 44_000_000):
            self.tick(reporter, clock, received)

        redraws = self.redraws(terminal)
        self.assertEqual(
            [redraw.rstrip() for redraw in redraws],
            [
                f"[{CTF_NAME}] {EMPTY_BAR}   0% 976.6 KiB/599.1 MiB 488.3 KiB/s",
                f"[{CTF_NAME}] {EMPTY_BAR}   1% 6.7 MiB/599.1 MiB 1.7 MiB/s",
                f"[{CTF_NAME}] {EMPTY_BAR}   2% 13.4 MiB/599.1 MiB 2.2 MiB/s",
                f"[{CTF_NAME}] {SEVEN_BAR}   7% 42.0 MiB/599.1 MiB 5.2 MiB/s",
            ],
        )
        # The start line ends; the four updates share the one line below it,
        # and the first of them is already on that line when it is written.
        self.assertEqual(terminal.text.count("\n"), 1, terminal.text)
        self.assertEqual(terminal.text.count("\r"), len(redraws) - 1, terminal.text)
        for redraw in redraws:
            self.assertLessEqual(cells(redraw), 80, redraw)

    def test_the_gauge_fills_as_the_file_arrives_and_finishes_solid(self):
        reporter, terminal, clock = self.download(columns=80)

        for received in (44_000_000, 315_000_000, DECLARED_BYTES):
            self.tick(reporter, clock, received)

        arriving, half, whole = self.redraws(terminal)
        self.assertIn(f"{SEVEN_BAR}   7%", arriving)
        self.assertIn(f"{HALF_BAR}  50%", half)
        self.assertIn(f"{FULL_BAR} 100%", whole)

    def test_the_live_line_does_not_repeat_the_path_the_start_line_named(self):
        """The path is written once, on the line that announces the download.

        It does not change between redraws, so repeating it would spend the
        width on text that is already on screen - and on a narrow terminal it
        would push out the gauge and the figures that do change.
        """
        reporter, terminal, clock = self.download(columns=80)

        for received in (7_000_000, 44_000_000):
            self.tick(reporter, clock, received)

        start, _newline, live = terminal.text.partition("\n")
        self.assertEqual(
            start,
            f"[{CTF_NAME}] downloading {LONG_PATH} (599.1 MiB)",
        )
        for fragment in ("Always_the_Same_Color", "15-Flag_1", "files/", ".zip"):
            self.assertNotIn(fragment, live)

    def test_a_narrower_update_leaves_no_part_of_the_wider_one_on_screen(self):
        """The gauge holds its width; the figures beside it do not.

        A share grows a digit and a size crosses a unit and loses one, so an
        update is sometimes narrower than the one it replaces. What the shorter
        text no longer covers has to come back blank rather than keep showing
        the tail of the update before it.
        """
        reporter, terminal, clock = self.download(columns=80)

        for received in (1_000_000, 44_000_000, DECLARED_BYTES):
            self.tick(reporter, clock, received)

        self.assertEqual(
            self.screens(terminal),
            [
                f"[{CTF_NAME}] {EMPTY_BAR}   0% 976.6 KiB/599.1 MiB 488.3 KiB/s",
                f"[{CTF_NAME}] {SEVEN_BAR}   7% 42.0 MiB/599.1 MiB 10.5 MiB/s",
                f"[{CTF_NAME}] {FULL_BAR} 100% 599.1 MiB/599.1 MiB 99.9 MiB/s",
            ],
        )
        self.assertNotIn("\x1b", terminal.text)

    def test_redraws_add_no_lines_however_many_of_them_arrive(self):
        reporter, terminal, clock = self.download(columns=60)

        for received in (7_000_000, 44_000_000, 90_000_000, 120_000_000):
            self.tick(reporter, clock, received)

        # The start line ends; the four redraws share the one line below it.
        self.assertEqual(terminal.text.count("\n"), 1, terminal.text)
        self.assertEqual(terminal.text.count("\r"), 3, terminal.text)

    def test_a_wide_terminal_does_not_stretch_the_gauge_to_fill_it(self):
        reporter, terminal, clock = self.download(
            columns=200,
            path=TERMINAL_PATH,
            declared=10 * MIB,
        )

        self.tick(reporter, clock, 2 * MIB, path=TERMINAL_PATH, declared=10 * MIB)

        self.assertEqual(
            self.redraws(terminal)[-1],
            f"[{CTF_NAME}] [{'=' * 4}>{' ' * 15}]  20% 2.0 MiB/10.0 MiB 1.0 MiB/s",
        )

    def test_a_narrow_terminal_drops_the_rate_before_anything_else(self):
        reporter, terminal, clock = self.download(columns=60)

        self.tick(reporter, clock, 44_000_000)

        redraw = self.redraws(terminal)[-1]
        self.assertLessEqual(cells(redraw), 60, redraw)
        self.assertEqual(
            redraw,
            f"[{CTF_NAME}] {SEVEN_BAR}   7% 42.0 MiB/599.1 MiB",
        )

    def test_the_name_of_the_ctf_goes_before_the_byte_counts_do(self):
        # One CTF is collected at a time and its name is on the line above, so
        # the counts are worth more of a narrow line than the name is.
        reporter, terminal, clock = self.download(columns=50)

        self.tick(reporter, clock, 44_000_000)

        redraw = self.redraws(terminal)[-1]
        self.assertLessEqual(cells(redraw), 50, redraw)
        self.assertEqual(redraw, f"{SEVEN_BAR}   7% 42.0 MiB/599.1 MiB")

    def test_a_terminal_too_narrow_for_the_counts_keeps_the_gauge_and_share(self):
        reporter, terminal, clock = self.download(columns=40)

        self.tick(reporter, clock, 44_000_000)

        redraw = self.redraws(terminal)[-1]
        self.assertLessEqual(cells(redraw), 40, redraw)
        self.assertEqual(redraw, f"{SEVEN_BAR}   7%")

    def test_a_gauge_too_wide_for_the_line_is_drawn_narrower_instead(self):
        for columns, expected in (
            (20, f"[>{' ' * 12}]   7%"),
            (8, "[>]   7%"),
            (7, "7%"),
        ):
            with self.subTest(columns=columns):
                reporter, terminal, clock = self.download(columns=columns)

                self.tick(reporter, clock, 44_000_000)

                redraw = self.redraws(terminal)[-1]
                self.assertLessEqual(cells(redraw), columns, redraw)
                self.assertEqual(redraw, expected)

    def test_a_resized_terminal_is_measured_again_for_every_redraw(self):
        reporter, terminal, clock = self.download(columns=80)
        widths = (80, 40, 100)

        for columns, received in zip(widths, (7_000_000, 44_000_000, 90_000_000)):
            terminal.resize(columns)
            self.tick(reporter, clock, received)

        raw = terminal.text
        # Shrinking below the live line width settles that line once instead
        # of applying CR to a row the terminal has already reflowed.  The next
        # wider redraw then reuses the new live line normally.
        self.assertEqual(raw.count("\n"), 2, raw)
        self.assertEqual(raw.count("\r"), 1, raw)
        physical = raw.split("\n")
        first = physical[1]
        second, third = physical[2].split("\r")
        for columns, redraw in zip(widths, (first, second, third)):
            self.assertLessEqual(cells(redraw), columns, redraw)

    def test_wide_characters_in_the_name_are_counted_as_the_columns_they_take(self):
        # The path is gone from the line, but the name of the CTF is still on
        # it, and a fullwidth name measured in characters understates the line
        # by a column per character of it. Named here, the line is 58 columns
        # wide and 56 characters long, so a terminal between the two shows
        # which of them the reporter composed for: at 58 columns the name
        # fits and is kept, and at 57 it does not and is given up.
        ctf = "問題-2025"
        for columns, expected in (
            (58, f"[{ctf}] {SEVEN_BAR}   7% 42.0 MiB/599.1 MiB"),
            (57, f"{SEVEN_BAR}   7% 42.0 MiB/599.1 MiB"),
        ):
            with self.subTest(columns=columns):
                reporter, terminal, clock = self.download(columns=columns, ctf=ctf)

                self.tick(reporter, clock, 44_000_000, ctf=ctf)

                redraw = self.redraws(terminal)[-1]
                self.assertLessEqual(cells(redraw), columns, redraw)
                self.assertEqual(redraw, expected)

    def test_combining_marks_cost_no_columns_and_take_none(self):
        # Counting characters instead of columns would charge the line for
        # marks that occupy nothing, and the line would then give up the rate
        # it has the columns for.
        plain = "grcon-" + "a" * 14
        marked = "grcon-" + "a̖" * 14
        drawn = []
        for ctf in (plain, marked):
            reporter, terminal, clock = self.download(columns=80, ctf=ctf)
            self.tick(reporter, clock, 44_000_000, ctf=ctf)
            redraw = self.redraws(terminal)[-1]
            self.assertLessEqual(cells(redraw), 80, redraw)
            self.assertIn("21.0 MiB/s", redraw)
            drawn.append(cells(redraw))

        self.assertEqual(drawn[1], drawn[0])

    def test_an_extremely_narrow_terminal_still_reports_a_share(self):
        for columns in range(1, 21):
            with self.subTest(columns=columns):
                reporter, terminal, clock = self.download(columns=columns)

                self.tick(reporter, clock, 44_000_000)

                redraw = self.redraws(terminal)[-1]
                self.assertLessEqual(cells(redraw), columns, redraw)
                if columns >= 2:
                    self.assertIn("%", redraw)

    def test_an_unmeasured_download_invents_no_gauge_however_narrow_the_line(self):
        # A gauge filled from a size the server never declared would claim a
        # distance to the end that nothing here knows, so a line too narrow
        # for the count is cut into rather than replaced by a share.
        for columns, expected in (
            (80, f"[{CTF_NAME}] 42.0 MiB 21.0 MiB/s"),
            (30, f"[{CTF_NAME}] 42.0 MiB"),
            (15, "42.0 MiB"),
            (5, "42..."),
        ):
            with self.subTest(columns=columns):
                reporter, terminal, clock = self.download(
                    columns=columns,
                    declared=None,
                )

                self.tick(reporter, clock, 44_000_000, declared=None)

                redraw = self.redraws(terminal)[-1]
                self.assertLessEqual(cells(redraw), columns, redraw)
                self.assertEqual(redraw, expected)
                self.assertNotIn("%", redraw)
                self.assertNotIn("=", redraw)


class UnmeasurableTerminalTests(TerminalHarness):
    """A terminal that cannot be measured is assumed to be the narrow default.

    `FakeTerminal` says it is a terminal but has no file descriptor to ask, and
    a redirected or emulated terminal can answer the same way. Guessing wide
    would wrap the line on exactly the terminals we could not check, so the
    guess is the conservative eighty columns.
    """

    def test_a_stream_that_cannot_report_its_width_is_drawn_for_eighty(self):
        reporter, stream, clock = self.make(min_interval=1.0, min_bytes=4 * MIB)
        reporter(
            {
                "event": "attachment_start",
                "ctf": CTF_NAME,
                "local_path": LONG_PATH,
                "declared": DECLARED_BYTES,
            }
        )
        clock.advance(2.0)

        reporter(
            {
                "event": "attachment_progress",
                "ctf": CTF_NAME,
                "local_path": LONG_PATH,
                "received": 44_000_000,
                "declared": DECLARED_BYTES,
            }
        )

        redraw = stream.getvalue().rsplit("\n", 1)[-1]
        self.assertLessEqual(cells(redraw), 80, redraw)
        self.assertEqual(
            redraw,
            f"[{CTF_NAME}] {SEVEN_BAR}   7% 42.0 MiB/599.1 MiB 21.0 MiB/s",
        )


if __name__ == "__main__":
    unittest.main()
