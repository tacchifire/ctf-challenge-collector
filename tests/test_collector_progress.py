import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from ctf_collector.collector import collect_all, collect_ctf

from .support import FakeOpener, make_config


ATTACHMENT_BODY = b"attachment payload"
ATTACHMENT_URL = "/files/a.bin?signature=do-not-show#fragment-do-not-show"


def ctfd_responder(*, files=(ATTACHMENT_URL,), headers=None, name="First"):
    def responder(request):
        path = urlsplit(request["url"]).path
        if path == "/api/v1/challenges":
            return 200, {}, {
                "data": [{"id": 1, "name": name, "category": "Web"}],
                "meta": {"pagination": {"page": 1, "pages": 1, "next": None}},
            }
        if path == "/api/v1/challenges/1":
            return 200, {}, {
                "data": {
                    "id": 1,
                    "name": name,
                    "category": "Web",
                    "files": list(files),
                }
            }
        if path == "/files/a.bin":
            return 200, dict(headers or {}), ATTACHMENT_BODY
        return 404, {}, b"missing"

    return responder


class RecordingProgress:
    def __init__(self):
        self.events = []

    def __call__(self, event):
        self.events.append(event)

    def kinds(self):
        return [event["event"] for event in self.events]

    def of(self, kind):
        return [event for event in self.events if event["event"] == kind]


class CollectorProgressTests(unittest.TestCase):
    def collect(self, responder, progress, **overrides):
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp, **overrides)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                return collect_ctf(config, progress=progress)

    def test_listing_challenge_and_attachment_milestones_are_reported(self):
        progress = RecordingProgress()

        manifest = self.collect(
            ctfd_responder(headers={"Content-Length": len(ATTACHMENT_BODY)}),
            progress,
        )

        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(
            progress.kinds()[:4],
            ["listing_start", "listing_done", "challenge", "attachment_start"],
        )
        self.assertEqual(progress.kinds()[-1], "attachment_done")
        self.assertEqual(
            progress.of("listing_start")[0],
            {"event": "listing_start", "ctf": "fake-ctfd", "platform": "ctfd"},
        )
        self.assertEqual(
            progress.of("listing_done")[0],
            {"event": "listing_done", "ctf": "fake-ctfd", "count": 1},
        )
        self.assertEqual(
            progress.of("challenge")[0],
            {
                "event": "challenge",
                "ctf": "fake-ctfd",
                "index": 1,
                "total": 1,
                "name": "First",
                "category": "Web",
            },
        )
        self.assertEqual(
            progress.of("attachment_start")[0],
            {
                "event": "attachment_start",
                "ctf": "fake-ctfd",
                "local_path": "Web/1-First/files/a.bin",
                "declared": len(ATTACHMENT_BODY),
            },
        )
        self.assertEqual(
            progress.of("attachment_done")[0],
            {
                "event": "attachment_done",
                "ctf": "fake-ctfd",
                "local_path": "Web/1-First/files/a.bin",
                "size": len(ATTACHMENT_BODY),
                "status": "downloaded",
            },
        )

    def test_progress_events_carry_received_and_declared_bytes(self):
        progress = RecordingProgress()

        self.collect(
            ctfd_responder(headers={"Content-Length": len(ATTACHMENT_BODY)}),
            progress,
        )

        self.assertEqual(
            progress.of("attachment_progress")[-1],
            {
                "event": "attachment_progress",
                "ctf": "fake-ctfd",
                "local_path": "Web/1-First/files/a.bin",
                "received": len(ATTACHMENT_BODY),
                "declared": len(ATTACHMENT_BODY),
            },
        )

    def test_missing_content_length_still_reports_received_bytes(self):
        progress = RecordingProgress()

        self.collect(ctfd_responder(), progress)

        self.assertIsNone(progress.of("attachment_start")[0]["declared"])
        self.assertEqual(
            progress.of("attachment_progress")[-1]["received"],
            len(ATTACHMENT_BODY),
        )

    def test_reused_file_is_reported_as_verified_without_a_download(self):
        responder = ctfd_responder(headers={"Content-Length": len(ATTACHMENT_BODY)})
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                collect_ctf(config)
                progress = RecordingProgress()
                collect_ctf(config, progress=progress)

        self.assertEqual(progress.of("attachment_start"), [])
        self.assertEqual(
            progress.of("attachment_done")[0]["status"],
            "verified",
        )

    def test_failed_attachment_reports_only_the_error_code(self):
        progress = RecordingProgress()

        manifest = self.collect(
            ctfd_responder(files=("/files/a.bin",)),
            progress,
            limits={
                "page_size": 2,
                "max_pages": 10,
                "max_file_bytes": 4,
                "max_total_bytes": 2048,
                "max_redirects": 3,
                "max_metadata_bytes": 1024 * 1024,
            },
        )

        self.assertEqual(manifest["status"], "partial")
        self.assertEqual(
            progress.of("attachment_failed")[0],
            {
                "event": "attachment_failed",
                "ctf": "fake-ctfd",
                "local_path": "Web/1-First/files/a.bin",
                "code": "file_too_large",
            },
        )
        self.assertEqual(progress.of("attachment_done"), [])


class BrokenProgressTests(unittest.TestCase):
    """A reporter is a display, so its bugs must never cost us a collection."""

    def collect_with(self, progress):
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(
                ctfd_responder(headers={"Content-Length": len(ATTACHMENT_BODY)})
            )
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config, progress=progress)
            stored = (
                config["output_root"]
                / "fake-ctfd"
                / "Web"
                / "1-First"
                / "files"
                / "a.bin"
            )
            return manifest, stored.read_bytes()

    def test_a_callback_that_always_raises_does_not_stop_the_collection(self):
        def progress(event):
            raise RuntimeError("reporter is broken")

        manifest, body = self.collect_with(progress)

        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(body, ATTACHMENT_BODY)

    def test_a_broken_callback_is_disabled_after_its_first_failure(self):
        calls = []

        def progress(event):
            calls.append(event)
            raise ValueError("boom")

        manifest, _body = self.collect_with(progress)

        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(len(calls), 1, calls)

    def test_a_callback_that_raises_a_string_formatting_bug_is_tolerated(self):
        def progress(event):
            return event["field_that_does_not_exist"]

        manifest, body = self.collect_with(progress)

        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(body, ATTACHMENT_BODY)

    def test_an_interrupt_from_the_reporter_still_reaches_the_operator(self):
        def progress(event):
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            self.collect_with(progress)

    def test_one_broken_callback_is_disabled_for_the_whole_run(self):
        calls = []

        def progress(event):
            calls.append(event)
            raise RuntimeError("boom")

        configs = [
            {"name": "first", "fail_on_partial": True},
            {"name": "second", "fail_on_partial": True},
        ]
        with (
            patch(
                "ctf_collector.collector._preflight_configs",
                return_value=["a-token", "b-token"],
            ),
            patch(
                "ctf_collector.collector.collect_ctf",
                return_value={"status": "complete", "failures": []},
            ),
        ):
            results = collect_all(configs, progress=progress)

        self.assertEqual(len(results), 2)
        self.assertTrue(all(result["error"] is None for result in results))
        self.assertEqual(len(calls), 1, calls)


class CollectAllProgressTests(unittest.TestCase):
    def test_each_ctf_start_and_outcome_is_reported(self):
        progress = RecordingProgress()
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(ctfd_responder(files=()))
            with patch("ctf_collector.http.build_opener", return_value=fake):
                collect_all([config], progress=progress)

        self.assertEqual(progress.kinds()[0], "ctf_start")
        self.assertEqual(
            progress.of("ctf_start")[0],
            {"event": "ctf_start", "ctf": "fake-ctfd", "index": 1, "total": 1},
        )
        self.assertEqual(
            progress.of("ctf_done")[0],
            {
                "event": "ctf_done",
                "ctf": "fake-ctfd",
                "status": "complete",
                "failures": 0,
            },
        )

    def test_a_failed_ctf_reports_its_error_code_and_the_run_continues(self):
        progress = RecordingProgress()
        configs = [
            {"name": "broken", "fail_on_partial": True},
            {"name": "healthy", "fail_on_partial": True},
        ]
        with (
            patch(
                "ctf_collector.collector._preflight_configs",
                return_value=["first-token", "second-token"],
            ),
            patch(
                "ctf_collector.collector.collect_ctf",
                side_effect=[
                    OSError("disk unavailable"),
                    {"status": "complete", "failures": []},
                ],
            ),
        ):
            results = collect_all(configs, progress=progress)

        self.assertEqual(len(results), 2)
        self.assertEqual(
            progress.of("ctf_failed")[0],
            {"event": "ctf_failed", "ctf": "broken", "code": "io_error"},
        )
        self.assertEqual(progress.of("ctf_done")[0]["ctf"], "healthy")


if __name__ == "__main__":
    unittest.main()
