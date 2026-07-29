"""A short read must never be renamed into place as a complete attachment.

`Content-Length` is the only length signal the collector gets for an identity
encoded body, so a body that stops early has to be rejected before the atomic
rename, and a stream that raises partway through must surface as a collector
failure rather than an unhandled exception.
"""

from http.client import IncompleteRead
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from ctf_collector.collector import collect_ctf
from ctf_collector.errors import CollectorError

from .support import FakeOpener, FakeResponse, make_config


class BrokenStreamResponse(FakeResponse):
    """Models a connection that dies after the first chunk."""

    def read(self, size=-1):
        raise IncompleteRead(b"partial", 64)


def challenge_listing(request, files):
    parsed = urlsplit(request["url"])
    if parsed.path == "/api/v1/challenges":
        return 200, {}, {
            "data": [{"id": 1, "name": "One", "category": "web"}],
            "meta": {
                "pagination": {
                    "page": 1,
                    "pages": 1,
                    "next": None,
                }
            },
        }
    if parsed.path == "/api/v1/challenges/1":
        return 200, {}, {
            "data": {"id": 1, "name": "One", "category": "web", "files": files}
        }
    return None


class DownloadIntegrityTests(unittest.TestCase):
    def collect(self, responder, **overrides):
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp, **overrides)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)
            root = Path(tmp) / "out" / "fake-ctfd"
            stored = sorted(
                path.name for path in root.rglob("*")
                if path.is_file() and path.parent.name == "files"
            )
            leftovers = sorted(str(path) for path in root.rglob("*.part"))
            return manifest, stored, leftovers

    def test_short_body_against_declared_content_length_is_rejected(self):
        def responder(request):
            listing = challenge_listing(request, ["/files/short.bin"])
            if listing is not None:
                return listing
            if urlsplit(request["url"]).path == "/files/short.bin":
                # Declares 64 bytes, delivers 6.
                return 200, {"Content-Length": "64"}, b"123456"
            return 404, {}, b"missing"

        manifest, stored, leftovers = self.collect(responder)

        self.assertEqual(manifest["status"], "partial")
        self.assertEqual(
            [failure["error"]["code"] for failure in manifest["failures"]],
            ["truncated_download"],
        )
        self.assertEqual(
            manifest["challenges"][0]["files"][0]["status"], "failed"
        )
        self.assertEqual(stored, [], "a truncated body must not be renamed into place")
        self.assertEqual(leftovers, [])

    def test_honest_content_length_still_downloads(self):
        def responder(request):
            listing = challenge_listing(request, ["/files/whole.bin"])
            if listing is not None:
                return listing
            if urlsplit(request["url"]).path == "/files/whole.bin":
                return 200, {"Content-Length": "6"}, b"123456"
            return 404, {}, b"missing"

        manifest, stored, leftovers = self.collect(responder)

        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(stored, ["whole.bin"])
        self.assertEqual(leftovers, [])

    def test_missing_content_length_is_accepted(self):
        def responder(request):
            listing = challenge_listing(request, ["/files/nolength.bin"])
            if listing is not None:
                return listing
            if urlsplit(request["url"]).path == "/files/nolength.bin":
                return 200, {}, b"123456"
            return 404, {}, b"missing"

        manifest, stored, leftovers = self.collect(responder)

        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(stored, ["nolength.bin"])
        self.assertEqual(leftovers, [])

    def test_zero_content_length_with_nonempty_body_is_rejected(self):
        def responder(request):
            listing = challenge_listing(request, ["/files/zero.bin"])
            if listing is not None:
                return listing
            if urlsplit(request["url"]).path == "/files/zero.bin":
                return 200, {"Content-Length": "0"}, b"123456"
            return 404, {}, b"missing"

        manifest, stored, leftovers = self.collect(responder)

        self.assertEqual(manifest["status"], "partial")
        self.assertEqual(
            [failure["error"]["code"] for failure in manifest["failures"]],
            ["truncated_download"],
        )
        self.assertEqual(stored, [])
        self.assertEqual(leftovers, [])

    def test_negative_and_invalid_content_lengths_are_rejected(self):
        for declared in ("-1", "six"):
            with self.subTest(declared=declared):
                def responder(request):
                    listing = challenge_listing(request, ["/files/invalid.bin"])
                    if listing is not None:
                        return listing
                    if urlsplit(request["url"]).path == "/files/invalid.bin":
                        return 200, {"Content-Length": declared}, b"123456"
                    return 404, {}, b"missing"

                manifest, stored, leftovers = self.collect(responder)

                self.assertEqual(manifest["status"], "partial")
                self.assertEqual(
                    [failure["error"]["code"] for failure in manifest["failures"]],
                    ["invalid_content_length"],
                )
                self.assertEqual(stored, [])
                self.assertEqual(leftovers, [])

    def test_stream_that_dies_midway_becomes_a_failure_not_a_crash(self):
        def responder(request):
            listing = challenge_listing(request, ["/files/broken.bin"])
            if listing is not None:
                return listing
            if urlsplit(request["url"]).path == "/files/broken.bin":
                return BrokenStreamResponse(b"", 200, {"Content-Length": "64"})
            return 404, {}, b"missing"

        manifest, stored, leftovers = self.collect(responder)

        self.assertEqual(manifest["status"], "partial")
        self.assertEqual(
            [failure["error"]["code"] for failure in manifest["failures"]],
            ["download_failed"],
        )
        self.assertEqual(stored, [])
        self.assertEqual(leftovers, [])

    def test_metadata_stream_that_dies_midway_becomes_a_collector_error(self):
        def responder(request):
            if urlsplit(request["url"]).path == "/api/v1/challenges":
                return BrokenStreamResponse(b"", 200, {})
            return 404, {}, b"missing"

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with (
                patch("ctf_collector.http.build_opener", return_value=fake),
                self.assertRaises(CollectorError) as caught,
            ):
                collect_ctf(config)

        self.assertEqual(caught.exception.code, "network_error")


if __name__ == "__main__":
    unittest.main()
