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

from ctf_collector.collector import _download, collect_all, collect_ctf
from ctf_collector.config import MAX_TOTAL_BYTES
from ctf_collector.errors import CollectorError
from ctf_collector.safety import ctf_directory_name

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
    def test_non_integer_runtime_limit_fails_before_network(self):
        opened = []

        class Client:
            def open_get(self, url, *, attachment=False):
                opened.append(url)
                raise AssertionError("invalid limits must fail before network")

        with self.assertRaises(CollectorError) as caught:
            _download(
                Client(),
                "https://base.example/file.bin",
                object(),
                (),
                "file.bin",
                {
                    "max_file_bytes": float("nan"),
                    "max_total_bytes": MAX_TOTAL_BYTES,
                },
                0,
                ctf_name="safe",
                local_path="files/file.bin",
            )

        self.assertEqual(caught.exception.code, "invalid_config")
        self.assertEqual(opened, [])

    def test_collect_ctf_normalizes_all_limits_before_http_or_cache_paths(self):
        invalid_cases = (
            ("page_size", float("nan")),
            ("max_pages", "10"),
            ("max_file_bytes", float("nan")),
            ("max_total_bytes", True),
            ("max_redirects", -1),
            ("max_metadata_bytes", 1),
        )
        for key, invalid_value in invalid_cases:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as tmp:
                limits = {
                    "page_size": 2,
                    "max_pages": 10,
                    "max_file_bytes": 100,
                    "max_total_bytes": 1000,
                    "max_redirects": 3,
                    "max_metadata_bytes": 1024 * 1024,
                }
                limits[key] = invalid_value
                config = make_config(tmp, limits=limits)
                with patch("ctf_collector.http.build_opener") as build_opener:
                    with self.assertRaises(CollectorError) as caught:
                        collect_ctf(config)

                self.assertEqual(caught.exception.code, "invalid_config")
                build_opener.assert_not_called()

    def test_absolute_total_cap_rejects_without_prompt_and_closes_response(self):
        response = FakeResponse(b"x", headers={"Content-Length": "1"})
        requests = []

        class Client:
            def open_get(self, url, *, attachment=False):
                return response, url

        with self.assertRaises(CollectorError) as caught:
            _download(
                Client(),
                "https://base.example/file.bin",
                object(),
                (),
                "file.bin",
                {
                    "max_file_bytes": MAX_TOTAL_BYTES,
                    "max_total_bytes": MAX_TOTAL_BYTES + 1,
                },
                MAX_TOTAL_BYTES,
                ctf_name="safe",
                local_path="files/file.bin",
                limit_approver=lambda request: requests.append(request) or True,
            )

        self.assertEqual(caught.exception.code, "total_too_large")
        self.assertEqual(requests, [])
        self.assertTrue(response._stream.closed)

    def collect(self, responder, *, limit_approver=None, **overrides):
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp, **overrides)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config, limit_approver=limit_approver)
            root = Path(tmp) / "out" / ctf_directory_name(config["name"])
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

    def test_declared_oversize_download_requires_explicit_finite_approval(self):
        requests = []

        def responder(request):
            listing = challenge_listing(request, ["/files/large.bin"])
            if listing is not None:
                return listing
            if urlsplit(request["url"]).path == "/files/large.bin":
                return 200, {"Content-Length": "6"}, b"123456"
            return 404, {}, b"missing"

        def approve(request):
            requests.append(request)
            return True

        limits = {
            "page_size": 2,
            "max_pages": 10,
            "max_file_bytes": 5,
            "max_total_bytes": 5,
            "max_redirects": 3,
            "max_metadata_bytes": 1024 * 1024,
        }
        manifest, stored, leftovers = self.collect(
            responder,
            limit_approver=approve,
            limits=limits,
        )

        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(stored, ["large.bin"])
        self.assertEqual(leftovers, [])
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]["exceeded"], "both")
        self.assertEqual(requests[0]["required_file_bytes"], 6)
        self.assertEqual(requests[0]["required_total_bytes"], 6)
        self.assertEqual(requests[0]["current_file_limit"], 5)
        self.assertEqual(requests[0]["current_total_limit"], 5)
        self.assertEqual(requests[0]["local_path"], "web/1-One/files/large.bin")
        self.assertEqual(limits["max_file_bytes"], 5)
        self.assertEqual(limits["max_total_bytes"], 5)

    def test_approval_request_uses_terminal_safe_ctf_name(self):
        requests = []

        def responder(request):
            listing = challenge_listing(request, ["/files/safe.bin"])
            if listing is not None:
                return listing
            if urlsplit(request["url"]).path == "/files/safe.bin":
                return 200, {"Content-Length": "6"}, b"123456"
            return 404, {}, b"missing"

        manifest, stored, leftovers = self.collect(
            responder,
            name="event\x1b[2J\nspoof",
            limit_approver=lambda request: requests.append(request) or True,
            limits={
                "page_size": 2,
                "max_pages": 10,
                "max_file_bytes": 5,
                "max_total_bytes": 20,
                "max_redirects": 3,
                "max_metadata_bytes": 1024 * 1024,
            },
        )

        self.assertEqual(manifest["status"], "complete")
        self.assertNotIn("\x1b", requests[0]["ctf_name"])
        self.assertNotIn("\n", requests[0]["ctf_name"])
        self.assertEqual(stored, ["safe.bin"])
        self.assertEqual(leftovers, [])

    def test_declared_oversize_identifies_file_and_total_scopes(self):
        cases = (
            (5, 20, "file"),
            (20, 5, "total"),
        )
        for file_limit, total_limit, expected in cases:
            with self.subTest(expected=expected):
                requests = []

                def responder(request):
                    listing = challenge_listing(request, ["/files/scoped.bin"])
                    if listing is not None:
                        return listing
                    if urlsplit(request["url"]).path == "/files/scoped.bin":
                        return 200, {"Content-Length": "6"}, b"123456"
                    return 404, {}, b"missing"

                manifest, stored, leftovers = self.collect(
                    responder,
                    limit_approver=lambda request: requests.append(request) or True,
                    limits={
                        "page_size": 2,
                        "max_pages": 10,
                        "max_file_bytes": file_limit,
                        "max_total_bytes": total_limit,
                        "max_redirects": 3,
                        "max_metadata_bytes": 1024 * 1024,
                    },
                )

                self.assertEqual(manifest["status"], "complete")
                self.assertEqual(requests[0]["exceeded"], expected)
                self.assertEqual(stored, ["scoped.bin"])
                self.assertEqual(leftovers, [])

    def two_oversize_attachments(self, request):
        listing = challenge_listing(
            request,
            ["/files/first.bin", "/files/second.bin"],
        )
        if listing is not None:
            return listing
        if urlsplit(request["url"]).path in {
            "/files/first.bin",
            "/files/second.bin",
        }:
            return 200, {"Content-Length": "6"}, b"123456"
        return 404, {}, b"missing"

    OVERSIZE_LIMITS = {
        "page_size": 2,
        "max_pages": 10,
        "max_file_bytes": 5,
        "max_total_bytes": 20,
        "max_redirects": 3,
        "max_metadata_bytes": 1024 * 1024,
    }

    def test_one_approval_covers_every_oversize_attachment_in_the_run(self):
        requests = []

        def approve(request):
            requests.append(request)
            return True

        manifest, stored, leftovers = self.collect(
            self.two_oversize_attachments,
            limit_approver=approve,
            limits=dict(self.OVERSIZE_LIMITS),
        )

        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(len(requests), 1)
        self.assertEqual(
            [entry["status"] for entry in manifest["challenges"][0]["files"]],
            ["downloaded", "downloaded"],
        )
        self.assertEqual(stored, ["first.bin", "second.bin"])
        self.assertEqual(leftovers, [])

    def test_a_refusal_is_not_asked_again_for_the_rest_of_the_run(self):
        requests = []

        def refuse(request):
            requests.append(request)
            return False

        manifest, stored, leftovers = self.collect(
            self.two_oversize_attachments,
            limit_approver=refuse,
            limits=dict(self.OVERSIZE_LIMITS),
        )

        self.assertEqual(manifest["status"], "partial")
        self.assertEqual(len(requests), 1)
        self.assertEqual(
            [entry["status"] for entry in manifest["challenges"][0]["files"]],
            ["failed", "failed"],
        )
        self.assertEqual(stored, [])
        self.assertEqual(leftovers, [])

    def test_an_approver_that_raises_refuses_the_run_without_asking_again(self):
        requests = []

        def explode(request):
            requests.append(request)
            raise RuntimeError("the prompt is broken")

        manifest, stored, leftovers = self.collect(
            self.two_oversize_attachments,
            limit_approver=explode,
            limits=dict(self.OVERSIZE_LIMITS),
        )

        self.assertEqual(manifest["status"], "partial")
        self.assertEqual(len(requests), 1)
        self.assertEqual(
            [entry["status"] for entry in manifest["challenges"][0]["files"]],
            ["failed", "failed"],
        )
        self.assertEqual(stored, [])
        self.assertEqual(leftovers, [])

    def test_an_interrupt_at_the_prompt_still_reaches_the_operator(self):
        def interrupt(request):
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            self.collect(
                self.two_oversize_attachments,
                limit_approver=interrupt,
                limits=dict(self.OVERSIZE_LIMITS),
            )

    def test_unknown_oversize_does_not_request_unbounded_approval(self):
        requests = []

        def responder(request):
            listing = challenge_listing(request, ["/files/unknown.bin"])
            if listing is not None:
                return listing
            if urlsplit(request["url"]).path == "/files/unknown.bin":
                return 200, {}, b"123456"
            return 404, {}, b"missing"

        manifest, stored, leftovers = self.collect(
            responder,
            limit_approver=lambda request: requests.append(request) or True,
            limits={
                "page_size": 2,
                "max_pages": 10,
                "max_file_bytes": 5,
                "max_total_bytes": 5,
                "max_redirects": 3,
                "max_metadata_bytes": 1024 * 1024,
            },
        )

        self.assertEqual(manifest["status"], "partial")
        self.assertEqual(requests, [])
        self.assertEqual(stored, [])
        self.assertEqual(leftovers, [])

    def test_oversize_approval_must_be_literal_true(self):
        def responder(request):
            listing = challenge_listing(request, ["/files/rejected.bin"])
            if listing is not None:
                return listing
            if urlsplit(request["url"]).path == "/files/rejected.bin":
                return 200, {"Content-Length": "6"}, b"123456"
            return 404, {}, b"missing"

        limits = {
            "page_size": 2,
            "max_pages": 10,
            "max_file_bytes": 5,
            "max_total_bytes": 20,
            "max_redirects": 3,
            "max_metadata_bytes": 1024 * 1024,
        }
        manifest, stored, leftovers = self.collect(
            responder,
            limit_approver=lambda request: 1,
            limits=limits,
        )

        self.assertEqual(manifest["status"], "partial")
        self.assertEqual(manifest["failures"][0]["error"]["code"], "file_too_large")
        self.assertEqual(stored, [])
        self.assertEqual(leftovers, [])

    def test_approval_does_not_disable_content_length_integrity(self):
        def responder(request):
            listing = challenge_listing(request, ["/files/short.bin"])
            if listing is not None:
                return listing
            if urlsplit(request["url"]).path == "/files/short.bin":
                return 200, {"Content-Length": "6"}, b"12345"
            return 404, {}, b"missing"

        manifest, stored, leftovers = self.collect(
            responder,
            limit_approver=lambda request: True,
            limits={
                "page_size": 2,
                "max_pages": 10,
                "max_file_bytes": 5,
                "max_total_bytes": 20,
                "max_redirects": 3,
                "max_metadata_bytes": 1024 * 1024,
            },
        )

        self.assertEqual(manifest["status"], "partial")
        self.assertEqual(
            manifest["failures"][0]["error"]["code"],
            "truncated_download",
        )
        self.assertEqual(stored, [])
        self.assertEqual(leftovers, [])

    def test_declared_size_above_hard_cap_is_not_prompted(self):
        requests = []

        def responder(request):
            listing = challenge_listing(request, ["/files/impossible.bin"])
            if listing is not None:
                return listing
            if urlsplit(request["url"]).path == "/files/impossible.bin":
                return 200, {"Content-Length": str(1024 ** 4 + 1)}, b""
            return 404, {}, b"missing"

        oversized_limits = {
            "page_size": 2,
            "max_pages": 10,
            "max_file_bytes": 1024 ** 4 + 10,
            "max_total_bytes": 1024 ** 5 + 10,
            "max_redirects": 3,
            "max_metadata_bytes": 1024 * 1024,
        }
        manifest, stored, leftovers = self.collect(
            responder,
            limit_approver=lambda request: requests.append(request) or True,
            limits=oversized_limits,
        )

        self.assertEqual(manifest["status"], "partial")
        self.assertEqual(
            manifest["failures"][0]["error"]["code"],
            "file_too_large",
        )
        self.assertEqual(requests, [])
        self.assertEqual(stored, [])
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


class RunApprovalScopeTests(unittest.TestCase):
    """The run is the unit of approval: one answer covers it, and only it."""

    LIMITS = {
        "page_size": 2,
        "max_pages": 10,
        "max_file_bytes": 5,
        "max_total_bytes": 20,
        "max_redirects": 3,
        "max_metadata_bytes": 1024 * 1024,
    }

    @staticmethod
    def responder(request):
        listing = challenge_listing(request, ["/files/big.bin"])
        if listing is not None:
            return listing
        if urlsplit(request["url"]).path == "/files/big.bin":
            return 200, {"Content-Length": "6"}, b"123456"
        return 404, {}, b"missing"

    def run_collection(self, tmp, names, limit_approver):
        configs = [
            make_config(tmp, name=name, limits=dict(self.LIMITS))
            for name in names
        ]
        fake = FakeOpener(self.responder)
        with patch("ctf_collector.http.build_opener", return_value=fake):
            results = collect_all(configs, limit_approver=limit_approver)
        stored = sorted(
            path.name
            for path in (Path(tmp) / "out").rglob("*")
            if path.is_file() and path.parent.name == "files"
        )
        return results, stored

    def test_one_approval_covers_every_ctf_in_the_same_run(self):
        requests = []

        with tempfile.TemporaryDirectory() as tmp:
            results, stored = self.run_collection(
                tmp,
                ("first-ctf", "second-ctf"),
                lambda request: requests.append(request) or True,
            )

        self.assertEqual(len(requests), 1)
        self.assertEqual([result["partial"] for result in results], [False, False])
        self.assertEqual(stored, ["big.bin", "big.bin"])


if __name__ == "__main__":
    unittest.main()
