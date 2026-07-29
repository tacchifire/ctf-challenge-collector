import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from ctf_collector.collector import collect_ctf
from ctf_collector.errors import CollectorError

from .support import FakeOpener, FakeResponse, make_config


def terminal_page(items):
    return {
        "data": items,
        "meta": {
            "pagination": {
                "next": None,
                "page": 1,
                "pages": 1,
            }
        },
    }


class CtfdPaginationFindingTests(unittest.TestCase):
    def collect(self, responder, **limit_overrides):
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            config["limits"].update(limit_overrides)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)
            list_pages = [
                int(parse_qs(urlsplit(item["url"]).query)["page"][0])
                for item in fake.requests
                if urlsplit(item["url"]).path == "/api/v1/challenges"
            ]
            return manifest, list_pages

    def test_meta_pagination_next_page_wins_over_short_page_length(self):
        def responder(request):
            parsed = urlsplit(request["url"])
            if parsed.path == "/api/v1/challenges":
                page = int(parse_qs(parsed.query)["page"][0])
                return 200, {}, {
                    "data": [
                        {
                            "id": page,
                            "name": f"Page {page}",
                            "category": "web",
                        }
                    ],
                    "meta": {
                        "pagination": {
                            "page": page,
                            "pages": 2,
                            "next": page + 1 if page == 1 else None,
                        }
                    },
                }
            if parsed.path.startswith("/api/v1/challenges/"):
                challenge_id = parsed.path.rsplit("/", 1)[-1]
                return 200, {}, {
                    "data": {
                        "id": challenge_id,
                        "name": f"Page {challenge_id}",
                        "category": "web",
                        "files": [],
                    }
                }
            return 404, {}, b"missing"

        manifest, pages = self.collect(responder, page_size=100)

        self.assertEqual(manifest["status"], "complete")
        self.assertEqual([item["id"] for item in manifest["challenges"]], ["1", "2"])
        self.assertEqual(pages, [1, 2])

    def test_short_page_without_meta_continues_until_empty_terminal_page(self):
        def responder(request):
            parsed = urlsplit(request["url"])
            if parsed.path == "/api/v1/challenges":
                page = int(parse_qs(parsed.query)["page"][0])
                if page == 1:
                    return 200, {}, {
                        "data": [{"id": 1, "name": "One", "category": "web"}]
                    }
                return 200, {}, {"data": []}
            if parsed.path == "/api/v1/challenges/1":
                return 200, {}, {
                    "data": {
                        "id": 1,
                        "name": "One",
                        "category": "web",
                        "files": [],
                    }
                }
            return 404, {}, b"missing"

        manifest, pages = self.collect(responder, page_size=100)

        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(pages, [1, 2])

    def test_repeated_page_is_a_structured_partial_failure(self):
        repeated = [{"id": 1, "name": "One", "category": "web"}]

        def responder(request):
            path = urlsplit(request["url"]).path
            if path == "/api/v1/challenges":
                return 200, {}, {"data": repeated}
            if path == "/api/v1/challenges/1":
                return 200, {}, {"data": {**repeated[0], "files": []}}
            return 404, {}, b"missing"

        manifest, pages = self.collect(responder, page_size=1)

        self.assertEqual(manifest["status"], "partial")
        self.assertEqual(pages, [1, 2])
        self.assertIn(
            "pagination_no_progress",
            [failure["error"]["code"] for failure in manifest["failures"]],
        )

    def test_inconsistent_meta_is_a_structured_partial_failure(self):
        def responder(request):
            path = urlsplit(request["url"]).path
            if path == "/api/v1/challenges":
                return 200, {}, {
                    "data": [{"id": 1, "name": "One", "category": "web"}],
                    "meta": {
                        "pagination": {
                            "page": 7,
                            "pages": 2,
                            "next": 2,
                        }
                    },
                }
            if path == "/api/v1/challenges/1":
                return 200, {}, {
                    "data": {
                        "id": 1,
                        "name": "One",
                        "category": "web",
                        "files": [],
                    }
                }
            return 404, {}, b"missing"

        manifest, pages = self.collect(responder)

        self.assertEqual(manifest["status"], "partial")
        self.assertEqual(pages, [1])
        self.assertIn(
            "pagination_inconsistent",
            [failure["error"]["code"] for failure in manifest["failures"]],
        )

    def test_meta_next_beyond_max_pages_is_a_structured_partial_failure(self):
        def responder(request):
            path = urlsplit(request["url"]).path
            if path == "/api/v1/challenges":
                return 200, {}, {
                    "data": [{"id": 1, "name": "One", "category": "web"}],
                    "meta": {
                        "pagination": {
                            "page": 1,
                            "pages": 2,
                            "next": 2,
                        }
                    },
                }
            if path == "/api/v1/challenges/1":
                return 200, {}, {
                    "data": {
                        "id": 1,
                        "name": "One",
                        "category": "web",
                        "files": [],
                    }
                }
            return 404, {}, b"missing"

        manifest, pages = self.collect(responder, max_pages=1)

        self.assertEqual(manifest["status"], "partial")
        self.assertEqual(pages, [1])
        self.assertIn(
            "pagination_limit",
            [failure["error"]["code"] for failure in manifest["failures"]],
        )


class AttachmentAndCacheFindingTests(unittest.TestCase):
    def test_changed_redacted_source_url_forces_redownload(self):
        current_path = "/first/payload.bin"
        bodies = {
            "/first/payload.bin": b"first",
            "/second/payload.bin": b"second",
        }
        downloads = []

        def responder(request):
            path = urlsplit(request["url"]).path
            if path == "/api/v1/challenges":
                return 200, {}, terminal_page(
                    [{"id": 1, "name": "One", "category": "web"}]
                )
            if path == "/api/v1/challenges/1":
                return 200, {}, {
                    "data": {
                        "id": 1,
                        "name": "One",
                        "category": "web",
                        "files": [{"name": "payload.bin", "url": current_path}],
                    }
                }
            if path in bodies:
                downloads.append(path)
                return 200, {}, bodies[path]
            return 404, {}, b"missing"

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                first = collect_ctf(config)
                current_path = "/second/payload.bin"
                second = collect_ctf(config)

            target = (
                Path(tmp)
                / "out"
                / "fake-ctfd"
                / "web"
                / "1-One"
                / "files"
                / "payload.bin"
            )
            self.assertEqual(first["challenges"][0]["files"][0]["status"], "downloaded")
            self.assertEqual(second["challenges"][0]["files"][0]["status"], "downloaded")
            self.assertEqual(downloads, ["/first/payload.bin", "/second/payload.bin"])
            self.assertEqual(target.read_bytes(), b"second")

    def test_malformed_attachment_does_not_suppress_valid_attachments(self):
        bodies = {
            "/files/one.bin": b"one",
            "/files/two.bin": b"two",
        }

        def responder(request):
            path = urlsplit(request["url"]).path
            if path == "/api/v1/challenges":
                return 200, {}, terminal_page(
                    [{"id": 1, "name": "One", "category": "web"}]
                )
            if path == "/api/v1/challenges/1":
                return 200, {}, {
                    "data": {
                        "id": 1,
                        "name": "One",
                        "category": "web",
                        "files": [
                            "/files/one.bin",
                            {"name": "broken.bin"},
                            {"name": "two.bin", "url": "/files/two.bin"},
                        ],
                    }
                }
            if path in bodies:
                return 200, {}, bodies[path]
            return 404, {}, b"missing"

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)

            files = manifest["challenges"][0]["files"]
            self.assertEqual(manifest["status"], "partial")
            self.assertEqual(
                [failure["error"]["code"] for failure in manifest["failures"]],
                ["invalid_api_data"],
            )
            self.assertEqual(
                [(item["local_path"].rsplit("/", 1)[-1], item["status"]) for item in files],
                [("one.bin", "downloaded"), ("two.bin", "downloaded")],
            )
            stored = (
                Path(tmp) / "out" / "fake-ctfd" / "web" / "1-One" / "files"
            )
            self.assertEqual((stored / "one.bin").read_bytes(), b"one")
            self.assertEqual((stored / "two.bin").read_bytes(), b"two")


class SwappingResponse(FakeResponse):
    def __init__(self, body, files_path):
        super().__init__(body)
        self.files_path = files_path
        self.swapped = False

    def read(self, size=-1):
        if not self.swapped:
            self.swapped = True
            real_path = self.files_path.with_name("files-real")
            self.files_path.rename(real_path)
            self.files_path.symlink_to(real_path.name, target_is_directory=True)
        return super().read(size)


class DirectoryFdFindingTests(unittest.TestCase):
    def test_symlink_swap_during_download_is_rejected_without_following_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            files_path = (
                Path(tmp) / "out" / "fake-ctfd" / "web" / "1-One" / "files"
            )

            def responder(request):
                path = urlsplit(request["url"]).path
                if path == "/api/v1/challenges":
                    return 200, {}, terminal_page(
                        [{"id": 1, "name": "One", "category": "web"}]
                    )
                if path == "/api/v1/challenges/1":
                    return 200, {}, {
                        "data": {
                            "id": 1,
                            "name": "One",
                            "category": "web",
                            "files": ["/files/swap.bin"],
                        }
                    }
                if path == "/files/swap.bin":
                    return SwappingResponse(b"must-not-land", files_path)
                return 404, {}, b"missing"

            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)

            self.assertEqual(manifest["status"], "partial")
            self.assertIn(
                "unsafe_path",
                [failure["error"]["code"] for failure in manifest["failures"]],
            )
            self.assertTrue(files_path.is_symlink())
            self.assertFalse((files_path / "swap.bin").exists())
            self.assertFalse((files_path.with_name("files-real") / "swap.bin").exists())
            self.assertEqual(
                list(files_path.with_name("files-real").glob("*.part")),
                [],
            )

    def test_missing_directory_fd_primitives_fail_closed_before_http(self):
        def responder(request):
            return 200, {}, terminal_page([])

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with (
                patch("ctf_collector.http.build_opener", return_value=fake),
                patch(
                    "ctf_collector.safety._dirfd_capability_error",
                    return_value="O_NOFOLLOW is unavailable",
                    create=True,
                ),
                self.assertRaises(CollectorError) as caught,
            ):
                collect_ctf(config)

            self.assertEqual(caught.exception.code, "unsupported_platform")
            self.assertIn("O_NOFOLLOW", caught.exception.message)
            self.assertEqual(fake.requests, [])


if __name__ == "__main__":
    unittest.main()
