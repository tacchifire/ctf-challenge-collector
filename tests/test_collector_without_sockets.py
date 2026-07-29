import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from ctf_collector.collector import collect_all, collect_ctf
from ctf_collector.errors import CollectorError

from .support import FakeOpener, make_config


class CollectorWithoutSocketsTests(unittest.TestCase):
    def test_multiple_ctfs_continue_after_scoped_io_failure(self):
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
                side_effect=[OSError("disk unavailable"), {"status": "complete"}],
            ),
        ):
            results = collect_all(configs)

        self.assertEqual([item["name"] for item in results], ["broken", "healthy"])
        self.assertEqual(results[0]["error"].code, "io_error")
        self.assertIsNone(results[1]["error"])
        self.assertFalse(results[1]["partial"])

    def test_token_file_rejects_embedded_line_break_before_http(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            config["token_file"].write_text("first\nsecond\n", encoding="utf-8")
            fake = FakeOpener(lambda request: self.fail("HTTP must not be attempted"))
            with (
                patch("ctf_collector.http.build_opener", return_value=fake),
                self.assertRaisesRegex(CollectorError, "visible ASCII"),
            ):
                collect_ctf(config)
            self.assertEqual(fake.requests, [])

    def test_ctfd_accepts_data_object_map_and_single_detail_array(self):
        def responder(request):
            path = urlsplit(request["url"]).path
            if path == "/api/v1/challenges":
                return 200, {}, {
                    "data": {
                        "only": {
                            "id": "mapped",
                            "name": "Mapped",
                            "category": "forensics",
                        }
                    },
                    "meta": {
                        "pagination": {
                            "page": 1,
                            "pages": 1,
                            "next": None,
                        }
                    },
                }
            if path == "/api/v1/challenges/mapped":
                return 200, {}, {
                    "data": [
                        {
                            "id": "mapped",
                            "name": "Mapped",
                            "category": "forensics",
                            "files": [],
                        }
                    ]
                }
            return 404, {}, b"missing"

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)

            self.assertEqual(manifest["status"], "complete")
            self.assertEqual(manifest["challenges"][0]["id"], "mapped")

    def test_ctfd_collection_is_get_only_authenticated_and_idempotent(self):
        attachment = b"flag{memory-transport}"
        file_requests = 0

        def responder(request):
            nonlocal file_requests
            parsed = urlsplit(request["url"])
            if parsed.path == "/api/v1/challenges":
                page = int(parse_qs(parsed.query)["page"][0])
                if page == 1:
                    return 200, {}, {
                        "data": [
                            {"id": 1, "name": "One", "category": "web"},
                            {"id": 2, "name": "Two", "category": "pwn"},
                        ]
                    }
                return 200, {}, {"data": []}
            if parsed.path == "/api/v1/challenges/1":
                return 200, {}, {
                    "data": {
                        "id": 1,
                        "name": "One",
                        "category": "web",
                        "description": "kept",
                        "reflected": "server saw ctfd-secret",
                        "relative_url": "downloads/help?signature=never-either",
                        "files": ["/files/a.txt?signed=never-write"],
                    }
                }
            if parsed.path == "/api/v1/challenges/2":
                return 200, {}, {
                    "data": {
                        "id": 2,
                        "name": "Two",
                        "category": "pwn",
                        "files": [],
                    }
                }
            if parsed.path == "/files/a.txt":
                file_requests += 1
                return 200, {}, attachment
            return 404, {}, b"missing"

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                first = collect_ctf(config)
                second = collect_ctf(config)

            self.assertEqual(first["status"], "complete")
            self.assertEqual(second["status"], "complete")
            self.assertEqual(file_requests, 1)
            self.assertTrue(all(item["method"] == "GET" for item in fake.requests))
            self.assertTrue(
                all(
                    item["headers"].get("authorization") == "Token ctfd-secret"
                    for item in fake.requests
                )
            )
            challenge = (
                Path(tmp) / "out" / "fake-ctfd" / "web" / "1-One"
            )
            self.assertEqual((challenge / "files" / "a.txt").read_bytes(), attachment)
            self.assertEqual(
                json.loads((challenge / "challenge.json").read_text())["raw"][
                    "description"
                ],
                "kept",
            )
            manifest_text = (
                Path(tmp) / "out" / "fake-ctfd" / "manifest.json"
            ).read_text()
            self.assertNotIn("never-write", manifest_text)
            self.assertNotIn("ctfd-secret", manifest_text)
            self.assertNotIn(
                "ctfd-secret",
                (challenge / "challenge.json").read_text(),
            )
            self.assertNotIn(
                "never-either",
                (challenge / "challenge.json").read_text(),
            )
            self.assertEqual(second["challenges"][1]["files"][0]["status"], "verified")

    def test_existing_ctf_root_symlink_cannot_redirect_output(self):
        def responder(request):
            if urlsplit(request["url"]).path == "/api/v1/challenges":
                return 200, {}, {"data": []}
            return 404, {}, b"missing"

        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as other:
            config = make_config(tmp)
            config["output_root"].mkdir()
            (config["output_root"] / "fake-ctfd").symlink_to(
                Path(other),
                target_is_directory=True,
            )
            fake = FakeOpener(responder)
            with (
                patch("ctf_collector.http.build_opener", return_value=fake),
                self.assertRaisesRegex(Exception, "symlink"),
            ):
                collect_ctf(config)
            self.assertEqual(list(Path(other).iterdir()), [])

    def test_rctf_fallback_detail_and_foreign_attachment_is_anonymous(self):
        payload = b"foreign"

        def responder(request):
            parsed = urlsplit(request["url"])
            if parsed.path in ("/api/v1/challs", "/api/v1/challenges"):
                return 404, {}, b"missing"
            if parsed.path == "/api/challs":
                return 200, {}, {
                    "challs": [
                        {
                            "id": "x",
                            "name": "X",
                            "category": "crypto",
                            "detail_url": "/api/challs/x",
                        }
                    ]
                }
            if parsed.path == "/api/challs/x":
                return 200, {}, {
                    "data": {
                        "id": "x",
                        "name": "X",
                        "category": "crypto",
                        "files": [
                            {
                                "name": "../../NUL",
                                "URL": "https://cdn.example/file.bin?token=signed",
                            }
                        ],
                    }
                }
            if request["url"].startswith("https://cdn.example/file.bin"):
                return 200, {}, payload
            return 404, {}, b"missing"

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(
                tmp,
                platform="rctf",
                unauthenticated_attachment_origins=["https://cdn.example"],
            )
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)

            self.assertEqual(manifest["status"], "complete")
            foreign = [
                item for item in fake.requests
                if urlsplit(item["url"]).hostname == "cdn.example"
            ]
            self.assertEqual(len(foreign), 1)
            self.assertNotIn("authorization", foreign[0]["headers"])
            same_origin = [
                item for item in fake.requests
                if urlsplit(item["url"]).hostname == "base.example"
            ]
            self.assertTrue(
                all(
                    item["headers"].get("authorization") == "Bearer rctf-secret"
                    for item in same_origin
                )
            )
            stored = (
                Path(tmp)
                / "out"
                / "fake-rctf"
                / "crypto"
                / "x-X"
                / "files"
                / "_NUL"
            )
            self.assertEqual(stored.read_bytes(), payload)
            self.assertNotIn(
                "signed",
                (Path(tmp) / "out" / "fake-rctf" / "manifest.json").read_text(),
            )

    def test_redirect_to_unapproved_origin_is_rejected_before_request(self):
        def responder(request):
            path = urlsplit(request["url"]).path
            if path == "/api/v1/challenges":
                return 200, {}, {
                    "data": [{"id": 1, "name": "Redirect", "category": "web"}],
                    "meta": {
                        "pagination": {
                            "page": 1,
                            "pages": 1,
                            "next": None,
                        }
                    },
                }
            if path == "/api/v1/challenges/1":
                return 200, {}, {
                    "data": {
                        "id": 1,
                        "name": "Redirect",
                        "category": "web",
                        "files": ["/redirect"],
                    }
                }
            if path == "/redirect":
                return 302, {"Location": "https://evil.example/leak"}, b""
            if urlsplit(request["url"]).hostname == "evil.example":
                self.fail("unapproved redirect destination was requested")
            return 404, {}, b"missing"

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)

            self.assertEqual(manifest["status"], "partial")
            self.assertEqual(
                manifest["failures"][0]["error"]["code"],
                "foreign_origin",
            )
            self.assertFalse(
                any(
                    urlsplit(item["url"]).hostname == "evil.example"
                    for item in fake.requests
                )
            )

    def test_retry_and_file_total_limits(self):
        list_attempts = 0
        bodies = {
            "/f/large": b"123456",
            "/f/one": b"1234",
            "/f/two": b"5678",
        }

        def responder(request):
            nonlocal list_attempts
            path = urlsplit(request["url"]).path
            if path == "/api/v1/challenges":
                list_attempts += 1
                if list_attempts == 1:
                    return 503, {"Retry-After": "0"}, b"retry"
                return 200, {}, {
                    "data": [{"id": 1, "name": "Limits", "category": "misc"}],
                    "meta": {
                        "pagination": {
                            "page": 1,
                            "pages": 1,
                            "next": None,
                        }
                    },
                }
            if path == "/api/v1/challenges/1":
                return 200, {}, {
                    "data": {
                        "id": 1,
                        "name": "Limits",
                        "category": "misc",
                        "files": list(bodies),
                    }
                }
            if path in bodies:
                return 200, {"Content-Length": len(bodies[path])}, bodies[path]
            return 404, {}, b"missing"

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            config["limits"].update({"max_file_bytes": 5, "max_total_bytes": 6})
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)

            self.assertEqual(list_attempts, 2)
            self.assertEqual(
                [failure["error"]["code"] for failure in manifest["failures"]],
                ["file_too_large", "total_too_large"],
            )
            self.assertEqual(
                [item["status"] for item in manifest["challenges"][0]["files"]],
                ["failed", "downloaded", "failed"],
            )
            self.assertFalse(list((Path(tmp) / "out").rglob("*.part")))


if __name__ == "__main__":
    unittest.main()
