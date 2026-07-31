"""Gate cycle 11 regressions added before their fixes."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from ctf_collector.collector import collect_all, collect_ctf

from .support import FakeOpener, make_config


VALID_PNG = b"\x89PNG\r\n\x1a\ncycle eleven"
FIXED_CTF_FILES = {"manifest.json", "rules.html"}


def _documents(root):
    return [path for path in root.rglob("*") if path.is_file()]


def _tree_snapshot(root):
    return {
        path.relative_to(root).as_posix(): (
            "directory" if path.is_dir() else path.read_bytes()
        )
        for path in root.rglob("*")
    }


class GeneratedMarkerRedactionTests(unittest.TestCase):
    def test_malformed_summary_id_cannot_regenerate_either_token_spelling(self):
        for token in ("[REDACTED]", "REDACTED"):
            with self.subTest(token=token), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                token_file = root / "marker.token"
                token_file.write_text(token + "\n", encoding="ascii")
                config = make_config(
                    tmp,
                    name="marker",
                    base_url="https://marker.example",
                    token_file=token_file,
                )

                def responder(request):
                    path = urlsplit(request["url"]).path
                    if path == "/api/v1/challenges":
                        return 200, {}, {
                            "data": [
                                {
                                    "id": "http://[/x",
                                    "name": "Malformed marker",
                                    "category": "web",
                                }
                            ],
                            "meta": {
                                "pagination": {
                                    "next": None,
                                    "page": 1,
                                    "pages": 1,
                                }
                            },
                        }
                    if path == "/api/v1/challenges/http%3A%2F%2F%5B%2Fx":
                        return 200, {}, {
                            "data": {
                                "id": "http://[/x",
                                "name": "Malformed marker",
                                "category": "web",
                                "description": "ordinary body",
                                "files": [],
                            }
                        }
                    if path == "/rules":
                        return 200, {"Content-Type": "text/plain"}, b"ordinary rules"
                    self.fail(f"unexpected request: {request['url']}")

                fake = FakeOpener(responder)
                with patch("ctf_collector.http.build_opener", return_value=fake):
                    results = collect_all([config])

                output_root = root / "out"
                event_root = output_root / "marker"
                manifest = json.loads(
                    (event_root / "manifest.json").read_text(encoding="utf-8")
                )
                paths = [path.relative_to(output_root).as_posix() for path in output_root.rglob("*")]
                documents = _documents(output_root)

                self.assertEqual([result["error"] for result in results], [None])
                self.assertEqual(manifest["status"], "complete")
                self.assertEqual(len(manifest["challenges"]), 1)
                self.assertTrue(documents)
                self.assertTrue(all(token not in path for path in paths))
                self.assertTrue(
                    all(token.encode("ascii") not in path.read_bytes() for path in documents)
                )


class UrlUnicodeScalarIngressTests(unittest.TestCase):
    def test_all_url_ingress_is_scalar_safe_and_collection_continues(self):
        def responder(request):
            parsed = urlsplit(request["url"])
            if parsed.hostname == "hostile.example":
                if parsed.path == "/api/v1/challs":
                    return 404, {}, b"missing"
                if parsed.path == "/api/v1/challenges":
                    return 200, {}, {
                        "data": [
                            {
                                "id": 1,
                                "name": "Scalar URLs",
                                "category": "web",
                                "detail_url": "/api/details/\ud800?credential=detail",
                            },
                            {
                                "id": 2,
                                "name": "Later challenge",
                                "category": "pwn",
                                "description": "later challenge body",
                                "files": [],
                            },
                        ]
                    }
                if parsed.path == "/api/details/%EF%BF%BD":
                    return 200, {}, {
                        "data": {
                            "id": 1,
                            "name": "Scalar URLs",
                            "category": "web",
                            "description": (
                                '<img src="/media/\udcff.png?credential=media">'
                            ),
                            "files": [
                                {
                                    "name": "scalar.bin",
                                    "url": "/attachments/\ud800.bin?credential=file",
                                }
                            ],
                        }
                    }
                if parsed.path == "/attachments/%EF%BF%BD.bin":
                    return 200, {"Content-Type": "application/octet-stream"}, b"attachment"
                if parsed.path == "/media/%EF%BF%BD.png":
                    return 200, {"Content-Type": "image/png"}, VALID_PNG
                if parsed.path in {
                    "/rules",
                    "/api/v1/integrations/client/config",
                }:
                    return 404, {}, b"missing"
            if parsed.hostname == "later.example":
                if parsed.path == "/api/v1/challenges":
                    return 200, {}, {
                        "data": [],
                        "meta": {
                            "pagination": {"next": None, "page": 1, "pages": 0}
                        },
                    }
                if parsed.path == "/rules":
                    return 404, {}, b"missing"
            self.fail(f"unexpected request: {request['url']}")

        with tempfile.TemporaryDirectory() as tmp:
            hostile = make_config(
                tmp,
                platform="rctf",
                name="hostile",
                base_url="https://hostile.example",
            )
            later = make_config(
                tmp,
                name="later",
                base_url="https://later.example",
            )
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                results = collect_all([hostile, later])

            output_root = Path(tmp) / "out"
            hostile_manifest = json.loads(
                (output_root / "hostile" / "manifest.json").read_text(
                    encoding="utf-8"
                )
            )
            later_manifest = json.loads(
                (output_root / "later" / "manifest.json").read_text(
                    encoding="utf-8"
                )
            )
            documents = [
                path.read_bytes()
                for path in _documents(output_root)
                if path.suffix in {".html", ".json"}
            ]

        requested_paths = [urlsplit(item["url"]).path for item in fake.requests]
        self.assertEqual([result["error"] for result in results], [None, None])
        self.assertEqual(hostile_manifest["status"], "complete")
        self.assertEqual(later_manifest["status"], "complete")
        self.assertEqual(
            {challenge["id"] for challenge in hostile_manifest["challenges"]},
            {"1", "2"},
        )
        self.assertIn("/api/details/%EF%BF%BD", requested_paths)
        self.assertIn("/attachments/%EF%BF%BD.bin", requested_paths)
        self.assertIn("/media/%EF%BF%BD.png", requested_paths)
        downloaded = next(
            challenge
            for challenge in hostile_manifest["challenges"]
            if challenge["id"] == "1"
        )
        self.assertEqual(downloaded["files"][0]["status"], "downloaded")
        self.assertEqual(downloaded["media"][0]["status"], "downloaded")
        self.assertRegex(downloaded["files"][0]["source_identity"], r"^[0-9a-f]{64}$")
        self.assertRegex(downloaded["media"][0]["source_identity"], r"^[0-9a-f]{64}$")
        for document in documents:
            text = document.decode("utf-8")
            self.assertNotIn("UnicodeEncodeError", text)
            self.assertNotIn("UnicodeDecodeError", text)
            self.assertNotIn("rctf-secret", text)
            self.assertNotIn("ctfd-secret", text)
            self.assertNotIn("credential=detail", text)
            self.assertNotIn("credential=file", text)
            self.assertNotIn("credential=media", text)


class FixedCategoryCollisionTests(unittest.TestCase):
    def _responder(self, categories):
        def responder(request):
            path = urlsplit(request["url"]).path
            if path == "/api/v1/challenges":
                return 200, {}, {
                    "data": [
                        {"id": index, "name": f"Challenge {index}", "category": category}
                        for index, category in enumerate(categories, 1)
                    ],
                    "meta": {
                        "pagination": {"next": None, "page": 1, "pages": 1}
                    },
                }
            if path.startswith("/api/v1/challenges/"):
                challenge_id = int(path.rsplit("/", 1)[-1])
                category = categories[challenge_id - 1]
                return 200, {}, {
                    "data": {
                        "id": challenge_id,
                        "name": f"Challenge {challenge_id}",
                        "category": category,
                        "description": f"body {challenge_id}",
                        "files": [],
                    }
                }
            if path == "/rules":
                return 200, {"Content-Type": "text/plain"}, b"Cycle 11 rules retained."
            self.fail(f"unexpected request: {request['url']}")

        return responder

    def _assert_fixed_files_and_grouping(self, event_root, manifest):
        self.assertTrue((event_root / "manifest.json").is_file())
        self.assertTrue((event_root / "rules.html").is_file())
        self.assertIn(
            "Cycle 11 rules retained.",
            (event_root / "rules.html").read_text(encoding="utf-8"),
        )
        categories = [Path(item["directory"]).parts[0] for item in manifest["challenges"]]
        self.assertTrue(FIXED_CTF_FILES.isdisjoint(categories))
        manifest_categories = [
            Path(item["directory"]).parts[0]
            for item in manifest["challenges"]
            if item["category"] == "manifest.json"
        ]
        self.assertEqual(len(set(manifest_categories)), 1)

    def test_hostile_categories_are_safe_on_the_first_run_and_rerun_converges(self):
        categories = ["manifest.json", "manifest.json", "rules.html"]
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(self._responder(categories))
            with patch("ctf_collector.http.build_opener", return_value=fake):
                first = collect_ctf(config)
                event_root = Path(tmp) / "out" / "fake-ctfd"
                first_snapshot = _tree_snapshot(event_root)
                second = collect_ctf(config)
                second_snapshot = _tree_snapshot(event_root)

            self._assert_fixed_files_and_grouping(event_root, second)

        self.assertEqual(first["status"], "complete")
        self.assertEqual(first, second)
        self.assertEqual(first_snapshot, second_snapshot)

    def test_hostile_categories_are_safe_after_a_benign_manifest_exists(self):
        categories = ["web"]
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(self._responder(categories))
            with patch("ctf_collector.http.build_opener", return_value=fake):
                benign = collect_ctf(config)
                event_root = Path(tmp) / "out" / "fake-ctfd"
                self.assertTrue((event_root / "manifest.json").is_file())
                categories[:] = ["manifest.json", "manifest.json", "rules.html"]
                first_hostile = collect_ctf(config)
                first_snapshot = _tree_snapshot(event_root)
                second_hostile = collect_ctf(config)
                second_snapshot = _tree_snapshot(event_root)

            self._assert_fixed_files_and_grouping(event_root, second_hostile)

        self.assertEqual(benign["status"], "complete")
        self.assertEqual(first_hostile["status"], "complete")
        self.assertEqual(first_hostile, second_hostile)
        self.assertEqual(first_snapshot, second_snapshot)


if __name__ == "__main__":
    unittest.main()
