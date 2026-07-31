import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from ctf_collector.collector import collect_all, collect_ctf
from ctf_collector.errors import CollectorError
from ctf_collector.safety import SafeOutput

from .support import FakeOpener, make_config


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


class ExactPaginationTests(unittest.TestCase):
    def test_meta_next_cannot_skip_a_page(self):
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
                            "next": 3 if page == 1 else None,
                            "page": page,
                            "pages": 3,
                        }
                    },
                }
            if parsed.path.startswith("/api/v1/challenges/"):
                challenge_id = parsed.path.rsplit("/", 1)[-1]
                return 200, {}, {
                    "data": {
                        "category": "web",
                        "files": [],
                        "id": challenge_id,
                        "name": f"Page {challenge_id}",
                    }
                }
            return 404, {}, b"missing"

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)

        list_pages = [
            int(parse_qs(urlsplit(item["url"]).query)["page"][0])
            for item in fake.requests
            if urlsplit(item["url"]).path == "/api/v1/challenges"
        ]
        self.assertEqual(list_pages, [1])
        self.assertEqual(manifest["status"], "partial")
        self.assertIn(
            "pagination_inconsistent",
            [failure["error"]["code"] for failure in manifest["failures"]],
        )


class KeyedSourceIdentityTests(unittest.TestCase):
    def test_query_only_change_redownloads_but_identical_source_reuses(self):
        signature = "first-secret-query"
        downloads = []

        def responder(request):
            parsed = urlsplit(request["url"])
            if parsed.path == "/api/v1/challenges":
                return 200, {}, terminal_page(
                    [{"id": 1, "name": "One", "category": "web"}]
                )
            if parsed.path == "/api/v1/challenges/1":
                return 200, {}, {
                    "data": {
                        "category": "web",
                        "files": [
                            {
                                "name": "payload.bin",
                                "url": f"/files/payload.bin?signature={signature}",
                            }
                        ],
                        "id": 1,
                        "name": "One",
                    }
                }
            if parsed.path == "/files/payload.bin":
                requested_signature = parse_qs(parsed.query)["signature"][0]
                downloads.append(requested_signature)
                return 200, {}, requested_signature.encode("ascii")
            return 404, {}, b"missing"

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                first = collect_ctf(config)
                unchanged = collect_ctf(config)
                signature = "second-secret-query"
                changed = collect_ctf(config)

            manifest_text = (
                Path(tmp) / "out" / "fake-ctfd" / "manifest.json"
            ).read_text(encoding="utf-8")
            stored = (
                Path(tmp)
                / "out"
                / "fake-ctfd"
                / "web"
                / "1-One"
                / "files"
                / "payload.bin"
            )
            stored_bytes = stored.read_bytes()

        first_entry = first["challenges"][0]["files"][0]
        unchanged_entry = unchanged["challenges"][0]["files"][0]
        changed_entry = changed["challenges"][0]["files"][0]
        self.assertEqual(first_entry["status"], "downloaded")
        self.assertEqual(unchanged_entry["status"], "verified")
        self.assertEqual(changed_entry["status"], "downloaded")
        self.assertEqual(
            downloads,
            ["first-secret-query", "second-secret-query"],
        )
        self.assertRegex(changed_entry["source_identity"], r"\A[0-9a-f]{64}\Z")
        self.assertNotEqual(
            first_entry["source_identity"],
            changed_entry["source_identity"],
        )
        self.assertEqual(changed_entry["source_url"], "https://base.example/files/payload.bin")
        self.assertNotIn("first-secret-query", manifest_text)
        self.assertNotIn("second-secret-query", manifest_text)
        self.assertNotIn("ctfd-secret", manifest_text)
        self.assertEqual(stored_bytes, b"second-secret-query")

    def test_manifest_without_source_identity_forces_redownload(self):
        downloads = 0

        def responder(request):
            nonlocal downloads
            path = urlsplit(request["url"]).path
            if path == "/api/v1/challenges":
                return 200, {}, terminal_page(
                    [{"id": 1, "name": "One", "category": "web"}]
                )
            if path == "/api/v1/challenges/1":
                return 200, {}, {
                    "data": {
                        "category": "web",
                        "files": ["/files/legacy.bin?signature=private"],
                        "id": 1,
                        "name": "One",
                    }
                }
            if path == "/files/legacy.bin":
                downloads += 1
                return 200, {}, b"legacy"
            return 404, {}, b"missing"

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            manifest_path = Path(tmp) / "out" / "fake-ctfd" / "manifest.json"
            with patch("ctf_collector.http.build_opener", return_value=fake):
                collect_ctf(config)
                old_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                old_manifest["challenges"][0]["files"][0].pop(
                    "source_identity",
                    None,
                )
                manifest_path.write_text(
                    json.dumps(old_manifest),
                    encoding="utf-8",
                )
                second = collect_ctf(config)

        self.assertEqual(downloads, 2)
        self.assertEqual(
            second["challenges"][0]["files"][0]["status"],
            "downloaded",
        )


class CtfDirectoryPreflightTests(unittest.TestCase):
    def test_token_name_refusal_is_per_ctf_and_safe_later_name_is_collected(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = make_config(tmp)
            first["name"] = "event-ctfd-secret"
            second = make_config(tmp)
            second["name"] = "event-[REDACTED]"
            fake = FakeOpener(
                lambda request: (200, {}, terminal_page([]))
            )

            with patch("ctf_collector.http.build_opener", return_value=fake):
                results = collect_all([first, second])

            self.assertEqual(results[0]["error"].code, "invalid_config")
            self.assertIsNone(results[1]["error"])
            self.assertTrue(fake.requests)
            self.assertFalse((Path(tmp) / "out" / "event-ctfd-secret").exists())
            self.assertTrue(
                (Path(tmp) / "out" / "event-_REDACTED" / "manifest.json").is_file()
            )

    def test_later_unsafe_ctf_name_does_not_erase_earlier_collection(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = make_config(tmp)
            first["name"] = "safe-first"
            second = make_config(tmp)
            second["name"] = "unsafe-ctfd-secret"
            fake = FakeOpener(
                lambda request: (200, {}, terminal_page([]))
            )

            with patch("ctf_collector.http.build_opener", return_value=fake):
                results = collect_all([first, second])

            self.assertIsNone(results[0]["error"])
            self.assertEqual(results[1]["error"].code, "invalid_config")
            self.assertTrue(fake.requests)
            self.assertTrue(
                (Path(tmp) / "out" / "safe-first" / "manifest.json").is_file()
            )
            self.assertFalse((Path(tmp) / "out" / "unsafe-ctfd-secret").exists())


class PostCommitDirectoryValidationTests(unittest.TestCase):
    def test_download_commit_swap_is_cleaned_from_moved_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            files_path = (
                Path(tmp) / "out" / "fake-ctfd" / "web" / "1-One" / "files"
            )
            outside_path = Path(tmp) / "outside-files"

            def responder(request):
                path = urlsplit(request["url"]).path
                if path == "/api/v1/challenges":
                    return 200, {}, terminal_page(
                        [{"id": 1, "name": "One", "category": "web"}]
                    )
                if path == "/api/v1/challenges/1":
                    return 200, {}, {
                        "data": {
                            "category": "web",
                            "files": ["/files/commit.bin"],
                            "id": 1,
                            "name": "One",
                        }
                    }
                if path == "/files/commit.bin":
                    return 200, {}, b"must-be-cleaned"
                return 404, {}, b"missing"

            real_replace = os.replace
            swapped = False

            def swap_then_replace(
                source,
                target,
                *,
                src_dir_fd=None,
                dst_dir_fd=None,
            ):
                nonlocal swapped
                if target == "commit.bin" and not swapped:
                    swapped = True
                    files_path.rename(outside_path)
                    files_path.symlink_to(outside_path, target_is_directory=True)
                return real_replace(
                    source,
                    target,
                    src_dir_fd=src_dir_fd,
                    dst_dir_fd=dst_dir_fd,
                )

            fake = FakeOpener(responder)
            with (
                patch("ctf_collector.http.build_opener", return_value=fake),
                patch(
                    "ctf_collector.safety.os.replace",
                    side_effect=swap_then_replace,
                ),
            ):
                manifest = collect_ctf(config)

            self.assertTrue(swapped)
            self.assertEqual(manifest["status"], "partial")
            self.assertIn(
                "unsafe_path",
                [failure["error"]["code"] for failure in manifest["failures"]],
            )
            self.assertFalse((outside_path / "commit.bin").exists())
            self.assertFalse((outside_path / "commit.bin.part").exists())

    def test_atomic_json_commit_swap_cleans_challenge_and_manifest_targets(self):
        cases = (
            (("ctf", "web", "1-One"), "challenge.json"),
            (("ctf",), "manifest.json"),
        )
        for parent_parts, target_name in cases:
            with self.subTest(target_name=target_name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "out"
                parent_path = root.joinpath(*parent_parts)
                outside_path = Path(tmp) / f"outside-{target_name}"
                real_replace = os.replace
                swapped = False

                def swap_then_replace(
                    source,
                    target,
                    *,
                    src_dir_fd=None,
                    dst_dir_fd=None,
                ):
                    nonlocal swapped
                    if target == target_name and not swapped:
                        swapped = True
                        parent_path.rename(outside_path)
                        parent_path.symlink_to(
                            outside_path,
                            target_is_directory=True,
                        )
                    return real_replace(
                        source,
                        target,
                        src_dir_fd=src_dir_fd,
                        dst_dir_fd=dst_dir_fd,
                    )

                with SafeOutput(root) as output:
                    output.ensure_directory(parent_parts)
                    with (
                        patch(
                            "ctf_collector.safety.os.replace",
                            side_effect=swap_then_replace,
                        ),
                        self.assertRaises(CollectorError) as caught,
                    ):
                        output.atomic_json(
                            (*parent_parts, target_name),
                            {"safe": True},
                        )

                self.assertTrue(swapped)
                self.assertEqual(caught.exception.code, "unsafe_path")
                self.assertFalse((outside_path / target_name).exists())
                self.assertFalse(
                    (outside_path / f".{target_name}.part").exists()
                )


if __name__ == "__main__":
    unittest.main()
