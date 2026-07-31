"""Gate cycle 10 regressions added before their fixes."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from ctf_collector.archive import media_signature_matches, render_challenge_html
from ctf_collector.collector import collect_all, collect_ctf
import ctf_collector.safety as safety
from ctf_collector.safety import SafeOutput, safe_metadata

from .support import FakeOpener, make_config


FIXED_MARKER = "[REDACTED]"
CONFLICTING_MARKER = "[WITHHELD]"
VALID_PNG_ONE = b"\x89PNG\r\n\x1a\nfirst image"
VALID_PNG_TWO = b"\x89PNG\r\n\x1a\nsecond image"


class ConflictSafeRedactionTests(unittest.TestCase):
    def test_marker_is_fixed_for_ordinary_secrets_and_conflict_safe_for_variants(self):
        self.assertEqual(
            safe_metadata({"password": "ordinary"}, secrets=("ordinary-secret",))[
                "password"
            ],
            FIXED_MARKER,
        )

        secrets = (FIXED_MARKER, "REDACTED", CONFLICTING_MARKER)
        metadata = safe_metadata(
            {
                "password": "sensitive-by-key",
                FIXED_MARKER: f"one {FIXED_MARKER}",
                "description": (
                    f"{FIXED_MARKER} / {CONFLICTING_MARKER} / "
                    "［ＲＥＤＡＣＴＥＤ］"
                ),
            },
            secrets=secrets,
        )
        persisted = json.dumps(metadata, ensure_ascii=False)

        for secret in secrets:
            with self.subTest(secret=secret):
                self.assertNotIn(secret, persisted)

    def test_all_configured_marker_secrets_are_absent_end_to_end(self):
        def responder(request):
            parsed = urlsplit(request["url"])
            if parsed.hostname == "marker-one.example":
                if parsed.path == "/api/v1/challenges":
                    return 200, {}, {
                        "data": [
                            {
                                "id": 1,
                                "name": f"{FIXED_MARKER} {CONFLICTING_MARKER}",
                                "category": "web",
                            }
                        ],
                        "meta": {
                            "pagination": {"next": None, "page": 1, "pages": 1}
                        },
                    }
                if parsed.path == "/api/v1/challenges/1":
                    return 200, {}, {
                        "data": {
                            "id": 1,
                            "name": f"{FIXED_MARKER} {CONFLICTING_MARKER}",
                            "category": "web",
                            "description": (
                                f"body {FIXED_MARKER} {CONFLICTING_MARKER}"
                            ),
                            "password": "classified",
                            FIXED_MARKER: CONFLICTING_MARKER,
                            "files": [],
                        }
                    }
                if parsed.path == "/rules":
                    return (
                        200,
                        {"Content-Type": "text/plain"},
                        f"rules {FIXED_MARKER} {CONFLICTING_MARKER}".encode(),
                    )
            if parsed.hostname == "marker-two.example":
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
            root = Path(tmp)
            first_token = root / "first.token"
            second_token = root / "second.token"
            first_token.write_text(FIXED_MARKER + "\n", encoding="ascii")
            second_token.write_text(CONFLICTING_MARKER + "\n", encoding="ascii")
            first = make_config(
                tmp,
                name="marker-one",
                base_url="https://marker-one.example",
                token_file=first_token,
            )
            second = make_config(
                tmp,
                name="marker-two",
                base_url="https://marker-two.example",
                token_file=second_token,
            )
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                results = collect_all([first, second])

            output_root = root / "out"
            paths = [path.relative_to(output_root).as_posix() for path in output_root.rglob("*")]
            documents = [
                path.read_bytes()
                for path in output_root.rglob("*")
                if path.is_file()
            ]
            first_manifest = json.loads(
                (output_root / "marker-one" / "manifest.json").read_text(
                    encoding="utf-8"
                )
            )

        self.assertEqual([result["error"] for result in results], [None, None])
        self.assertEqual(first_manifest["status"], "complete")
        for secret in (FIXED_MARKER, CONFLICTING_MARKER):
            encoded = secret.encode("ascii")
            with self.subTest(secret=secret):
                self.assertTrue(all(secret not in path for path in paths))
                self.assertTrue(all(encoded not in document for document in documents))


class InvalidUnicodeScalarTests(unittest.TestCase):
    def test_metadata_render_and_write_normalize_isolated_surrogates(self):
        metadata = safe_metadata(
            {
                "bad\ud800key": "lead\udcfftail",
                "nested": {"description": "body\ud800text"},
            }
        )
        encoded_metadata = json.dumps(metadata, ensure_ascii=False).encode("utf-8")
        rendered = render_challenge_html(
            {
                "id": "id\ud800",
                "name": "name\udcff",
                "category": "cat\ud800",
                "description": metadata,
            },
            [],
            [],
        )
        encoded_html = rendered.encode("utf-8")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            with SafeOutput(root) as output:
                output.atomic_json(("scalar.json",), {"value": "x\ud800y"})
            written = (root / "scalar.json").read_bytes()
            decoded = written.decode("utf-8")

        self.assertIn("\ufffd", encoded_metadata.decode("utf-8"))
        self.assertIn("\ufffd", encoded_html.decode("utf-8"))
        self.assertIn("\ufffd", decoded)

    def test_surrogate_challenge_does_not_block_later_challenge_or_ctf(self):
        replacement_path = "/api/v1/challenges/%EF%BF%BD"

        def responder(request):
            parsed = urlsplit(request["url"])
            if parsed.hostname == "surrogate.example":
                if parsed.path == "/api/v1/challenges":
                    return 200, {}, {
                        "data": [
                            {
                                "id": "\ud800",
                                "name": "Hostile\udcff",
                                "category": "misc\ud800",
                            },
                            {"id": 2, "name": "Safe later", "category": "web"},
                        ],
                        "meta": {
                            "pagination": {"next": None, "page": 1, "pages": 1}
                        },
                    }
                if parsed.path == replacement_path:
                    return 200, {}, {
                        "data": {
                            "id": "\ud800",
                            "name": "Hostile\udcff",
                            "category": "misc\ud800",
                            "bad\ud800key": "bad\udcffvalue",
                            "description": (
                                "safe lead\ud800 https://base.example/path"
                                "?credential=ctfd-secret"
                            ),
                            "files": [],
                        }
                    }
                if parsed.path == "/api/v1/challenges/2":
                    return 200, {}, {
                        "data": {
                            "id": 2,
                            "name": "Safe later",
                            "category": "web",
                            "description": "safe later body",
                            "files": [],
                        }
                    }
                if parsed.path == "/rules":
                    return 404, {}, b"missing"
            if parsed.hostname == "after.example":
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
                name="surrogate",
                base_url="https://surrogate.example",
            )
            later = make_config(
                tmp,
                name="after",
                base_url="https://after.example",
            )
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                results = collect_all([hostile, later])

            output_root = Path(tmp) / "out"
            hostile_manifest = json.loads(
                (output_root / "surrogate" / "manifest.json").read_text(
                    encoding="utf-8"
                )
            )
            later_manifest = json.loads(
                (output_root / "after" / "manifest.json").read_text(
                    encoding="utf-8"
                )
            )
            documents = [
                path.read_bytes()
                for path in output_root.rglob("*")
                if path.is_file()
            ]

        self.assertEqual([result["error"] for result in results], [None, None])
        self.assertEqual(
            [item["id"] for item in hostile_manifest["challenges"]],
            ["\ufffd", "2"],
        )
        self.assertEqual(later_manifest["status"], "complete")
        for document in documents:
            document.decode("utf-8")
            self.assertNotIn(b"ctfd-secret", document)
            self.assertNotIn(b"UnicodeEncodeError", document)


class CtfdInvalidSummaryTests(unittest.TestCase):
    def test_each_invalid_summary_is_a_failure_and_later_pages_continue(self):
        invalid = [
            "scalar",
            5,
            None,
            ["nested"],
            {"name": "missing"},
            {"id": {"nested": 1}},
            {"id": [1]},
            {"id": True},
            {"id": None},
        ]

        def responder(request):
            parsed = urlsplit(request["url"])
            if parsed.path == "/api/v1/challenges":
                page = int(parse_qs(parsed.query)["page"][0])
                if page == 1:
                    return 200, {}, {
                        "data": [*invalid, {"id": 7, "name": "Seven", "category": "web"}],
                        "meta": {
                            "pagination": {"next": 2, "page": 1, "pages": 2}
                        },
                    }
                if page == 2:
                    return 200, {}, {
                        "data": [
                            {"id": 7, "name": "Duplicate", "category": "other"},
                            {"id": 8, "name": "Eight", "category": "pwn"},
                        ],
                        "meta": {
                            "pagination": {"next": None, "page": 2, "pages": 2}
                        },
                    }
            if parsed.path == "/api/v1/challenges/7":
                return 200, {}, {
                    "data": {
                        "id": 700,
                        "_id": 701,
                        "name": "Detailed Seven",
                        "category": "web",
                        "description": "seven",
                        "files": [],
                    }
                }
            if parsed.path == "/api/v1/challenges/8":
                return 200, {}, {
                    "data": {
                        "id": 8,
                        "name": "Eight",
                        "category": "pwn",
                        "description": "eight",
                        "files": [],
                    }
                }
            if parsed.path == "/rules":
                return 404, {}, b"missing"
            self.fail(f"unexpected request: {request['url']}")

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)

            persisted = json.loads(
                (Path(tmp) / "out" / "fake-ctfd" / "manifest.json").read_text(
                    encoding="utf-8"
                )
            )

        invalid_failures = [
            failure
            for failure in manifest["failures"]
            if failure["error"]["code"] == "invalid_api_data"
        ]
        summary_failures = [
            failure
            for failure in invalid_failures
            if failure["error"]["message"].startswith("challenge summary")
        ]
        self.assertEqual(manifest, persisted)
        self.assertEqual(manifest["status"], "partial")
        self.assertEqual([item["id"] for item in manifest["challenges"]], ["8", "7"])
        self.assertEqual(len(summary_failures), len(invalid))
        self.assertEqual(len(invalid_failures), len(invalid) + 1)
        self.assertTrue(all("challenge_id" not in item for item in summary_failures))
        list_pages = [
            parse_qs(urlsplit(item["url"]).query)["page"][0]
            for item in fake.requests
            if urlsplit(item["url"]).path == "/api/v1/challenges"
        ]
        self.assertEqual(list_pages, ["1", "2"])


class LinearNameAllocationTests(unittest.TestCase):
    def test_same_name_probe_growth_is_linear_and_names_are_deterministic(self):
        allocator_type = getattr(safety, "UniqueNameAllocator", None)
        self.assertIsNotNone(allocator_type)

        traces = []
        last_names = []
        for size in (100, 200, 400):
            allocator = allocator_type()
            names = [
                safety.safe_unique_component(
                    ("out", "files"),
                    "same.bin",
                    allocator,
                    siblings=(".part",),
                )
                for _ in range(size)
            ]
            traces.append(allocator.probe_count)
            last_names.append(names[-1])
            self.assertEqual(len(set(name.casefold() for name in names)), size)

        self.assertEqual(last_names, ["same__100.bin", "same__200.bin", "same__400.bin"])
        self.assertEqual(traces, [100, 200, 400])


class TemporarySiblingCollisionTests(unittest.TestCase):
    def test_attachment_and_media_part_names_survive_and_rerun_converges(self):
        downloads = {
            "/attachments/first": b"first attachment",
            "/attachments/second": b"second attachment",
            "/media/X.part": VALID_PNG_ONE,
            "/media/X": VALID_PNG_TWO,
        }
        download_counts = {path: 0 for path in downloads}

        def responder(request):
            path = urlsplit(request["url"]).path
            if path == "/api/v1/challenges":
                return 200, {}, {
                    "data": [{"id": 10, "name": "Parts", "category": "web"}],
                    "meta": {
                        "pagination": {"next": None, "page": 1, "pages": 1}
                    },
                }
            if path == "/api/v1/challenges/10":
                return 200, {}, {
                    "data": {
                        "id": 10,
                        "name": "Parts",
                        "category": "web",
                        "description": (
                            '<img src="/media/X.part"><img src="/media/X">'
                        ),
                        "files": [
                            {"name": "X.part", "url": "/attachments/first"},
                            {"name": "X", "url": "/attachments/second"},
                        ],
                    }
                }
            if path == "/rules":
                return 404, {}, b"missing"
            if path in downloads:
                download_counts[path] += 1
                content_type = "image/png" if path.startswith("/media/") else "application/octet-stream"
                return 200, {"Content-Type": content_type}, downloads[path]
            self.fail(f"unexpected request: {request['url']}")

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                first = collect_ctf(config)
                challenge_root = next(
                    (Path(tmp) / "out" / "fake-ctfd" / "web").iterdir()
                )
                first_files = {
                    path.name: path.read_bytes()
                    for path in (challenge_root / "files").iterdir()
                }
                first_media = {
                    path.name: path.read_bytes()
                    for path in (challenge_root / "media").iterdir()
                }
                second = collect_ctf(config)

            page = (challenge_root / "challenge.html").read_text(encoding="utf-8")
            leftovers = [path.name for path in challenge_root.rglob("*.part.part")]

        expected_files = {"X.part": downloads["/attachments/first"], "X__2": downloads["/attachments/second"]}
        expected_media = {"X.part": VALID_PNG_ONE, "X__2": VALID_PNG_TWO}
        self.assertEqual(first_files, expected_files)
        self.assertEqual(first_media, expected_media)
        self.assertTrue(
            all(
                media_signature_matches(
                    "image/png",
                    payload,
                    total_size=len(payload),
                )
                for payload in first_media.values()
            )
        )
        self.assertEqual(download_counts, {path: 1 for path in downloads})
        self.assertEqual(leftovers, [])
        self.assertEqual(first["status"], "complete")
        self.assertEqual(second["status"], "complete")
        for collection, expected in (("files", expected_files), ("media", expected_media)):
            first_entries = first["challenges"][0][collection]
            second_entries = second["challenges"][0][collection]
            self.assertEqual(
                [item["local_path"] for item in first_entries],
                [item["local_path"] for item in second_entries],
            )
            self.assertEqual([item["status"] for item in second_entries], ["verified", "verified"])
            for entries in (first_entries, second_entries):
                for entry in entries:
                    name = Path(entry["local_path"]).name
                    payload = expected[name]
                    self.assertEqual(entry["size"], len(payload))
                    self.assertEqual(
                        entry["sha256"],
                        hashlib.sha256(payload).hexdigest(),
                    )
        for reference in (
            'href="files/X.part"',
            'href="files/X__2"',
            'src="media/X.part"',
            'src="media/X__2"',
        ):
            self.assertIn(reference, page)


if __name__ == "__main__":
    unittest.main()
