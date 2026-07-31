"""Gate cycle 6 regressions added before their fixes."""

import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from ctf_collector.collector import collect_ctf
from ctf_collector.safety import safe_metadata

from .support import FakeOpener, make_config


class CanonicalUserinfoTests(unittest.TestCase):
    def test_metadata_canonicalizes_entity_urls_and_whitespace_before_redaction(self):
        metadata = safe_metadata(
            {
                "source_url": (
                    " //bob:other-password@example.test/private "
                ),
                "description": (
                    "Fetch &sol;&sol;alice:plain-password@example.test/path now; "
                    "also fetch &#47;&#x2f;carol:third-password@example.test/other. "
                    "Ordinary prose, issue#42, and flag{keep?#=payload} remain."
                ),
            }
        )

        self.assertEqual(metadata["source_url"], "//example.test/private")
        self.assertEqual(
            metadata["description"],
            "Fetch //example.test/path now; "
            "also fetch //example.test/other. "
            "Ordinary prose, issue#42, and flag{keep?#=payload} remain.",
        )
        persisted = repr(metadata)
        for credential in ("bob", "other-password", "alice", "plain-password", "carol", "third-password"):
            with self.subTest(credential=credential):
                self.assertNotIn(credential, persisted)


class CtfdDetailIdentityTests(unittest.TestCase):
    def test_summary_identity_survives_bad_detail_ids_and_collection_continues(self):
        summaries = [
            {"category": "misc", "id": 1, "name": "Missing summary"},
            {"category": "web", "id": 2, "name": "Invalid summary"},
            {"category": "crypto", "id": 3, "name": "Mismatch summary"},
            {"category": "pwn", "id": 4, "name": "Later summary"},
        ]

        details = {
            "/api/v1/challenges/1": {
                "category": "misc",
                "description": "missing detail fields retained",
                "files": [],
                "name": "Missing detail",
            },
            "/api/v1/challenges/2": {
                "category": "web",
                "description": "invalid detail fields retained",
                "files": [],
                "id": [],
                "name": "Invalid detail",
            },
            "/api/v1/challenges/3": {
                "category": "crypto",
                "description": "mismatched detail fields retained",
                "files": [],
                "id": 4,
                "name": "Mismatch detail",
            },
            "/api/v1/challenges/4": {
                "category": "pwn",
                "description": "later detail retained",
                "files": [],
                "id": 4,
                "name": "Later detail",
            },
        }

        def responder(request):
            path = urlsplit(request["url"]).path
            if path == "/api/v1/challenges":
                return 200, {}, {
                    "data": summaries,
                    "meta": {
                        "pagination": {
                            "next": None,
                            "page": 1,
                            "pages": 1,
                        }
                    },
                }
            if path in details:
                return 200, {}, {"data": details[path]}
            if path == "/rules":
                return 404, {}, b"missing"
            self.fail(f"unexpected CTFd route: {request['url']}")

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)

        self.assertEqual(manifest["status"], "partial")
        self.assertEqual(
            [(item["id"], item["name"]) for item in manifest["challenges"]],
            [
                ("3", "Mismatch detail"),
                ("1", "Missing detail"),
                ("4", "Later detail"),
                ("2", "Invalid detail"),
            ],
        )
        self.assertEqual(
            [failure["error"]["code"] for failure in manifest["failures"]],
            ["invalid_api_data", "invalid_api_data", "invalid_api_data"],
        )
        self.assertEqual(
            [failure["challenge_id"] for failure in manifest["failures"]],
            ["1", "2", "3"],
        )


if __name__ == "__main__":
    unittest.main()
