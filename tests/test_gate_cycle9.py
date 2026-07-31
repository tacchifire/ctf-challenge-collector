"""Gate cycle 9 regressions added before their fixes."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from ctf_collector.archive import render_challenge_html
from ctf_collector.collector import collect_all, collect_ctf
from ctf_collector.errors import CollectorError
from ctf_collector.safety import (
    MAX_METADATA_NESTING,
    redact_urls_in_text,
    safe_metadata,
)

from .support import FakeOpener, make_config


METADATA_DEPTH = 500
HOSTILE_BODY = "CYCLE9-HOSTILE-BODY-CREDENTIAL"
SAFE_URL = "http://example.test/path"
CREDENTIAL_URLS = (
    "http://alice:\tplain-password@example.test/path?token=Q#F",
    "http://ali&Tab;ce:plain-password@example.test/path?token=Q#F",
    "http://alice:plain&#10;-password@example.test/path?token=Q#F",
    "http://ali&#13;ce:plain-password@example.test/path?token=Q#F",
)


def nested_value(kind, depth=METADATA_DEPTH):
    value = HOSTILE_BODY
    for _ in range(depth):
        value = [value] if kind == "list" else {"nested": value}
    return value


def nested_json(kind, depth=METADATA_DEPTH):
    leaf = json.dumps(HOSTILE_BODY).encode("utf-8")
    if kind == "list":
        return (b"[" * depth) + leaf + (b"]" * depth)
    return (b'{"nested":' * depth) + leaf + (b"}" * depth)


def hostile_detail(challenge_id, kind):
    return (
        b'{"data":{"id":'
        + str(challenge_id).encode("ascii")
        + b',"name":"Hostile '
        + kind.encode("ascii")
        + b'","category":"misc","files":[],"description":'
        + nested_json(kind)
        + b"}}"
    )


class MetadataNestingTests(unittest.TestCase):
    def test_metadata_limit_is_safe_for_json_and_html_rendering(self):
        for kind in ("list", "dict"):
            with self.subTest(kind=kind):
                boundary = safe_metadata(
                    nested_value(kind, MAX_METADATA_NESTING)
                )

                json.dumps(boundary)
                rendered = render_challenge_html(
                    {"name": "Boundary", "hints": boundary},
                    [],
                    [],
                )
                self.assertIn(HOSTILE_BODY, rendered)
                with self.assertRaises(CollectorError) as caught:
                    safe_metadata(
                        nested_value(kind, MAX_METADATA_NESTING + 1)
                    )
                self.assertEqual(caught.exception.code, "metadata_too_deep")

    def test_safe_metadata_rejects_deep_lists_and_dicts_structurally(self):
        for kind in ("list", "dict"):
            with self.subTest(kind=kind):
                with self.assertRaises(CollectorError) as caught:
                    safe_metadata(
                        nested_value(kind),
                        secrets=("ctfd-secret",),
                    )

                self.assertEqual(caught.exception.code, "metadata_too_deep")
                self.assertNotIn(HOSTILE_BODY, caught.exception.message)
                self.assertNotIn("ctfd-secret", caught.exception.message)
                self.assertNotIn("RecursionError", caught.exception.message)

    def test_hostile_challenges_are_partial_and_later_ctf_gets_manifest(self):
        summaries = [
            {"id": 1, "name": "Hostile list", "category": "misc"},
            {"id": 2, "name": "Hostile dict", "category": "misc"},
            {"id": 3, "name": "Safe later challenge", "category": "web"},
        ]

        def responder(request):
            parsed = urlsplit(request["url"])
            if parsed.hostname == "hostile.example":
                if parsed.path == "/api/v1/challenges":
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
                if parsed.path == "/api/v1/challenges/1":
                    return 200, {}, hostile_detail(1, "list")
                if parsed.path == "/api/v1/challenges/2":
                    return 200, {}, hostile_detail(2, "dict")
                if parsed.path == "/api/v1/challenges/3":
                    return 200, {}, {
                        "data": {
                            "id": 3,
                            "name": "Safe later challenge",
                            "category": "web",
                            "description": "safe body retained",
                            "files": [],
                        }
                    }
                if parsed.path == "/rules":
                    return 404, {}, b"missing"
            if (
                parsed.hostname == "later.example"
                and parsed.path == "/api/v1/challenges"
            ):
                return 200, {}, {
                    "data": [],
                    "meta": {
                        "pagination": {"next": None, "page": 1, "pages": 0}
                    },
                }
            if parsed.hostname == "later.example" and parsed.path == "/rules":
                return 404, {}, b"missing"
            self.fail(f"unexpected request: {request['url']}")

        with tempfile.TemporaryDirectory() as tmp:
            hostile = make_config(
                tmp,
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

            hostile_text = (
                Path(tmp) / "out" / "hostile" / "manifest.json"
            ).read_text(encoding="utf-8")
            safe_challenge_text = next(
                (Path(tmp) / "out" / "hostile" / "web").glob(
                    "*/challenge.json"
                )
            ).read_text(encoding="utf-8")
            later_text = (
                Path(tmp) / "out" / "later" / "manifest.json"
            ).read_text(encoding="utf-8")

        hostile_manifest = json.loads(hostile_text)
        later_manifest = json.loads(later_text)
        self.assertEqual([item["name"] for item in results], ["hostile", "later"])
        self.assertIsNone(results[0]["error"])
        self.assertTrue(results[0]["partial"])
        self.assertIsNone(results[1]["error"])
        self.assertFalse(results[1]["partial"])
        self.assertEqual(hostile_manifest["status"], "partial")
        self.assertEqual(
            [item["id"] for item in hostile_manifest["challenges"]],
            ["3"],
        )
        nesting_failures = [
            failure
            for failure in hostile_manifest["failures"]
            if failure["error"]["code"] == "metadata_too_deep"
        ]
        self.assertEqual(
            [failure["challenge_id"] for failure in nesting_failures],
            ["1", "2"],
        )
        self.assertIn("safe body retained", safe_challenge_text)
        self.assertEqual(later_manifest["status"], "complete")
        for persisted in (hostile_text, later_text):
            self.assertNotIn(HOSTILE_BODY, persisted)
            self.assertNotIn("ctfd-secret", persisted)
            self.assertNotIn("RecursionError", persisted)


class UrlUserinfoControlTests(unittest.TestCase):
    def test_url_metadata_and_prose_remove_whatwg_userinfo_controls(self):
        for source_url in CREDENTIAL_URLS:
            with self.subTest(source_url=source_url):
                prose = f"First prose line\nFetch {source_url} now.\nLast prose line"

                metadata = safe_metadata(
                    {"source_url": source_url, "description": prose}
                )

                expected_prose = (
                    f"First prose line\nFetch {SAFE_URL} now.\nLast prose line"
                )
                self.assertEqual(metadata["source_url"], SAFE_URL)
                self.assertEqual(metadata["description"], expected_prose)
                self.assertEqual(redact_urls_in_text(prose), expected_prose)
                persisted = repr(metadata)
                for credential in ("alice", "plain-password", "token=Q", "#F"):
                    self.assertNotIn(credential, persisted)

    def test_credentials_do_not_persist_in_challenge_or_rules_documents(self):
        description = (
            "Description before\n"
            + "\n".join(CREDENTIAL_URLS)
            + "\nDescription after"
        )
        rules = (
            "Rules before\n" + "\n".join(CREDENTIAL_URLS) + "\nRules after"
        )

        def responder(request):
            path = urlsplit(request["url"]).path
            if path == "/api/v1/challenges":
                return 200, {}, {
                    "data": [{"id": 9, "name": "Controls", "category": "web"}],
                    "meta": {
                        "pagination": {"next": None, "page": 1, "pages": 1}
                    },
                }
            if path == "/api/v1/challenges/9":
                return 200, {}, {
                    "data": {
                        "id": 9,
                        "name": "Controls",
                        "category": "web",
                        "description": description,
                        "files": [],
                        "source_url": CREDENTIAL_URLS[1],
                    }
                }
            if path == "/rules":
                return 200, {"Content-Type": "text/plain"}, rules.encode("utf-8")
            self.fail(f"unexpected request: {request['url']}")

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)

            challenge_root = next(
                (Path(tmp) / "out" / "fake-ctfd" / "web").iterdir()
            )
            persisted = {
                "json": (challenge_root / "challenge.json").read_text(
                    encoding="utf-8"
                ),
                "challenge_html": (challenge_root / "challenge.html").read_text(
                    encoding="utf-8"
                ),
                "rules_html": (
                    Path(tmp) / "out" / "fake-ctfd" / "rules.html"
                ).read_text(encoding="utf-8"),
            }

        self.assertEqual(manifest["status"], "complete")
        for name, document in persisted.items():
            with self.subTest(document=name):
                self.assertIn("example.test/path", document)
                self.assertNotIn("?token=Q", document)
                self.assertNotIn("#F", document)
                self.assertNotIn("plain-password", document)
                self.assertNotIn("alice", document)
                self.assertNotIn("ali&#", document)
        self.assertIn('"source_url": "http://example.test/path"', persisted["json"])
        self.assertIn("Description before", persisted["challenge_html"])
        self.assertIn("Description after", persisted["challenge_html"])
        self.assertIn("Rules before", persisted["rules_html"])
        self.assertIn("Rules after", persisted["rules_html"])


if __name__ == "__main__":
    unittest.main()
