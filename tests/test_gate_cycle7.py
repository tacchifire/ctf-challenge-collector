"""Gate cycle 7 regressions added before their fixes."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from ctf_collector.archive import redact_rules_values
from ctf_collector.collector import collect_ctf
from ctf_collector.safety import (
    WITHHELD,
    redact_url,
    redact_urls_in_text,
    safe_metadata,
)

from .support import FakeOpener, make_config


class WhatwgAuthorityRedactionTests(unittest.TestCase):
    def test_redact_url_removes_userinfo_from_noncanonical_authorities(self):
        variants = {
            "///alice:plain-password@example.test/path": "//example.test/path",
            "////alice:plain-password@example.test/path": "//example.test/path",
            r"\\alice:plain-password@example.test/path": "//example.test/path",
            "http:alice:plain-password@example.test/path": (
                "http://example.test/path"
            ),
            "http:/alice:plain-password@example.test/path": (
                "http://example.test/path"
            ),
            "http:///alice:plain-password@example.test/path": (
                "http://example.test/path"
            ),
            r"http:\alice:plain-password@example.test/path": (
                "http://example.test/path"
            ),
            r"http:\\alice:plain-password@example.test/path": (
                "http://example.test/path"
            ),
            r"http:/\alice:plain-password@example.test/path": (
                "http://example.test/path"
            ),
            (
                "http&colon;&sol;&sol;alice&colon;plain-password&commat;"
                "example.test&sol;path"
            ): "http://example.test/path",
            (
                "&sol;&sol;alice&colon;plain-password&commat;"
                "example.test&sol;path"
            ): "//example.test/path",
        }

        for source, expected in variants.items():
            with self.subTest(source=source):
                redacted = redact_url(source)
                self.assertEqual(redacted, expected)
                self.assertEqual(
                    redact_urls_in_text(f"Fetch {source} now."),
                    f"Fetch {expected} now.",
                )
                self.assertEqual(
                    safe_metadata({"source_url": source}),
                    {"source_url": expected},
                )
                self.assertNotIn("alice", redacted)
                self.assertNotIn("plain-password", redacted)

    def test_text_and_metadata_remove_noncanonical_userinfo_but_keep_context(self):
        sources = (
            "///alice:plain-password@example.test/path",
            "////alice:plain-password@example.test/path",
            r"\\alice:plain-password@example.test/path",
            "http:alice:plain-password@example.test/path",
            "http:/alice:plain-password@example.test/path",
            "http:///alice:plain-password@example.test/path",
            r"http:\alice:plain-password@example.test/path",
            r"http:\\alice:plain-password@example.test/path",
            r"http:/\alice:plain-password@example.test/path",
            (
                "http&colon;&sol;&sol;alice&colon;plain-password&commat;"
                "example.test&sol;path"
            ),
        )
        description = (
            "Ordinary prose alice@example.test issue#42 flag{keep?#=payload}. "
            + " ".join(sources)
        )

        redacted = redact_urls_in_text(description)
        metadata = safe_metadata(
            {
                "description": description,
                "source_url": "///alice:plain-password@example.test/path",
            }
        )

        for persisted in (redacted, repr(metadata)):
            self.assertNotIn("plain-password", persisted)
        self.assertEqual(metadata["source_url"], "//example.test/path")
        self.assertIn("Ordinary prose alice@example.test", redacted)
        self.assertIn("issue#42", redacted)
        self.assertIn("flag{keep?#=payload}", redacted)
        self.assertIn("example.test/path", redacted)

    def test_entity_scheme_relative_userinfo_after_prefix_is_removed(self):
        source = "x&sol;&sol;alice:plain-password@example.test/path"
        expected = "x//example.test/path"

        self.assertEqual(redact_urls_in_text(source), expected)
        self.assertEqual(
            safe_metadata({"description": source}),
            {"description": expected},
        )

    def test_hierarchical_url_metadata_strips_userinfo_for_any_scheme(self):
        source = "ssh://bob:other-password@example.test/private"

        self.assertEqual(redact_url(source), "ssh://example.test/private")
        self.assertEqual(
            safe_metadata({"source_url": source}),
            {"source_url": "ssh://example.test/private"},
        )


class CanonicalSensitiveKeyTests(unittest.TestCase):
    def test_metadata_classifies_the_canonical_stored_key(self):
        metadata = safe_metadata(
            {
                "apikey": "compact-secret",
                "api&#75;ey": "entity-secret",
                "access&#84;oken": "access-secret",
                "monkey": "ordinary value",
                "comment": "Ordinary prose alice@example.test issue#42 flag{keep}",
            }
        )

        self.assertEqual(metadata["apikey"], WITHHELD)
        self.assertEqual(metadata["apiKey"], WITHHELD)
        self.assertEqual(metadata["accessToken"], WITHHELD)
        self.assertEqual(metadata["monkey"], "ordinary value")
        self.assertEqual(
            metadata["comment"],
            "Ordinary prose alice@example.test issue#42 flag{keep}",
        )

    def test_rules_redact_compact_and_entity_api_keys_but_keep_source_content(self):
        source = (
            "apikey=COMPACT api&#75;ey=ENTITY. "
            "Ordinary rules prose remains. <!-- flag{comment-kept} -->"
        )

        redacted = redact_rules_values(source)

        self.assertNotIn("COMPACT", redacted)
        self.assertNotIn("ENTITY", redacted)
        self.assertIn("Ordinary rules prose remains.", redacted)
        self.assertIn("<!-- flag{comment-kept} -->", redacted)

    def test_rules_persistence_redacts_compact_and_entity_api_keys(self):
        rules = (
            "apikey=PERSISTED-COMPACT api&#75;ey=PERSISTED-ENTITY. "
            "Ordinary rules prose remains. <!-- flag{comment-kept} -->"
        )

        def responder(request):
            path = urlsplit(request["url"]).path
            if path == "/rules":
                return 200, {"Content-Type": "text/plain"}, rules.encode("utf-8")
            if path == "/api/v1/challenges":
                return 200, {}, {
                    "data": [],
                    "meta": {
                        "pagination": {"next": None, "page": 1, "pages": 0}
                    },
                }
            self.fail(f"unexpected request: {request['url']}")

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)
            persisted = (
                Path(tmp) / "out" / "fake-ctfd" / "rules.html"
            ).read_text(encoding="utf-8")

        self.assertEqual(manifest["status"], "complete")
        self.assertNotIn("PERSISTED-COMPACT", persisted)
        self.assertNotIn("PERSISTED-ENTITY", persisted)
        self.assertIn("Ordinary rules prose remains.", persisted)
        self.assertIn("&lt;!-- flag{comment-kept} --&gt;", persisted)


if __name__ == "__main__":
    unittest.main()
