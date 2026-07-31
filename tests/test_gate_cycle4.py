"""Gate cycle 4 regressions added before their fixes."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from ctf_collector.archive import redact_rules_values
from ctf_collector.collector import collect_ctf
from ctf_collector.safety import safe_metadata

from .support import FakeOpener, make_config


def terminal_page(challenges):
    return {
        "data": challenges,
        "meta": {
            "pagination": {
                "next": None,
                "page": 1,
                "pages": 1 if challenges else 0,
            }
        },
    }


class CanonicalizedRedactionTests(unittest.TestCase):
    def test_rules_redaction_canonicalizes_entities_unicode_and_prefixed_names(self):
        source = (
            "Contact operator&#64;localhost or e\u0301@example.local. "
            "username&#61;operator/sessionid&#61;SID/csrftoken&#61;CSRF; "
            "data-username=DATA-USER current_username=CURRENT-USER "
            "old_sessionid=OLD-SESSION next_csrftoken=NEXT-CSRF. "
            "Ordinary rules prose remains. <!-- flag{comment-kept} -->"
        )

        redacted = redact_rules_values(source)

        for leaked in (
            "operator",
            "e\u0301@example.local",
            "é@example.local",
            "SID",
            "CSRF",
            "DATA-USER",
            "CURRENT-USER",
            "OLD-SESSION",
            "NEXT-CSRF",
        ):
            self.assertNotIn(leaked, redacted)
        self.assertIn("Ordinary rules prose remains.", redacted)
        self.assertIn("<!-- flag{comment-kept} -->", redacted)

    def test_saved_sources_strip_entity_url_state_and_decoded_configured_secret(self):
        description = (
            '<img src="/media/pixel.png&quest;credential=SIGNED-SECRET&num;view"> '
            '<a href="/docs/ctfd&#45;secret">docs</a> '
            "see issue#42 and flag{keep?#=payload}"
        )
        rules = (
            "<p>Keep this rules prose.</p><!-- flag{rules-comment} -->"
            "<p>ctfd&#45;secret</p>"
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        )

        def responder(request):
            parsed = urlsplit(request["url"])
            if parsed.path == "/rules":
                return 200, {"Content-Type": "text/html"}, rules.encode("utf-8")
            if parsed.path == "/api/v1/challenges":
                return 200, {}, terminal_page(
                    [{"category": "misc", "id": 1, "name": "Entity URL"}]
                )
            if parsed.path == "/api/v1/challenges/1":
                return 200, {}, {
                    "data": {
                        "category": "misc",
                        "description": description,
                        "files": [],
                        "id": 1,
                        "name": "Entity URL",
                    }
                }
            if parsed.path == "/media/pixel.png":
                return 200, {"Content-Type": "image/png"}, b"\x89PNG\r\n\x1a\npixels"
            self.fail(f"unexpected request: {request['url']}")

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)

            event_root = Path(tmp) / "out" / "fake-ctfd"
            challenge_root = event_root / "misc" / "1-Entity_URL"
            metadata = json.loads(
                (challenge_root / "challenge.json").read_text(encoding="utf-8")
            )
            persisted = "\n".join(
                (
                    (event_root / "rules.html").read_text(encoding="utf-8"),
                    (challenge_root / "challenge.html").read_text(encoding="utf-8"),
                    (challenge_root / "challenge.json").read_text(encoding="utf-8"),
                    (event_root / "manifest.json").read_text(encoding="utf-8"),
                )
            )

        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(
            metadata["raw"]["description"],
            '<img src="/media/pixel.png"> '
            '<a href="/docs/[REDACTED]">docs</a> '
            "see issue#42 and flag{keep?#=payload}",
        )
        for leaked in (
            "SIGNED-SECRET",
            "credential=",
            "&quest;",
            "&num;view",
            "ctfd-secret",
            "ctfd&#45;secret",
        ):
            self.assertNotIn(leaked, persisted)
        self.assertIn("Keep this rules prose.", persisted)
        self.assertIn("&lt;!-- flag{rules-comment} --&gt;", persisted)
        self.assertIn("issue#42", persisted)
        self.assertIn("flag{keep?#=payload}", persisted)
        self.assertNotIn("<script", persisted.lower())

    def test_url_valued_metadata_rechecks_secrets_after_entity_decoding(self):
        metadata = safe_metadata(
            {
                "source_url": (
                    "/docs/ctfd&#45;secret&quest;credential=SIGNED-SECRET&num;view"
                )
            },
            secrets=("ctfd-secret",),
        )

        self.assertEqual(metadata["source_url"], "/docs/[REDACTED]")


class RctfMalformedDetailTests(unittest.TestCase):
    def test_missing_and_invalid_detail_ids_are_partial_and_collection_continues(self):
        summaries = [
            {
                "category": "misc",
                "detail_url": "/api/detail/missing",
                "files": [],
                "id": "summary-missing",
                "name": "Missing detail id summary",
            },
            {
                "category": "web",
                "detail_url": "/api/detail/invalid",
                "files": [],
                "id": "summary-invalid",
                "name": "Invalid detail id summary",
            },
            {
                "category": "crypto",
                "detail_url": "/api/detail/good",
                "files": [],
                "id": "summary-good",
                "name": "Good summary",
            },
        ]

        def responder(request):
            path = urlsplit(request["url"]).path
            if path in ("/api/v1/challs", "/api/v1/challenges"):
                return 404, {}, b"missing"
            if path == "/api/challs":
                return 200, {}, {"challs": summaries}
            if path == "/api/detail/missing":
                return 200, {}, {
                    "category": "misc",
                    "description": "detail retained",
                    "files": [],
                    "name": "Missing detail id",
                }
            if path == "/api/detail/invalid":
                return 200, {}, {
                    "category": "web",
                    "files": [],
                    "id": [],
                    "name": "Invalid detail id",
                }
            if path == "/api/detail/good":
                return 200, {}, {
                    "category": "crypto",
                    "files": [],
                    "id": "summary-good",
                    "name": "Good detail",
                }
            if path == "/api/v1/integrations/client/config":
                return 200, {}, {
                    "kind": "goodClientConfig",
                    "data": {"homeContent": ""},
                }
            self.fail(f"unexpected request: {request['url']}")

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp, platform="rctf")
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)

        self.assertEqual(manifest["status"], "partial")
        self.assertEqual(
            {challenge["id"] for challenge in manifest["challenges"]},
            {"summary-missing", "summary-invalid", "summary-good"},
        )
        self.assertEqual(len(manifest["challenges"]), 3)
        self.assertEqual(
            {
                challenge["id"]: challenge["name"]
                for challenge in manifest["challenges"]
            },
            {
                "summary-missing": "Missing detail id",
                "summary-invalid": "Invalid detail id",
                "summary-good": "Good detail",
            },
        )
        self.assertEqual(
            [failure["error"]["code"] for failure in manifest["failures"]],
            ["invalid_api_data", "invalid_api_data"],
        )
        self.assertEqual(
            {failure["challenge_id"] for failure in manifest["failures"]},
            {"summary-missing", "summary-invalid"},
        )


if __name__ == "__main__":
    unittest.main()
