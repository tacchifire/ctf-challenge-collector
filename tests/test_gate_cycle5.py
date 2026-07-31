"""Gate cycle 5 regressions added before their fixes."""

import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from ctf_collector import safety
from ctf_collector.archive import redact_rules_values
from ctf_collector.collector import collect_ctf
from ctf_collector.safety import redact_url, redact_urls_in_text, safe_metadata

from .support import FakeOpener, make_config


class MetadataKeyCollisionTests(unittest.TestCase):
    def test_collision_suffix_skips_configured_secrets(self):
        metadata = safe_metadata(
            {"a?one=1": 1, "a#two=2": 2},
            secrets=("a__2",),
        )

        self.assertEqual(metadata, {"a": 1, "a__3": 2})
        self.assertNotIn("a__2", metadata)

    def test_collision_suffixes_are_linear_and_skip_preexisting_keys(self):
        count = 2_000
        source = {"shared__2": -1}
        source.update(
            {f"shared?collision={index}": index for index in range(count)}
        )
        candidate_checks = 0
        original_check = safety._metadata_key_available

        def counted_check(candidate, result, secrets):
            nonlocal candidate_checks
            candidate_checks += 1
            return original_check(candidate, result, secrets)

        with patch.object(
            safety,
            "_metadata_key_available",
            side_effect=counted_check,
        ):
            metadata = safe_metadata(source)

        self.assertEqual(len(metadata), count + 1)
        self.assertEqual(metadata["shared"], 0)
        self.assertEqual(metadata["shared__2"], -1)
        self.assertEqual(metadata[f"shared__{count + 1}"], count - 1)
        self.assertLessEqual(candidate_checks, 2 * len(source) + 1)


class SchemeRelativeUserinfoTests(unittest.TestCase):
    def test_scheme_relative_userinfo_is_removed_at_every_metadata_boundary(self):
        credentialed = "//alice:plain-password@example.test/path"
        safe = "//example.test/path"

        self.assertEqual(redact_url(credentialed), safe)
        self.assertEqual(
            redact_urls_in_text(f"Fetch {credentialed} now."),
            f"Fetch {safe} now.",
        )
        self.assertEqual(
            safe_metadata(
                {
                    "source_url": credentialed,
                    "description": f"Fetch {credentialed} now.",
                }
            ),
            {
                "source_url": safe,
                "description": f"Fetch {safe} now.",
            },
        )


class RctfFallbackIdentityTests(unittest.TestCase):
    def test_bad_summary_and_mismatched_detail_ids_are_partial_and_continue(self):
        summaries = [
            {
                "category": "misc",
                "detail_url": "/api/detail/missing-summary-id",
                "name": "Missing summary id",
            },
            {
                "category": "web",
                "detail_url": "/api/detail/invalid-summary-id",
                "id": [],
                "name": "Invalid summary id",
            },
            {
                "category": "crypto",
                "detail_url": "/api/detail/mismatch",
                "id": "summary-kept",
                "name": "Mismatch summary",
            },
            {
                "category": "pwn",
                "detail_url": "/api/detail/later",
                "id": "later",
                "name": "Later summary",
            },
        ]

        def responder(request):
            path = urlsplit(request["url"]).path
            if path in ("/api/v1/challs", "/api/v1/challenges"):
                return 404, {}, b"missing"
            if path == "/api/challs":
                return 200, {}, {"challs": summaries}
            if path in (
                "/api/detail/missing-summary-id",
                "/api/detail/invalid-summary-id",
            ):
                self.fail("a detail without a valid summary identity was fetched")
            if path == "/api/detail/mismatch":
                return 200, {}, {
                    "category": "crypto",
                    "description": "safe detail retained",
                    "files": [],
                    # This would duplicate the later challenge if detail
                    # identity were allowed to replace summary identity.
                    "id": "later",
                    "name": "Mismatch detail",
                }
            if path == "/api/detail/later":
                return 200, {}, {
                    "category": "pwn",
                    "files": [],
                    "id": "later",
                    "name": "Later detail",
                }
            if path == "/api/v1/integrations/client/config":
                return 200, {}, {
                    "kind": "goodClientConfig",
                    "data": {"homeContent": ""},
                }
            self.fail(f"unexpected rCTF route: {request['url']}")

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp, platform="rctf")
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)

        self.assertEqual(manifest["status"], "partial")
        self.assertEqual(
            [(item["id"], item["name"]) for item in manifest["challenges"]],
            [
                ("summary-kept", "Mismatch detail"),
                ("later", "Later detail"),
            ],
        )
        invalid = [
            failure
            for failure in manifest["failures"]
            if failure["error"]["code"] == "invalid_api_data"
        ]
        self.assertEqual(len(invalid), 3)
        self.assertEqual(
            [failure.get("challenge_id") for failure in invalid],
            [None, None, "summary-kept"],
        )


class RulesApiKeyTests(unittest.TestCase):
    def test_api_key_names_are_redacted_without_losing_rules_prose_or_comments(self):
        source = (
            "apiKey=CAMEL api_key=SNAKE data-api-key=DATA "
            "data&#45;api&#45;key&#61;ENTITY. "
            "Ordinary rules prose remains. <!-- flag{comment-kept} -->"
        )

        redacted = redact_rules_values(source)

        for secret in ("CAMEL", "SNAKE", "DATA", "ENTITY"):
            self.assertNotIn(secret, redacted)
        self.assertIn("Ordinary rules prose remains.", redacted)
        self.assertIn("<!-- flag{comment-kept} -->", redacted)


if __name__ == "__main__":
    unittest.main()
