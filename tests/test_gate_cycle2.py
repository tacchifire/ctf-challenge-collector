"""Gate cycle 2 regressions added before their fixes."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from ctf_collector.archive import (
    media_signature_matches,
    redact_rules_values,
    strip_session_markup,
)
from ctf_collector.collector import collect_ctf
from ctf_collector.errors import CollectorError
from ctf_collector.safety import SafeOutput, redact_urls_in_text, safe_metadata

from .support import FakeOpener, make_config


VALID_MP4 = b"\x00\x00\x00\x10ftypisom\x00\x00\x00\x00"
VALID_ID3 = b"ID3\x04\x00\x00\x00\x00\x00\x00"
VALID_PNG = b"\x89PNG\r\n\x1a\npixels"


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


def ctfd_responder(test, detail, *, rules=None, bodies=None):
    def responder(request):
        path = urlsplit(request["url"]).path
        if path == "/rules":
            return rules if rules is not None else (404, {}, b"missing")
        if path == "/api/v1/challenges":
            return 200, {}, terminal_page(
                [
                    {
                        "category": detail["category"],
                        "id": detail["id"],
                        "name": detail["name"],
                    }
                ]
            )
        if path == f"/api/v1/challenges/{detail['id']}":
            return 200, {}, {"data": detail}
        if bodies and path in bodies:
            return bodies[path]
        test.fail(f"unexpected request: {request['url']}")

    return responder


class RulesValueRedactionTests(unittest.TestCase):
    def test_rules_redact_emails_and_sensitive_named_values_outside_removed_tags(self):
        source = (
            '<body data-owner="operator@example.com" '
            'data-session-nonce="BODY-NONCE" csrf="BODY-CSRF" '
            'auth="BODY-AUTH" token="BODY-TOKEN" email="BODY-EMAIL" '
            'user="BODY-USER">'
            '<p>Contact operator@example.com for ordinary event prose.</p>'
            '<div sessionNonce="DIV-NONCE">'
            'sessionNonce="TEXT-NONCE"; CSRF: TEXT-CSRF; '
            'auth=TEXT-AUTH; token=TEXT-TOKEN; email=TEXT-EMAIL; user=TEXT-USER'
            '</div><!-- flag{comment-kept} --></body>'
        )
        detail = {"category": "misc", "files": [], "id": 1, "name": "Rules"}
        responder = ctfd_responder(
            self,
            detail,
            rules=(
                200,
                {"Content-Type": "text/html; charset=utf-8"},
                source.encode("utf-8"),
            ),
        )

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)
            persisted = (
                Path(tmp) / "out" / "fake-ctfd" / "rules.html"
            ).read_text(encoding="utf-8")

        self.assertEqual(manifest["status"], "complete")
        self.assertIn("ordinary event prose", persisted)
        self.assertIn("&lt;!-- flag{comment-kept} --&gt;", persisted)
        for leaked in (
            "operator@example.com",
            "BODY-NONCE",
            "BODY-CSRF",
            "BODY-AUTH",
            "BODY-TOKEN",
            "BODY-EMAIL",
            "BODY-USER",
            "DIV-NONCE",
            "TEXT-NONCE",
            "TEXT-CSRF",
            "TEXT-AUTH",
            "TEXT-TOKEN",
            "TEXT-EMAIL",
            "TEXT-USER",
        ):
            self.assertNotIn(leaked, persisted)

    def test_self_closing_removed_container_discards_the_ambiguous_remainder(self):
        self.assertEqual(
            strip_session_markup(
                "<p>before</p><script/>SESSION-SECRET<p>after</p>"
            ),
            "<p>before</p>",
        )


class BareDestinationRedactionTests(unittest.TestCase):
    def test_opaque_and_unicode_bare_destinations_are_sanitized(self):
        self.assertEqual(
            redact_urls_in_text(
                "Get download?SIGNEDOPAQUE and attachment#SIGNEDFRAGMENT "
                "or 配布?token=x now"
            ),
            "Get download and attachment or 配布 now",
        )

    def test_flag_payload_is_preserved_but_configured_secrets_are_not(self):
        self.assertEqual(
            redact_urls_in_text("flag{a#b=c} flag{download?SIGNEDOPAQUE}"),
            "flag{a#b=c} flag{download?SIGNEDOPAQUE}",
        )
        redacted = safe_metadata(
            {"description": "flag{a#configured-secret=b} configured-secret"},
            secrets=("configured-secret",),
        )["description"]
        self.assertNotIn("configured-secret", redacted)
        self.assertIn("flag{a#[REDACTED]=b}", redacted)


class CachedDescriptorTests(unittest.TestCase):
    def _responder(self, requests):
        detail = {
            "category": "misc",
            "description": '<img src="/media/pixel.png">',
            "files": [{"name": "file.bin", "url": "/files/file.bin"}],
            "id": 1,
            "name": "Cached",
        }
        base = ctfd_responder(self, detail)

        def responder(request):
            path = urlsplit(request["url"]).path
            if path == "/files/file.bin":
                requests.append(path)
                return 200, {}, b"cached attachment"
            if path == "/media/pixel.png":
                requests.append(path)
                return 200, {"Content-Type": "image/png"}, VALID_PNG
            return base(request)

        return responder

    def test_cached_media_digest_and_prefix_do_not_use_a_second_open(self):
        requests = []
        real_read_bytes = SafeOutput.read_bytes

        def read_bytes(self, parts, maximum=None):
            if maximum is not None:
                raise AssertionError("cached media prefix used a second open")
            return real_read_bytes(self, parts, maximum)

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(self._responder(requests))
            with patch("ctf_collector.http.build_opener", return_value=fake):
                first = collect_ctf(config)
                with patch.object(SafeOutput, "read_bytes", read_bytes):
                    second = collect_ctf(config)

        self.assertEqual(first["status"], "complete")
        self.assertEqual(second["status"], "complete")
        self.assertEqual(second["challenges"][0]["media"][0]["status"], "verified")
        self.assertEqual(requests, ["/files/file.bin", "/media/pixel.png"])

    def test_cached_unsafe_path_is_a_structured_item_failure(self):
        requests = []
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(self._responder(requests))
            with patch("ctf_collector.http.build_opener", return_value=fake):
                collect_ctf(config)
                with patch.object(
                    SafeOutput,
                    "hash_file",
                    side_effect=CollectorError(
                        "unsafe_path", "output file is a symlink"
                    ),
                ):
                    second = collect_ctf(config)

        self.assertEqual(second["status"], "partial")
        for collection in ("files", "media"):
            entry = second["challenges"][0][collection][0]
            self.assertEqual(entry["status"], "failed")
            self.assertEqual(entry["failure"]["code"], "unsafe_path")

    def test_cached_read_oserror_is_a_structured_item_failure(self):
        requests = []
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(self._responder(requests))
            with patch("ctf_collector.http.build_opener", return_value=fake):
                collect_ctf(config)
                with patch.object(
                    SafeOutput,
                    "hash_file",
                    side_effect=OSError("cache read failed"),
                ):
                    second = collect_ctf(config)

        self.assertEqual(second["status"], "partial")
        entry = second["challenges"][0]["files"][0]
        self.assertEqual(entry["status"], "failed")
        self.assertEqual(entry["failure"]["code"], "cache_read_failed")


class RctfFallbackDetailTests(unittest.TestCase):
    def _collect(self, summary):
        def responder(request):
            path = urlsplit(request["url"]).path
            if path in ("/api/v1/challs", "/api/v1/challenges"):
                return 404, {}, b"missing"
            if path == "/api/challs":
                return 200, {}, {"challs": [summary]}
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
                return collect_ctf(config)

    def test_malformed_explicit_detail_url_is_partial(self):
        manifest = self._collect(
            {
                "category": "misc",
                "detail_url": "http://[broken/detail",
                "files": [],
                "id": "bad",
                "name": "Malformed detail",
            }
        )

        self.assertEqual(manifest["status"], "partial")
        self.assertEqual(len(manifest["challenges"]), 1)
        self.assertIn(
            "invalid_api_data",
            [failure["error"]["code"] for failure in manifest["failures"]],
        )

    def test_missing_optional_detail_url_remains_complete(self):
        manifest = self._collect(
            {
                "category": "misc",
                "detail_url": None,
                "files": [],
                "id": "summary-only",
                "name": "Summary is valid",
            }
        )

        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(len(manifest["challenges"]), 1)


class StrictMediaStructureTests(unittest.TestCase):
    def test_ftyp_brand_and_box_bounds_are_checked(self):
        valid_avif = b"\x00\x00\x00\x10ftypavif\x00\x00\x00\x00"
        valid_quicktime = b"\x00\x00\x00\x10ftypqt  \x00\x00\x00\x00"

        self.assertTrue(
            media_signature_matches(
                "video/mp4", VALID_MP4, total_size=len(VALID_MP4)
            )
        )
        self.assertTrue(media_signature_matches("image/avif", valid_avif))
        self.assertTrue(media_signature_matches("video/quicktime", valid_quicktime))
        self.assertFalse(media_signature_matches("video/mp4", VALID_MP4[:12]))
        self.assertFalse(
            media_signature_matches("video/mp4", VALID_MP4, total_size=15)
        )
        self.assertFalse(media_signature_matches("video/mp4", valid_avif))
        self.assertFalse(media_signature_matches("image/avif", VALID_MP4))
        self.assertFalse(media_signature_matches("video/quicktime", VALID_MP4))

    def test_id3_and_mpeg_require_plausible_bounded_headers(self):
        oversized_id3 = b"ID3\x04\x00\x00\x00\x00\x00\x01"

        self.assertTrue(media_signature_matches("audio/mpeg", VALID_ID3))
        self.assertTrue(media_signature_matches("audio/mpeg", b"\xff\xfb\x90\x00"))
        self.assertFalse(media_signature_matches("audio/mpeg", b"ID3"))
        self.assertFalse(media_signature_matches("audio/mpeg", oversized_id3))
        self.assertFalse(media_signature_matches("audio/mpeg", b"\xff\xfb\x00\x00"))


class ContentLengthDigitLimitTests(unittest.TestCase):
    def test_unreasonable_digit_count_is_a_structured_file_failure(self):
        detail = {
            "category": "misc",
            "files": [{"name": "huge.bin", "url": "/files/huge.bin"}],
            "id": 1,
            "name": "Huge length",
        }
        responder = ctfd_responder(
            self,
            detail,
            bodies={
                "/files/huge.bin": (
                    200,
                    {"Content-Length": "9" * 5000},
                    b"",
                )
            },
        )

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)

        self.assertEqual(manifest["status"], "partial")
        entry = manifest["challenges"][0]["files"][0]
        self.assertEqual(entry["status"], "failed")
        self.assertEqual(entry["failure"]["code"], "invalid_content_length")


class ReadmeMimeAllowlistTests(unittest.TestCase):
    def test_readme_documents_the_exact_media_mime_allowlist(self):
        readme = (Path(__file__).parents[1] / "README.md").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("`image/*`", readme)
        self.assertNotIn("`audio/*`", readme)
        self.assertNotIn("`video/*`", readme)
        for media_type in (
            "audio/flac",
            "audio/mpeg",
            "audio/mp4",
            "audio/ogg",
            "audio/wav",
            "audio/webm",
            "audio/x-wav",
            "image/bmp",
            "image/gif",
            "image/jpeg",
            "image/png",
            "image/webp",
            "video/mp4",
            "video/ogg",
            "video/quicktime",
            "video/webm",
        ):
            self.assertIn(f"`{media_type}`", readme)


class GateCycle3RedactionTests(unittest.TestCase):
    def test_compound_session_names_and_internationalized_emails_are_redacted(self):
        source = (
            'username="operator" sessionid="SID" csrftoken="CSRF"; '
            'Contact δοκιμή@παράδειγμα.δοκιμή or operator@localhost. '
            'Ordinary rules prose remains.'
        )

        redacted = redact_rules_values(source)

        for secret in (
            "operator",
            "SID",
            "CSRF",
            "δοκιμή@παράδειγμα.δοκιμή",
            "operator@localhost",
        ):
            self.assertNotIn(secret, redacted)
        self.assertIn("Ordinary rules prose remains.", redacted)

    def test_digit_prefixed_bare_destination_loses_query_and_fragment(self):
        source = "Fetch 7zip?token=SIGNED-SECRET and 123#opaque-secret now"

        redacted = safe_metadata({"description": source})["description"]

        self.assertEqual(redacted, "Fetch 7zip and 123 now")

    def test_numeric_scalar_matching_a_configured_token_is_redacted(self):
        value = {"reflected": 123456, "ordinary": 123457, "boolean": True}

        redacted = safe_metadata(value, secrets=("123456",))

        self.assertEqual(redacted["reflected"], "[REDACTED]")
        self.assertEqual(redacted["ordinary"], 123457)
        self.assertIs(redacted["boolean"], True)


if __name__ == "__main__":
    unittest.main()
