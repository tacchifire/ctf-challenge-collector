"""Regressions for the blocking P0/P1 gate findings.

Each class here pins one finding: what must never reach the archive, and what
must stay a structured partial failure instead of ending the run.
"""

from html.parser import HTMLParser
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from ctf_collector.archive import (
    MEDIA_SIGNATURE_PREFIX_BYTES,
    media_signature_matches,
    passive_media_name,
    render_challenge_html,
    strip_session_markup,
)
from ctf_collector.collector import _approved_cached_size, collect_ctf
from ctf_collector.config import MAX_FILE_BYTES, MAX_TOTAL_BYTES
from ctf_collector.errors import CollectorError
from ctf_collector.http import HttpClient
from ctf_collector.safety import (
    SafeOutput,
    WITHHELD,
    redact_url,
    redact_urls_in_text,
    safe_metadata,
)

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


def challenge_responder(test, detail, *, rules=None, bodies=None):
    """A CTFd responder for one challenge, with optional rules and bodies."""

    def responder(request):
        path = urlsplit(request["url"]).path
        if path == "/rules":
            return rules if rules is not None else (404, {}, b"missing")
        if path == "/api/v1/challenges":
            return 200, {}, terminal_page(
                [
                    {
                        "id": detail["id"],
                        "name": detail["name"],
                        "category": detail["category"],
                    }
                ]
            )
        if path == f"/api/v1/challenges/{detail['id']}":
            return 200, {}, {"data": detail}
        if bodies is not None and path in bodies:
            return bodies[path]
        test.fail(f"unexpected request: {request['url']}")

    return responder


class _Anchors(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.anchors = []

    def handle_starttag(self, tag, attrs):
        if tag.casefold() == "a":
            self.anchors.append(
                {name.casefold(): value for name, value in attrs}
            )


CTFD_RULES_PAGE = (
    "<!doctype html><html><head>"
    '<meta name="csrf-nonce" content="NONCE-abcdef">'
    "<title>Rules</title></head><body>"
    '<nav><a href="/profile">operator@example.com</a></nav>'
    "<header>Signed in as operator@example.com</header>"
    "<h1>Event Rules</h1><!-- flag{comment-kept} --><p>Be kind.</p>"
    '<form><input type="hidden" name="nonce" value="NONCE-abcdef"></form>'
    "<footer>operator@example.com</footer>"
    "<script>var init = {'csrfNonce': \"NONCE-abcdef\", "
    "'userEmail': \"operator@example.com\"};</script>"
    "</body></html>"
)


class RulesSessionStateTests(unittest.TestCase):
    """Finding 1: an authenticated page must not archive its session state."""

    def test_ctfd_rules_drop_session_markup_but_keep_comments_and_prose(self):
        responder = challenge_responder(
            self,
            {"id": 1, "name": "Only", "category": "misc", "files": []},
            rules=(
                200,
                {"Content-Type": "text/html; charset=utf-8"},
                CTFD_RULES_PAGE.encode("utf-8"),
            ),
        )

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)
            event_root = Path(tmp) / "out" / "fake-ctfd"
            rules_html = (event_root / "rules.html").read_text(encoding="utf-8")
            manifest_text = (event_root / "manifest.json").read_text(
                encoding="utf-8"
            )

        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(manifest["rules"]["status"], "written")
        self.assertIn("Event Rules", rules_html)
        self.assertIn("Be kind.", rules_html)
        self.assertIn("&lt;!-- flag{comment-kept} --&gt;", rules_html)
        persisted = f"{rules_html}\n{manifest_text}"
        for withheld in (
            "NONCE-abcdef",
            "operator@example.com",
            "csrfNonce",
            "userEmail",
            "csrf-nonce",
        ):
            self.assertNotIn(withheld, persisted)


    def test_session_markup_removal_is_fail_closed_and_keeps_prose(self):
        self.assertEqual(
            strip_session_markup("<p>keep</p><script>var nonce = 1;"),
            "<p>keep</p>",
        )
        self.assertEqual(
            strip_session_markup("<nav><nav>deep</nav>chrome</nav><p>after</p>"),
            "<p>after</p>",
        )
        self.assertEqual(
            strip_session_markup("<!-- flag{x} --><p>5 < 6</p><meta a><input b>"),
            "<!-- flag{x} --><p>5 < 6</p>",
        )


class RulesRedirectTests(unittest.TestCase):
    """Finding 2: a redirect off the rules page is not the rules page."""

    def rules_redirect(self, location, *, final_path, final_body):
        def responder(request):
            path = urlsplit(request["url"]).path
            if path == "/rules":
                return 302, {"Location": location}, b""
            if path == final_path:
                return 200, {"Content-Type": "text/html"}, final_body
            if path == "/api/v1/challenges":
                return 200, {}, terminal_page([])
            self.fail(f"unexpected request: {request['url']}")

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)
            rules_path = Path(tmp) / "out" / "fake-ctfd" / "rules.html"
            written = (
                rules_path.read_text(encoding="utf-8")
                if rules_path.exists()
                else None
            )
        return manifest, written

    def test_login_redirect_is_a_structured_failure_and_writes_no_rules(self):
        manifest, written = self.rules_redirect(
            "/login?next=%2Frules",
            final_path="/login",
            final_body=b"<h1>Please log in</h1>",
        )

        self.assertEqual(manifest["status"], "partial")
        self.assertEqual(manifest["rules"]["status"], "failed")
        self.assertIsNone(manifest["rules"]["path"])
        self.assertIn(
            "rules_redirected",
            [failure["error"]["code"] for failure in manifest["failures"]],
        )
        self.assertIsNone(written)

    def test_trailing_slash_redirect_on_the_rules_path_is_still_the_rules(self):
        manifest, written = self.rules_redirect(
            "/rules/",
            final_path="/rules/",
            final_body=b"<h1>Event Rules</h1>",
        )

        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(manifest["rules"]["status"], "written")
        self.assertIn("Event Rules", written)


class AttachmentLinkTests(unittest.TestCase):
    """Finding 3: an attachment link must not navigate to active content."""

    def test_attachment_anchors_download_instead_of_navigating(self):
        page = render_challenge_html(
            {"category": "web", "description": "", "id": "1", "name": "Links"},
            [
                {
                    "html_path": "files/report.html",
                    "local_path": "web/1-Links/files/report.html",
                    "status": "downloaded",
                },
                {
                    "html_path": "files/vector.svg",
                    "local_path": "web/1-Links/files/vector.svg",
                    "status": "verified",
                },
            ],
            [],
        )
        parser = _Anchors()
        parser.feed(page)
        parser.close()

        self.assertEqual(len(parser.anchors), 2)
        for anchor in parser.anchors:
            self.assertIn("download", anchor)
            self.assertEqual(anchor.get("rel"), "noopener noreferrer")


VALID_BMP = (
    b"BM"
    + (62).to_bytes(4, "little")
    + b"\x00\x00\x00\x00"
    + (54).to_bytes(4, "little")
    + (40).to_bytes(4, "little")
)
VALID_PNG = b"\x89PNG\r\n\x1a\npixels"
VALID_MP4 = b"\x00\x00\x00\x10ftypisom\x00\x00\x00\x00"
VALID_ID3 = b"ID3\x04\x00\x00\x00\x00\x00\x00"


class MediaSignatureTests(unittest.TestCase):
    """Finding 4: a signature must be the format, not a substring of it."""

    def test_document_bodies_that_merely_contain_a_marker_are_rejected(self):
        rejected = (
            ("video/mp4", b"<!--ftyp-->"),
            ("audio/mp4", b"<!--ftyp-->"),
            ("video/quicktime", b"<!--ftyp-->"),
            ("video/mp4", b"\x00\x00\x00\x02ftypisom"),
            ("image/bmp", b"BM<script>alert(1)</script>"),
            ("image/bmp", b"BM"),
            ("audio/mpeg", b"\xff\xe0\x00\x00"),
            ("audio/mpeg", b"\xff\xff\xff\xff"),
            ("audio/mpeg", b"\xffhello"),
        )
        for content_type, payload in rejected:
            with self.subTest(content_type=content_type, payload=payload):
                self.assertFalse(media_signature_matches(content_type, payload))

    def test_real_headers_are_still_accepted(self):
        accepted = (
            ("video/mp4", VALID_MP4),
            ("image/bmp", VALID_BMP),
            ("audio/mpeg", b"\xff\xfb\x90\x00"),
            ("audio/mpeg", VALID_ID3),
            ("image/png", VALID_PNG),
        )
        for content_type, payload in accepted:
            with self.subTest(content_type=content_type, payload=payload):
                self.assertTrue(media_signature_matches(content_type, payload))


class PassiveMediaNameTests(unittest.TestCase):
    """Finding 4: an archived media file must not keep an active suffix."""

    def test_active_document_suffixes_gain_a_passive_one_idempotently(self):
        for name, expected in (
            ("evil.svg", "evil.svg.bin"),
            ("evil.HTML", "evil.HTML.bin"),
            ("page.htm", "page.htm.bin"),
            ("page.xhtml", "page.xhtml.bin"),
            ("feed.xml", "feed.xml.bin"),
            ("code.js", "code.js.bin"),
            ("code.mjs", "code.mjs.bin"),
            ("photo.png", "photo.png"),
            ("sound.mp3", "sound.mp3"),
            ("plain", "plain"),
        ):
            with self.subTest(name=name):
                self.assertEqual(passive_media_name(name), expected)
                self.assertEqual(
                    passive_media_name(passive_media_name(name)),
                    expected,
                )

    def test_downloaded_media_named_svg_is_stored_and_reused_as_passive(self):
        media_gets = 0

        def responder(request):
            nonlocal media_gets
            path = urlsplit(request["url"]).path
            if path == "/rules":
                return 404, {}, b"missing"
            if path == "/api/v1/challenges":
                return 200, {}, terminal_page(
                    [{"id": 1, "name": "Vector", "category": "web"}]
                )
            if path == "/api/v1/challenges/1":
                return 200, {}, {
                    "data": {
                        "category": "web",
                        "description": '<img src="/media/evil.svg">',
                        "files": [],
                        "id": 1,
                        "name": "Vector",
                    }
                }
            if path == "/media/evil.svg":
                media_gets += 1
                return 200, {"Content-Type": "image/png"}, VALID_PNG
            self.fail(f"unexpected request: {request['url']}")

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                first = collect_ctf(config)
                second = collect_ctf(config)
            challenge_dir = Path(tmp) / "out" / "fake-ctfd" / "web" / "1-Vector"
            page = (challenge_dir / "challenge.html").read_text(encoding="utf-8")
            stored = sorted(
                path.name for path in (challenge_dir / "media").glob("*")
            )

        self.assertEqual(first["status"], "complete")
        self.assertEqual(second["status"], "complete")
        self.assertEqual(media_gets, 1)
        self.assertEqual(stored, ["evil.svg.bin"])
        self.assertEqual(
            second["challenges"][0]["media"][0]["status"],
            "verified",
        )
        self.assertIn('src="media/evil.svg.bin"', page)


class BareRelativeRedactionTests(unittest.TestCase):
    """Finding 6: a bare relative destination still carries a query."""

    def test_bare_relative_destinations_lose_query_and_fragment(self):
        self.assertEqual(
            redact_urls_in_text("See download?credential=SECRET#fragment now"),
            "See download now",
        )
        self.assertEqual(
            redact_urls_in_text("attachment#token=SECRET ends"),
            "attachment ends",
        )
        # Prose keeps its own punctuation: none of these is a destination, and
        # a flag that spells one of these characters is the content we exist to
        # preserve.
        self.assertEqual(
            redact_urls_in_text("A question? remains, and # heading remains."),
            "A question? remains, and # heading remains.",
        )
        self.assertEqual(
            redact_urls_in_text("flag{a#b} and flag{c?d}"),
            "flag{a#b} and flag{c?d}",
        )
        self.assertEqual(
            redact_urls_in_text("see issue#42 now"),
            "see issue#42 now",
        )

    def test_bare_relative_destinations_are_redacted_in_source_documents(self):
        description = "Fetch download?credential=SECRET-DESC#frag for the file."
        rules = "Read handout?credential=SECRET-RULES#frag before starting."
        responder = challenge_responder(
            self,
            {
                "category": "misc",
                "description": description,
                "files": [],
                "id": 1,
                "name": "Bare",
            },
            rules=(200, {"Content-Type": "text/plain"}, rules.encode("utf-8")),
        )

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                collect_ctf(config)
            event_root = Path(tmp) / "out" / "fake-ctfd"
            persisted = "\n".join(
                path.read_text(encoding="utf-8", errors="replace")
                for path in event_root.rglob("*")
                if path.is_file()
            )

        self.assertIn("Fetch download for the file.", persisted)
        self.assertIn("Read handout before starting.", persisted)
        self.assertNotIn("SECRET-DESC", persisted)
        self.assertNotIn("SECRET-RULES", persisted)
        self.assertNotIn("credential=", persisted)


class MalformedUrlTests(unittest.TestCase):
    """Finding 7: an unparsable URL is a failure, never a raw ValueError."""

    def test_redaction_fails_closed_instead_of_raising(self):
        self.assertEqual(redact_url("http://[broken/x?token=SECRET"), WITHHELD)
        self.assertEqual(
            redact_url("http://[broken/x?token=SECRET", force=True),
            WITHHELD,
        )
        redacted = redact_urls_in_text("see http://[broken/x?token=SECRET now")
        self.assertNotIn("SECRET", redacted)
        self.assertEqual(
            safe_metadata({"url": "http://[broken/x?token=SECRET"}),
            {"url": WITHHELD},
        )

    def test_malformed_urls_become_collector_errors_not_value_errors(self):
        client = HttpClient(
            "https://base.example",
            "token",
            "Token",
            "ctfd",
            [],
            1.0,
            {
                "max_attempts": 1,
                "backoff_seconds": 0.0,
                "max_retry_after_seconds": 0.0,
            },
            {"verify": True},
            {"max_redirects": 3, "max_metadata_bytes": 1024},
        )
        for value in ("http://[broken/x", "//[broken/y"):
            with self.subTest(value=value):
                with self.assertRaises(CollectorError) as caught:
                    client.resolve(value)
                self.assertEqual(caught.exception.code, "invalid_url")

    def test_malformed_attachment_and_media_urls_are_partial_not_fatal(self):
        responder = challenge_responder(
            self,
            {
                "category": "misc",
                "description": '<img src="http://[broken/x?token=SECRET-MEDIA">',
                "files": [
                    {
                        "name": "a.bin",
                        "url": "http://[broken/y?token=SECRET-FILE",
                    }
                ],
                "id": 1,
                "name": "Broken",
            },
        )

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)
            event_root = Path(tmp) / "out" / "fake-ctfd"
            manifest_text = (event_root / "manifest.json").read_text(
                encoding="utf-8"
            )
            persisted = "\n".join(
                path.read_text(encoding="utf-8", errors="replace")
                for path in event_root.rglob("*")
                if path.is_file()
            )

        self.assertEqual(manifest["status"], "partial")
        self.assertEqual(
            {failure["error"]["code"] for failure in manifest["failures"]},
            {"invalid_url"},
        )
        self.assertNotIn("SECRET-MEDIA", persisted)
        self.assertNotIn("SECRET-FILE", persisted)
        self.assertIn("challenges", json.loads(manifest_text))

    def test_malformed_redirect_location_is_a_structured_rules_failure(self):
        def responder(request):
            path = urlsplit(request["url"]).path
            if path == "/rules":
                return 302, {"Location": "http://[broken/?token=SECRET"}, b""
            if path == "/api/v1/challenges":
                return 200, {}, terminal_page([])
            self.fail(f"unexpected request: {request['url']}")

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)
            manifest_text = (
                Path(tmp) / "out" / "fake-ctfd" / "manifest.json"
            ).read_text(encoding="utf-8")

        self.assertEqual(manifest["status"], "partial")
        self.assertEqual(manifest["rules"]["status"], "failed")
        self.assertIn(
            "invalid_url",
            [failure["error"]["code"] for failure in manifest["failures"]],
        )
        self.assertNotIn("SECRET", manifest_text)


class ArchiveWriteFailureTests(unittest.TestCase):
    """Finding 5: a page we cannot write is not a run we must abandon."""

    def collect_twice_over_symlinks(self, targets):
        detail = {
            "category": "misc",
            "description": "prose",
            "files": [],
            "id": 1,
            "name": "Page",
        }
        responder = challenge_responder(
            self,
            detail,
            rules=(200, {"Content-Type": "text/plain"}, b"Be kind."),
        )

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            outside = Path(tmp) / "outside"
            outside.write_text("untouched", encoding="utf-8")
            with patch("ctf_collector.http.build_opener", return_value=fake):
                first = collect_ctf(config)
                event_root = Path(tmp) / "out" / "fake-ctfd"
                for target in targets:
                    path = event_root / target
                    path.unlink()
                    path.symlink_to(outside)
                second = collect_ctf(config)
            manifest_text = (event_root / "manifest.json").read_text(
                encoding="utf-8"
            )
            leftovers = sorted(
                path.name for path in event_root.rglob("*.part")
            )
            outside_text = outside.read_text(encoding="utf-8")
        return first, second, json.loads(manifest_text), leftovers, outside_text

    def test_challenge_html_symlink_is_partial_and_still_writes_a_manifest(self):
        first, second, manifest, leftovers, outside_text = (
            self.collect_twice_over_symlinks(("misc/1-Page/challenge.html",))
        )

        self.assertEqual(first["status"], "complete")
        self.assertEqual(second["status"], "partial")
        entry = second["challenges"][0]["html"]
        self.assertEqual(entry["status"], "failed")
        self.assertIsNone(entry["path"])
        self.assertIn(
            "unsafe_path",
            [failure["error"]["code"] for failure in second["failures"]],
        )
        self.assertEqual(manifest["status"], "partial")
        self.assertEqual(manifest["challenges"][0]["html"]["status"], "failed")
        self.assertEqual(outside_text, "untouched")
        self.assertEqual(leftovers, [])

    def test_rules_html_symlink_is_partial_and_still_writes_a_manifest(self):
        _first, second, manifest, leftovers, outside_text = (
            self.collect_twice_over_symlinks(("rules.html",))
        )

        self.assertEqual(second["status"], "partial")
        self.assertEqual(second["rules"]["status"], "failed")
        self.assertIsNone(second["rules"]["path"])
        self.assertIn(
            "unsafe_path",
            [failure["error"]["code"] for failure in second["failures"]],
        )
        self.assertEqual(manifest["rules"]["status"], "failed")
        self.assertEqual(outside_text, "untouched")
        self.assertEqual(leftovers, [])


class CachedLimitApprovalTests(unittest.TestCase):
    """Finding 8: a cached file over the run's limits is asked about too."""

    ATTACHMENT_BODY = b"123456"
    MEDIA_BODY = b"\x89PNG\r\n\x1a\n"

    def responder(self, gets):
        detail = {
            "category": "misc",
            "description": '<img src="/media/pixel.png">',
            "files": [{"name": "big.bin", "url": "/files/big.bin"}],
            "id": 1,
            "name": "Cached",
        }
        base = challenge_responder(self, detail)

        def responder(request):
            path = urlsplit(request["url"]).path
            if path == "/files/big.bin":
                gets.append(path)
                return 200, {}, self.ATTACHMENT_BODY
            if path == "/media/pixel.png":
                gets.append(path)
                return 200, {"Content-Type": "image/png"}, self.MEDIA_BODY
            return base(request)

        return responder

    def collect_then_recollect(self, second_limits, approver):
        gets = []
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(self.responder(gets))
            with patch("ctf_collector.http.build_opener", return_value=fake):
                first = collect_ctf(config)
                config["limits"].update(second_limits)
                second = collect_ctf(config, limit_approver=approver)
        return first, second, gets

    def test_cached_file_over_the_file_threshold_is_approved_and_verified(self):
        requests = []
        first, second, gets = self.collect_then_recollect(
            {"max_file_bytes": 5},
            lambda request: requests.append(request) or True,
        )

        self.assertEqual(first["status"], "complete")
        self.assertEqual(second["status"], "complete")
        self.assertEqual(second["challenges"][0]["files"][0]["status"], "verified")
        self.assertEqual(gets, ["/files/big.bin", "/media/pixel.png"])
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]["exceeded"], "file")
        self.assertEqual(requests[0]["required_file_bytes"], 6)
        self.assertEqual(requests[0]["current_file_limit"], 5)

    def test_cached_media_over_the_total_threshold_is_approved_and_verified(self):
        requests = []
        _first, second, gets = self.collect_then_recollect(
            {"max_total_bytes": 8},
            lambda request: requests.append(request) or True,
        )

        self.assertEqual(second["status"], "complete")
        self.assertEqual(second["challenges"][0]["files"][0]["status"], "verified")
        self.assertEqual(second["challenges"][0]["media"][0]["status"], "verified")
        self.assertEqual(gets, ["/files/big.bin", "/media/pixel.png"])
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]["exceeded"], "total")
        self.assertEqual(requests[0]["required_total_bytes"], 14)

    def test_refused_cached_file_fails_without_downloading_it_again(self):
        _first, second, gets = self.collect_then_recollect(
            {"max_file_bytes": 5},
            lambda request: False,
        )

        self.assertEqual(second["status"], "partial")
        entry = second["challenges"][0]["files"][0]
        self.assertEqual(entry["status"], "failed")
        self.assertEqual(entry["failure"]["code"], "file_too_large")
        self.assertEqual(gets, ["/files/big.bin", "/media/pixel.png"])

    def test_cache_verification_never_reads_past_the_recorded_size(self):
        maxima = []
        real_hash_file = SafeOutput.hash_file

        def hash_file(self, parts, maximum, *, prefix_bytes=0):
            maxima.append(maximum)
            return real_hash_file(
                self,
                parts,
                maximum,
                prefix_bytes=prefix_bytes,
            )

        gets = []
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(self.responder(gets))
            with patch("ctf_collector.http.build_opener", return_value=fake):
                collect_ctf(config)
                with patch.object(SafeOutput, "hash_file", hash_file):
                    second = collect_ctf(config)

        self.assertEqual(second["status"], "complete")
        self.assertEqual(
            sorted(maxima),
            [len(self.ATTACHMENT_BODY), len(self.MEDIA_BODY)],
        )

    def test_cached_size_above_the_hard_cap_is_never_offered_for_approval(self):
        requests = []
        error = _approved_cached_size(
            MAX_FILE_BYTES + 1,
            0,
            {"max_file_bytes": MAX_FILE_BYTES, "max_total_bytes": MAX_TOTAL_BYTES},
            lambda request: requests.append(request) or True,
            ctf_name="fake-ctfd",
            local_path="misc/1-Cached/files/big.bin",
        )

        self.assertIsNotNone(error)
        self.assertEqual(error.code, "file_too_large")
        self.assertEqual(requests, [])


class CachedMediaReadFailureTests(unittest.TestCase):
    """A cache descriptor read failure is one media item, not the run."""

    def test_unreadable_cached_media_is_a_structured_media_failure(self):
        media_body = b"\x89PNG\r\n\x1a\n"
        detail = {
            "category": "misc",
            "description": '<img src="/media/pixel.png">',
            "files": [],
            "id": 1,
            "name": "Swapped",
        }
        base = challenge_responder(self, detail)

        def responder(request):
            if urlsplit(request["url"]).path == "/media/pixel.png":
                return 200, {"Content-Type": "image/png"}, media_body
            return base(request)

        real_hash_file = SafeOutput.hash_file

        def hash_file(self, parts, maximum, *, prefix_bytes=0):
            if prefix_bytes == MEDIA_SIGNATURE_PREFIX_BYTES:
                raise CollectorError("unsafe_path", "output file is a symlink")
            return real_hash_file(
                self,
                parts,
                maximum,
                prefix_bytes=prefix_bytes,
            )

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                first = collect_ctf(config)
                with patch.object(SafeOutput, "hash_file", hash_file):
                    second = collect_ctf(config)
            manifest_text = (
                Path(tmp) / "out" / "fake-ctfd" / "manifest.json"
            ).read_text(encoding="utf-8")

        self.assertEqual(first["status"], "complete")
        self.assertEqual(second["status"], "partial")
        entry = second["challenges"][0]["media"][0]
        self.assertEqual(entry["status"], "failed")
        self.assertEqual(entry["failure"]["code"], "unsafe_path")
        self.assertEqual(json.loads(manifest_text)["status"], "partial")


if __name__ == "__main__":
    unittest.main()
