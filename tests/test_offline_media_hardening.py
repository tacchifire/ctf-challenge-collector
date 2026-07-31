import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from ctf_collector.archive import extract_media_sources, render_challenge_html
from ctf_collector.collector import collect_ctf

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


class MediaExtractionHardeningTests(unittest.TestCase):
    def test_mixed_media_keeps_source_order_and_first_duplicate(self):
        description = (
            '<img src="/first.png">\n'
            '![second](/second.png)\n'
            '<audio><source src="/third.ogg"></audio>\n'
            '![duplicate](/first.png)\n'
            '<video src="/fourth.mp4"></video>'
        )

        self.assertEqual(
            extract_media_sources(description),
            [
                ("image", "/first.png"),
                ("image", "/second.png"),
                ("audio", "/third.ogg"),
                ("video", "/fourth.mp4"),
            ],
        )

    def test_media_extraction_is_bounded_to_sixty_four_unique_sources(self):
        description = "\n".join(
            f'![image {index}](/media/{index}.png)'
            for index in range(80)
        )

        sources = extract_media_sources(description)

        self.assertEqual(len(sources), 64)
        self.assertEqual(sources[0], ("image", "/media/0.png"))
        self.assertEqual(sources[-1], ("image", "/media/63.png"))


class _DocumentAudit(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.references = []
        self.event_attributes = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag.casefold())
        for name, value in attrs:
            name = name.casefold()
            if name.startswith("on"):
                self.event_attributes.append(name)
            if name in {"href", "src"}:
                self.references.append(value)


class ChallengeRenderHardeningTests(unittest.TestCase):
    def test_only_verified_local_files_and_media_become_active_references(self):
        page = render_challenge_html(
            {
                "category": "web",
                "description": '<script>alert(1)</script><img src="https://evil.example/x">',
                "id": "1",
                "name": "Hostile",
            },
            [
                {
                    "html_path": "files/tool.bin",
                    "local_path": "web/1-Hostile/files/tool.bin",
                    "status": "verified",
                },
                {
                    "html_path": "../../outside.bin",
                    "local_path": "../../outside.bin",
                    "status": "verified",
                },
            ],
            [
                {
                    "html_path": "media/pixel.png",
                    "media_kind": "image",
                    "status": "downloaded",
                },
                {
                    "html_path": "https://evil.example/active.png",
                    "media_kind": "image",
                    "status": "verified",
                },
            ],
        )
        audit = _DocumentAudit()
        audit.feed(page)
        audit.close()

        self.assertEqual(audit.references, ["files/tool.bin", "media/pixel.png"])
        self.assertFalse(audit.event_attributes)
        self.assertFalse(
            {"script", "iframe", "form", "object", "embed"}.intersection(audit.tags)
        )
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)


class MediaContentHardeningTests(unittest.TestCase):
    def test_svg_and_spoofed_png_are_not_saved_or_activated(self):
        description = (
            '<img src="/spoof.png">'
            '<img src="/vector.svg">'
            '<img src="/good.jpg">'
        )

        def responder(request):
            path = urlsplit(request["url"]).path
            if path == "/rules":
                return 404, {}, b"missing"
            if path == "/api/v1/challenges":
                return 200, {}, terminal_page(
                    [{"id": 1, "name": "MIME", "category": "web"}]
                )
            if path == "/api/v1/challenges/1":
                return 200, {}, {
                    "data": {
                        "category": "web",
                        "description": description,
                        "files": [],
                        "id": 1,
                        "name": "MIME",
                    }
                }
            if path == "/spoof.png":
                return 200, {"Content-Type": "image/png"}, b"<html>not png</html>"
            if path == "/vector.svg":
                return 200, {"Content-Type": "image/svg+xml"}, (
                    b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>'
                )
            if path == "/good.jpg":
                return 200, {"Content-Type": "image/jpeg"}, b"\xff\xd8\xffvalid"
            self.fail(f"unexpected request: {request['url']}")

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)
            challenge_dir = Path(tmp) / "out" / "fake-ctfd" / "web" / "1-MIME"
            page = (challenge_dir / "challenge.html").read_text(encoding="utf-8")
            media_names = sorted(
                path.name for path in (challenge_dir / "media").glob("*")
            )

        self.assertEqual(manifest["status"], "partial")
        entries = manifest["challenges"][0]["media"]
        self.assertEqual(
            [entry["failure"]["code"] for entry in entries[:2]],
            ["invalid_media_content", "invalid_media_type"],
        )
        self.assertEqual(entries[2]["status"], "downloaded")
        self.assertEqual(media_names, ["good.jpg"])
        self.assertNotIn('src="media/spoof.png"', page)
        self.assertNotIn('src="media/vector.svg"', page)
        self.assertIn('src="media/good.jpg"', page)

    def test_verified_cache_revalidates_magic_before_active_reuse(self):
        valid_png = b"\x89PNG\r\n\x1a\nvalid"
        malicious_svg = b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>'
        media_gets = 0

        def responder(request):
            nonlocal media_gets
            path = urlsplit(request["url"]).path
            if path == "/rules":
                return 404, {}, b"missing"
            if path == "/api/v1/challenges":
                return 200, {}, terminal_page(
                    [{"id": 1, "name": "Cache", "category": "web"}]
                )
            if path == "/api/v1/challenges/1":
                return 200, {}, {
                    "data": {
                        "category": "web",
                        "description": '<img src="/pixel.png">',
                        "files": [],
                        "id": 1,
                        "name": "Cache",
                    }
                }
            if path == "/pixel.png":
                media_gets += 1
                return 200, {"Content-Type": "image/png"}, valid_png
            self.fail(f"unexpected request: {request['url']}")

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                first = collect_ctf(config)

                event_dir = Path(tmp) / "out" / "fake-ctfd"
                media_path = event_dir / "web" / "1-Cache" / "media" / "pixel.png"
                manifest_path = event_dir / "manifest.json"
                media_path.write_bytes(malicious_svg)
                old_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                old_entry = old_manifest["challenges"][0]["media"][0]
                old_entry["size"] = len(malicious_svg)
                old_entry["sha256"] = hashlib.sha256(malicious_svg).hexdigest()
                manifest_path.write_text(
                    json.dumps(old_manifest),
                    encoding="utf-8",
                )

                second = collect_ctf(config)
                final_bytes = media_path.read_bytes()
                page = (event_dir / "web" / "1-Cache" / "challenge.html").read_text(
                    encoding="utf-8"
                )

        self.assertEqual(first["status"], "complete")
        self.assertEqual(second["status"], "complete")
        self.assertEqual(media_gets, 2)
        self.assertEqual(final_bytes, valid_png)
        self.assertEqual(
            second["challenges"][0]["media"][0]["status"],
            "downloaded",
        )
        self.assertIn('src="media/pixel.png"', page)


if __name__ == "__main__":
    unittest.main()
