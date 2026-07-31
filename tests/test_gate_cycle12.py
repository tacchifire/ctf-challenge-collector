"""Gate cycle 12 regressions added before their fixes."""

import hashlib
import hmac
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from ctf_collector.collector import collect_all, collect_ctf
from ctf_collector.errors import CollectorError
from ctf_collector.http import HttpClient, validated_url
from ctf_collector.safety import SafeOutput, safe_metadata

from .support import FakeOpener, make_config
from .test_sync import ScenarioServer


VALID_PNG = b"\x89PNG\r\n\x1a\ncycle twelve"
IDENTITY_CONTEXT = b"ctf-challenge-collector source identity\x00"
DETAIL_REFERENCE = (
    "/api/\u8a73\u7d30/\ud800/existing%2Fsegment"
    "?label=\u65e5\u672c\udcff&keep=a%20b/ok?x=y&plus=a+b"
    "&credential=detail-secret#detail-fragment"
)
DETAIL_WIRE = (
    "/api/%E8%A9%B3%E7%B4%B0/%EF%BF%BD/existing%2Fsegment"
    "?label=%E6%97%A5%E6%9C%AC%EF%BF%BD&keep=a%20b/ok?x=y&plus=a+b"
    "&credential=detail-secret"
)
ATTACHMENT_REFERENCE = (
    "/attachments/\u65e5\u672c/\ud800.bin"
    "?label=\u65e5\u672c\udcff&keep=f%2File&plus=f+g"
    "&credential=file-secret#file-fragment"
)
ATTACHMENT_WIRE = (
    "/attachments/%E6%97%A5%E6%9C%AC/%EF%BF%BD.bin"
    "?label=%E6%97%A5%E6%9C%AC%EF%BF%BD&keep=f%2File&plus=f+g"
    "&credential=file-secret"
)
MEDIA_REFERENCE = (
    "/media/\u753b\u50cf/\udcff.png"
    "?label=\u65e5\u672c\ud800&keep=m%20n&plus=m+n"
    "&credential=media-secret#media-fragment"
)
MEDIA_WIRE = (
    "/media/%E7%94%BB%E5%83%8F/%EF%BF%BD.png"
    "?label=%E6%97%A5%E6%9C%AC%EF%BF%BD&keep=m%20n&plus=m+n"
    "&credential=media-secret"
)
BODY_CREDENTIAL = "CYCLE12-BODY-CREDENTIAL"
PROGRAMMATIC_CREDENTIAL = "CYCLE12-PROGRAMMATIC-CREDENTIAL"
WRITE_CREDENTIAL = "CYCLE12-WRITE-CREDENTIAL"


def _source_identity(url, token):
    return hmac.new(
        token.encode("ascii"),
        IDENTITY_CONTEXT + url.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _documents(root):
    return [path for path in root.rglob("*") if path.is_file()]


class UrlWireEncodingTests(unittest.TestCase):
    def test_validated_url_canonically_encodes_path_and_query(self):
        source = "https://base.example" + DETAIL_REFERENCE

        self.assertEqual(
            validated_url(source),
            "https://base.example" + DETAIL_WIRE,
        )

    def test_real_http_encodes_unicode_urls_and_preserves_canonical_identity(self):
        def hostile_responder(method, raw_path, headers, body):
            if raw_path == "/api/v1/challs":
                return 404, {}, b"missing"
            if raw_path == "/api/v1/challenges":
                return 200, {}, {
                    "data": [
                        {
                            "id": "wire",
                            "name": "Unicode wire",
                            "category": "web",
                            "detail_url": DETAIL_REFERENCE,
                        },
                        {
                            "id": "later-challenge",
                            "name": "Later challenge",
                            "category": "pwn",
                            "detail_url": "/api/later-challenge",
                        },
                    ]
                }
            if raw_path == DETAIL_WIRE:
                return 200, {}, {
                    "data": {
                        "id": "wire",
                        "name": "Unicode wire",
                        "category": "web",
                        "description": f'<img src="{MEDIA_REFERENCE}">',
                        "files": [
                            {"name": "wire.bin", "url": ATTACHMENT_REFERENCE}
                        ],
                    }
                }
            if raw_path == "/api/later-challenge":
                return 200, {}, {
                    "data": {
                        "id": "later-challenge",
                        "name": "Later challenge",
                        "category": "pwn",
                        "description": "later challenge retained",
                        "files": [],
                    }
                }
            if raw_path == ATTACHMENT_WIRE:
                return 200, {"Content-Type": "application/octet-stream"}, b"wire"
            if raw_path == MEDIA_WIRE:
                return 200, {"Content-Type": "image/png"}, VALID_PNG
            if raw_path == "/api/v1/integrations/client/config":
                return 404, {}, b"missing"
            self.fail(f"unexpected hostile wire request: {raw_path!r}")

        def later_responder(method, raw_path, headers, body):
            parsed = urlsplit(raw_path)
            if parsed.path == "/api/v1/challenges":
                return 200, {}, {
                    "data": [],
                    "meta": {
                        "pagination": {"next": None, "page": 1, "pages": 0}
                    },
                }
            if parsed.path == "/rules":
                return 404, {}, b"missing"
            self.fail(f"unexpected later wire request: {raw_path!r}")

        with (
            tempfile.TemporaryDirectory() as tmp,
            ScenarioServer(hostile_responder) as hostile_server,
            ScenarioServer(later_responder) as later_server,
        ):
            hostile = make_config(
                tmp,
                platform="rctf",
                name="unicode-wire",
                base_url=hostile_server.origin,
            )
            later = make_config(
                tmp,
                name="later-ctf",
                base_url=later_server.origin,
            )
            results = collect_all([hostile, later])
            output_root = Path(tmp) / "out"
            hostile_manifest = json.loads(
                (output_root / "unicode-wire" / "manifest.json").read_text(
                    encoding="utf-8"
                )
            )
            later_manifest = json.loads(
                (output_root / "later-ctf" / "manifest.json").read_text(
                    encoding="utf-8"
                )
            )
            paths = [path.relative_to(output_root).as_posix() for path in output_root.rglob("*")]
            document_bytes = [path.read_bytes() for path in _documents(output_root)]

        self.assertEqual([item["error"] for item in results], [None, None])
        self.assertEqual(hostile_manifest["status"], "complete")
        self.assertEqual(later_manifest["status"], "complete")
        self.assertEqual(
            {item["id"] for item in hostile_manifest["challenges"]},
            {"wire", "later-challenge"},
        )
        requested = [request["path"] for request in hostile_server.requests]
        for expected in (DETAIL_WIRE, ATTACHMENT_WIRE, MEDIA_WIRE):
            self.assertIn(expected, requested)
        self.assertFalse(any("fragment" in path for path in requested))
        for request in hostile_server.requests:
            if request["path"] in {DETAIL_WIRE, ATTACHMENT_WIRE, MEDIA_WIRE}:
                self.assertEqual(
                    request["headers"].get("authorization"),
                    "Bearer rctf-secret",
                )

        wire_challenge = next(
            item for item in hostile_manifest["challenges"] if item["id"] == "wire"
        )
        self.assertEqual(
            wire_challenge["files"][0]["source_identity"],
            _source_identity(hostile_server.origin + ATTACHMENT_WIRE, "rctf-secret"),
        )
        self.assertEqual(
            wire_challenge["media"][0]["source_identity"],
            _source_identity(hostile_server.origin + MEDIA_WIRE, "rctf-secret"),
        )
        for secret in (
            "rctf-secret",
            "ctfd-secret",
            "detail-secret",
            "file-secret",
            "media-secret",
        ):
            encoded = secret.encode("ascii")
            with self.subTest(secret=secret):
                self.assertTrue(all(secret not in path for path in paths))
                self.assertTrue(all(encoded not in document for document in document_bytes))


class StrictJsonNumberTests(unittest.TestCase):
    def test_hostile_numbers_are_invalid_json_and_later_ctf_continues(self):
        cases = {
            "5000_digit_integer": (
                b'{"data":[],"meta":{"credential":"'
                + BODY_CREDENTIAL.encode("ascii")
                + b'","number":'
                + (b"9" * 5000)
                + b"}}"
            ),
            "nan": (
                b'{"data":[],"meta":{"credential":"'
                + BODY_CREDENTIAL.encode("ascii")
                + b'","number":NaN}}'
            ),
            "infinity": (
                b'{"data":[],"meta":{"credential":"'
                + BODY_CREDENTIAL.encode("ascii")
                + b'","number":Infinity}}'
            ),
            "negative_infinity": (
                b'{"data":[],"meta":{"credential":"'
                + BODY_CREDENTIAL.encode("ascii")
                + b'","number":-Infinity}}'
            ),
            "huge_exponent": (
                b'{"data":[],"meta":{"credential":"'
                + BODY_CREDENTIAL.encode("ascii")
                + b'","number":1e99999}}'
            ),
        }

        for label, payload in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmp:
                def responder(request):
                    parsed = urlsplit(request["url"])
                    if parsed.hostname == "numbers.example":
                        return 200, {}, payload
                    if parsed.hostname == "later.example":
                        if parsed.path == "/api/v1/challenges":
                            return 200, {}, {
                                "data": [],
                                "meta": {
                                    "pagination": {
                                        "next": None,
                                        "page": 1,
                                        "pages": 0,
                                    }
                                },
                            }
                        if parsed.path == "/rules":
                            return 404, {}, b"missing"
                    self.fail(f"unexpected request: {request['url']}")

                hostile = make_config(
                    tmp,
                    name="numbers",
                    base_url="https://numbers.example",
                )
                later = make_config(
                    tmp,
                    name="later",
                    base_url="https://later.example",
                )
                fake = FakeOpener(responder)
                with patch("ctf_collector.http.build_opener", return_value=fake):
                    results = collect_all([hostile, later])

                error = results[0]["error"]
                self.assertEqual(getattr(error, "code", None), "invalid_json")
                self.assertNotIn(BODY_CREDENTIAL, error.message)
                self.assertNotIn("ValueError", error.message)
                self.assertIsNone(results[1]["error"])
                later_manifest_text = (
                    Path(tmp) / "out" / "later" / "manifest.json"
                ).read_text(encoding="utf-8")
                self.assertEqual(json.loads(later_manifest_text)["status"], "complete")
                for document in _documents(Path(tmp) / "out"):
                    contents = document.read_bytes()
                    self.assertNotIn(BODY_CREDENTIAL.encode("ascii"), contents)
                    self.assertNotIn(b"ValueError", contents)

    def test_programmatic_nonfinite_metadata_is_item_failure_and_later_item_survives(self):
        def get_json(_client, url, *, authenticated=True):
            path = urlsplit(url).path
            if path == "/api/v1/challenges":
                return {
                    "data": [
                        {"id": 1, "name": "Nonfinite", "category": "misc"},
                        {"id": 2, "name": "Later item", "category": "web"},
                    ],
                    "meta": {
                        "pagination": {"next": None, "page": 1, "pages": 1}
                    },
                }, url
            if path == "/api/v1/challenges/1":
                return {
                    "data": {
                        "id": 1,
                        "name": "Nonfinite",
                        "category": "misc",
                        "points": float("inf"),
                        "note": PROGRAMMATIC_CREDENTIAL,
                        "files": [],
                    }
                }, url
            if path == "/api/v1/challenges/2":
                return {
                    "data": {
                        "id": 2,
                        "name": "Later item",
                        "category": "web",
                        "description": "later item retained",
                        "files": [],
                    }
                }, url
            self.fail(f"unexpected JSON request: {url}")

        def get_text(_client, url, *, accepted_types, authenticated=True):
            raise CollectorError("http_error", "HTTP 404 for GET request", status=404)

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            with (
                patch.object(HttpClient, "get_json", get_json),
                patch.object(HttpClient, "get_text", get_text),
            ):
                manifest = collect_ctf(config)
            manifest_text = (
                Path(tmp) / "out" / "fake-ctfd" / "manifest.json"
            ).read_text(encoding="utf-8")

        self.assertEqual(manifest["status"], "partial")
        self.assertEqual([item["id"] for item in manifest["challenges"]], ["2"])
        self.assertEqual(
            [failure["error"]["code"] for failure in manifest["failures"]],
            ["invalid_api_data"],
        )
        self.assertNotIn(PROGRAMMATIC_CREDENTIAL, manifest_text)
        self.assertNotIn("Infinity", manifest_text)

    def test_safe_metadata_and_atomic_json_reject_direct_nonfinite_values(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                with self.assertRaises(CollectorError) as caught:
                    safe_metadata({"value": value, "note": PROGRAMMATIC_CREDENTIAL})
                self.assertEqual(caught.exception.code, "invalid_api_data")
                self.assertNotIn(
                    PROGRAMMATIC_CREDENTIAL,
                    caught.exception.message,
                )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            with SafeOutput(root) as output:
                output.atomic_json(("metadata.json",), {"value": 1})
                original = (root / "metadata.json").read_bytes()
                for value in (float("nan"), float("inf"), float("-inf")):
                    with self.subTest(write=value):
                        with self.assertRaises(ValueError) as caught:
                            output.atomic_json(
                                ("metadata.json",),
                                {"value": value, "note": WRITE_CREDENTIAL},
                            )
                        self.assertNotIn(
                            WRITE_CREDENTIAL,
                            str(caught.exception),
                        )
                        self.assertEqual(
                            (root / "metadata.json").read_bytes(),
                            original,
                        )
                        self.assertFalse(
                            (root / ".metadata.json.part").exists()
                        )


if __name__ == "__main__":
    unittest.main()
