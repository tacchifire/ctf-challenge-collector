"""CTFd 3.8.6 only reads Authorization on GET when the request is JSON.

`CTFd.utils.initialization.init_request_processors` looks up the API token via
`request.headers.get("Authorization")` only inside the `request.is_json` branch,
and Flask's `is_json` is driven purely by the request Content-Type.  A token GET
without `Content-Type: application/json` is therefore treated as anonymous.
Attachment downloads are plain byte streams and must not claim a JSON body.
"""

import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from ctf_collector.collector import collect_ctf

from .support import FakeOpener, make_config


def api_requests(fake):
    return [
        item for item in fake.requests
        if urlsplit(item["url"]).path.startswith("/api/")
    ]


def requests_for(fake, path):
    return [item for item in fake.requests if urlsplit(item["url"]).path == path]


class ApiContentTypeTests(unittest.TestCase):
    def ctfd_responder(self, request):
        parsed = urlsplit(request["url"])
        if parsed.path == "/api/v1/challenges":
            return 200, {}, {
                "data": [{"id": 1, "name": "One", "category": "web"}],
                "meta": {
                    "pagination": {
                        "page": 1,
                        "pages": 1,
                        "next": None,
                    }
                },
            }
        if parsed.path == "/api/v1/challenges/1":
            return 200, {}, {
                "data": {
                    "id": 1,
                    "name": "One",
                    "category": "web",
                    "files": [
                        "/files/local.bin",
                        "https://cdn.example/remote.bin",
                    ],
                }
            }
        if parsed.path in ("/files/local.bin", "/remote.bin"):
            return 200, {}, b"payload"
        return 404, {}, b"missing"

    def collect(self, platform="ctfd", responder=None, **overrides):
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp, platform=platform, **overrides)
            fake = FakeOpener(responder or self.ctfd_responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)
            return fake, manifest

    def test_ctfd_api_gets_declare_json_content_type(self):
        fake, manifest = self.collect(
            unauthenticated_attachment_origins=["https://cdn.example"],
        )

        self.assertEqual(manifest["status"], "complete")
        self.assertTrue(api_requests(fake))
        for item in api_requests(fake):
            self.assertEqual(
                item["headers"].get("content-type"),
                "application/json",
                f"{item['url']} must be JSON for CTFd to honour the token",
            )
            self.assertEqual(item["headers"].get("authorization"), "Token ctfd-secret")

    def test_rctf_api_gets_declare_json_content_type(self):
        def responder(request):
            if urlsplit(request["url"]).path == "/api/v1/challs":
                return 200, {}, {
                    "kind": "goodChallenges",
                    "message": "Challenge listing retrieved.",
                    "data": [{"id": "a", "name": "A", "category": "misc"}],
                }
            return 404, {}, b"missing"

        fake, manifest = self.collect(platform="rctf", responder=responder)

        self.assertEqual(manifest["status"], "complete")
        self.assertTrue(api_requests(fake))
        for item in api_requests(fake):
            self.assertEqual(item["headers"].get("content-type"), "application/json")

    def test_same_origin_attachment_get_sends_no_json_content_type(self):
        fake, _ = self.collect(
            unauthenticated_attachment_origins=["https://cdn.example"],
        )

        downloads = requests_for(fake, "/files/local.bin")
        self.assertEqual(len(downloads), 1)
        self.assertIsNone(downloads[0]["headers"].get("content-type"))
        # Same-origin downloads still need the token to reach gated files.
        self.assertEqual(downloads[0]["headers"].get("authorization"), "Token ctfd-secret")

    def test_foreign_attachment_get_sends_neither_authorization_nor_content_type(self):
        fake, _ = self.collect(
            unauthenticated_attachment_origins=["https://cdn.example"],
        )

        foreign = [
            item for item in fake.requests
            if urlsplit(item["url"]).hostname == "cdn.example"
        ]
        self.assertEqual(len(foreign), 1)
        self.assertNotIn("authorization", foreign[0]["headers"])
        self.assertIsNone(foreign[0]["headers"].get("content-type"))


if __name__ == "__main__":
    unittest.main()
