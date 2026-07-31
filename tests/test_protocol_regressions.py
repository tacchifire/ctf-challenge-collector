from email.message import Message
from io import BytesIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import urlsplit

from ctf_collector.collector import collect_ctf
from ctf_collector.errors import CollectorError

from .support import FakeOpener, make_config


class BoundedErrorBody(BytesIO):
    def __init__(self, body, maximum):
        super().__init__(body)
        self.maximum = maximum
        self.read_sizes = []

    def read(self, size=-1):
        self.read_sizes.append(size)
        if size < 0 or size > self.maximum + 1:
            raise AssertionError("HTTP error body was not read with the metadata bound")
        return super().read(size)


class RctfProtocolTests(unittest.TestCase):
    def unauthorized_error(self, url, kind, stream):
        headers = Message()
        headers["Content-Type"] = "application/json"
        return HTTPError(url, 401, "Unauthorized", headers, stream)

    def test_401_envelope_kinds_are_distinct_bounded_and_not_retried(self):
        cases = (
            ("badNotStarted", "rctf_not_started"),
            ("badToken", "auth_error"),
        )
        for kind, expected_code in cases:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                maximum = 1024
                body = BoundedErrorBody(
                    json.dumps({"kind": kind, "message": f"{kind} message"}).encode(),
                    maximum,
                )

                def responder(request):
                    return self.unauthorized_error(request["url"], kind, body)

                config = make_config(tmp, platform="rctf")
                config["limits"]["max_metadata_bytes"] = maximum
                config["retries"]["max_attempts"] = 3
                fake = FakeOpener(responder)
                with (
                    patch("ctf_collector.http.build_opener", return_value=fake),
                    self.assertRaises(CollectorError) as caught,
                ):
                    collect_ctf(config)

                self.assertEqual(caught.exception.code, expected_code)
                self.assertEqual(caught.exception.status, 401)
                self.assertEqual(
                    [urlsplit(item["url"]).path for item in fake.requests],
                    ["/api/v1/challs"],
                    "a 401 must be neither retried nor treated as a fallback-route 404",
                )
                self.assertEqual(body.read_sizes, [maximum + 1])

    def test_official_list_is_complete_and_does_not_fetch_detail_links(self):
        def responder(request):
            path = urlsplit(request["url"]).path
            if path == "/api/v1/challs":
                return 200, {}, {
                    "kind": "goodChallenges",
                    "data": [
                        {
                            "id": "official",
                            "name": "Complete",
                            "category": "misc",
                            "description": "already complete",
                            "detail_url": "/api/v1/challs/official",
                            "files": [],
                        }
                    ],
                }
            if path == "/api/v1/challs/official":
                return 404, {}, b"there is no official detail route"
            return 404, {}, b"missing"

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp, platform="rctf")
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)

            self.assertEqual(manifest["status"], "complete")
            self.assertEqual(
                [urlsplit(item["url"]).path for item in fake.requests],
                [
                    "/api/v1/challs",
                    "/api/v1/integrations/client/config",
                ],
            )
            metadata_path = (
                Path(tmp)
                / "out"
                / "fake-rctf"
                / "misc"
                / "official-Complete"
                / "challenge.json"
            )
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            self.assertEqual(metadata["raw"]["description"], "already complete")

    def test_fork_list_fallback_still_follows_explicit_same_origin_detail(self):
        def responder(request):
            path = urlsplit(request["url"]).path
            if path == "/api/v1/challs":
                return 404, {}, b"missing"
            if path == "/api/v1/challenges":
                return 200, {}, {
                    "data": [
                        {
                            "id": "fork",
                            "name": "Fork",
                            "category": "web",
                            "_links": {"detail": {"href": "/api/v1/challenges/fork"}},
                        }
                    ]
                }
            if path == "/api/v1/challenges/fork":
                return 200, {}, {
                    "data": {
                        "id": "fork",
                        "name": "Fork",
                        "category": "web",
                        "description": "fork detail",
                        "files": [],
                    }
                }
            return 404, {}, b"missing"

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp, platform="rctf")
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)

            self.assertEqual(manifest["status"], "complete")
            self.assertEqual(
                [urlsplit(item["url"]).path for item in fake.requests],
                [
                    "/api/v1/challs",
                    "/api/v1/challenges",
                    "/api/v1/challenges/fork",
                    "/api/v1/integrations/client/config",
                ],
            )

    def test_official_list_rejects_non_good_challenges_success_kind(self):
        def responder(request):
            if urlsplit(request["url"]).path == "/api/v1/challs":
                return 200, {}, {
                    "kind": "badToken",
                    "data": [{"id": "unsafe", "name": "Unsafe", "category": "misc"}],
                }
            return 404, {}, b"missing"

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp, platform="rctf")
            fake = FakeOpener(responder)
            with (
                patch("ctf_collector.http.build_opener", return_value=fake),
                self.assertRaises(CollectorError) as caught,
            ):
                collect_ctf(config)

            self.assertEqual(caught.exception.code, "invalid_api_data")
            self.assertIn("goodChallenges", caught.exception.message)


class CtfdHiddenSummaryTests(unittest.TestCase):
    def test_detail_is_merged_over_summary_without_losing_list_only_metadata(self):
        def responder(request):
            path = urlsplit(request["url"]).path
            if path == "/api/v1/challenges":
                return 200, {}, {
                    "data": [
                        {
                            "id": 1,
                            "name": "Summary",
                            "category": "web",
                            "list_only": "preserved",
                        }
                    ],
                    "meta": {
                        "pagination": {
                            "page": 1,
                            "pages": 1,
                            "next": None,
                        }
                    },
                }
            if path == "/api/v1/challenges/1":
                return 200, {}, {
                    "data": {
                        "id": 1,
                        "name": "Detail",
                        "category": "web",
                        "description": "detail wins",
                        "files": [],
                    }
                }
            return 404, {}, b"missing"

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)

            metadata_path = (
                Path(tmp)
                / "out"
                / "fake-ctfd"
                / "web"
                / "1-Detail"
                / "challenge.json"
            )
            raw = json.loads(metadata_path.read_text(encoding="utf-8"))["raw"]
            self.assertEqual(manifest["status"], "complete")
            self.assertEqual(raw["list_only"], "preserved")
            self.assertEqual(raw["description"], "detail wins")

    def test_hidden_summary_records_inaccessible_failure_without_detail_get(self):
        def responder(request):
            path = urlsplit(request["url"]).path
            if path == "/api/v1/challenges":
                return 200, {}, {
                    "data": [
                        {
                            "id": 0,
                            "name": "Hidden",
                            "category": "hidden",
                            "type": "hidden",
                        }
                    ],
                    "meta": {
                        "pagination": {
                            "page": 1,
                            "pages": 1,
                            "next": None,
                        }
                    },
                }
            if path == "/api/v1/challenges/0":
                return 200, {}, {
                    "data": {
                        "id": 99,
                        "name": "Bogus detail",
                        "category": "hidden",
                    }
                }
            return 404, {}, b"missing"

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)

            self.assertEqual(manifest["status"], "partial")
            self.assertEqual(
                manifest["failures"],
                [
                    {
                        "challenge_id": "0",
                        "error": {
                            "code": "challenge_inaccessible",
                            "message": "hidden challenge summary is not accessible",
                        },
                    }
                ],
            )
            self.assertEqual(
                [urlsplit(item["url"]).path for item in fake.requests],
                ["/api/v1/challenges", "/rules"],
            )
            self.assertEqual(manifest["challenges"][0]["id"], "0")
            self.assertEqual(manifest["challenges"][0]["name"], "Hidden")


if __name__ == "__main__":
    unittest.main()
