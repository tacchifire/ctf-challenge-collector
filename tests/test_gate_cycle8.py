"""Gate cycle 8 regressions added before their fixes."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from ctf_collector.archive import redact_rules_values
from ctf_collector.collector import _read_old_manifest, collect_all
from ctf_collector.errors import CollectorError
from ctf_collector.http import HttpClient
from ctf_collector.safety import WITHHELD, safe_metadata

from .support import FakeOpener, FakeResponse, make_config


NESTED_JSON_LIMIT = 120 * 1024
BODY_CREDENTIAL = "HOSTILE-BODY-CREDENTIAL"
COMPOUND_KEY_PARTS = (
    ("access", "token"),
    ("session", "token"),
    ("auth", "token"),
    ("csrf", "token"),
    ("user", "token"),
    ("authorization", "token"),
    ("password", "hash"),
    ("secret", "value"),
    ("cookie", "data"),
    ("user", "name"),
    ("api", "key"),
)


def deeply_nested_json():
    depth = 1_100
    leaf = json.dumps(BODY_CREDENTIAL).encode("utf-8")
    padding = b" " * (NESTED_JSON_LIMIT - (2 * depth) - len(leaf))
    payload = (b"[" * depth) + padding + leaf + (b"]" * depth)
    if len(payload) != NESTED_JSON_LIMIT:
        raise AssertionError("nested JSON fixture must remain exactly size bounded")
    return payload


def compound_key_forms(first, second):
    camel = first + second.title()
    entity = first + f"&#{ord(second[0].upper())};" + second[1:]
    return (
        (first + second, first + second),
        (camel, camel),
        (f"{first}_{second}", f"{first}_{second}"),
        (f"{first}-{second}", f"{first}-{second}"),
        (entity, camel),
    )


def make_client(opener, *, platform="ctfd"):
    with patch("ctf_collector.http.build_opener", return_value=opener):
        return HttpClient(
            "https://base.example",
            "REQUEST-CREDENTIAL",
            "Token" if platform == "ctfd" else "Bearer",
            platform,
            [],
            1.0,
            {
                "max_attempts": 1,
                "backoff_seconds": 0.0,
                "max_retry_after_seconds": 0.0,
            },
            {"verify": True},
            {
                "max_redirects": 3,
                "max_metadata_bytes": NESTED_JSON_LIMIT,
            },
        )


class JsonRecursionTests(unittest.TestCase):
    def test_get_json_converts_bounded_recursion_error_without_disclosing_body(self):
        payload = deeply_nested_json()
        client = make_client(FakeOpener(lambda _request: (200, {}, payload)))

        with self.assertRaises(CollectorError) as caught:
            client.get_json("https://base.example/api/v1/challenges")

        self.assertEqual(caught.exception.code, "invalid_json")
        self.assertNotIn(BODY_CREDENTIAL, caught.exception.message)
        self.assertNotIn("REQUEST-CREDENTIAL", caught.exception.message)

    def test_rctf_unauthorized_ignores_bounded_unparseable_envelope(self):
        payload = deeply_nested_json()
        client = make_client(FakeOpener(lambda _request: None), platform="rctf")
        response = FakeResponse(payload, status=401)

        classified = client._rctf_unauthorized(response, 401)

        self.assertIsNone(classified)

    def test_read_old_manifest_ignores_bounded_recursive_json(self):
        payload = deeply_nested_json()

        class OldManifestOutput:
            def read_bytes(self, parts):
                self.parts = parts
                return payload

        output = OldManifestOutput()

        self.assertEqual(
            _read_old_manifest(output, ("event", "manifest.json")),
            {},
        )
        self.assertEqual(output.parts, ("event", "manifest.json"))

    def test_collect_all_records_invalid_json_and_continues_to_later_manifest(self):
        payload = deeply_nested_json()

        def responder(request):
            parsed = urlsplit(request["url"])
            if parsed.hostname == "hostile.example":
                return 200, {}, payload
            if parsed.hostname == "later.example" and parsed.path == "/api/v1/challenges":
                return 200, {}, {
                    "data": [],
                    "meta": {
                        "pagination": {"next": None, "page": 1, "pages": 0}
                    },
                }
            return 404, {}, b"missing"

        with tempfile.TemporaryDirectory() as tmp:
            hostile = make_config(tmp)
            hostile.update(
                {
                    "name": "hostile",
                    "base_url": "https://hostile.example",
                }
            )
            hostile["limits"]["max_metadata_bytes"] = NESTED_JSON_LIMIT
            later = make_config(tmp)
            later.update(
                {
                    "name": "later",
                    "base_url": "https://later.example",
                }
            )
            later["limits"]["max_metadata_bytes"] = NESTED_JSON_LIMIT
            fake = FakeOpener(responder)

            with patch("ctf_collector.http.build_opener", return_value=fake):
                results = collect_all([hostile, later])

            later_manifest_text = (
                Path(tmp) / "out" / "later" / "manifest.json"
            ).read_text(encoding="utf-8")

        self.assertEqual([item["name"] for item in results], ["hostile", "later"])
        self.assertEqual(results[0]["error"].code, "invalid_json")
        self.assertNotIn(BODY_CREDENTIAL, results[0]["error"].message)
        self.assertNotIn("ctfd-secret", results[0]["error"].message)
        self.assertIsNone(results[1]["error"])
        self.assertFalse(results[1]["partial"])
        self.assertEqual(json.loads(later_manifest_text)["status"], "complete")
        self.assertNotIn(BODY_CREDENTIAL, later_manifest_text)


class CompoundSensitiveKeyTests(unittest.TestCase):
    def test_metadata_redacts_canonical_compound_key_forms(self):
        for first, second in COMPOUND_KEY_PARTS:
            for source_key, stored_key in compound_key_forms(first, second):
                with self.subTest(source_key=source_key):
                    metadata = safe_metadata({source_key: "SENSITIVE-VALUE"})

                    self.assertEqual(list(metadata), [stored_key])
                    self.assertEqual(metadata[stored_key], WITHHELD)

    def test_rules_redact_compound_key_forms_but_preserve_ordinary_content(self):
        assignments = []
        sensitive_values = []
        for first, second in COMPOUND_KEY_PARTS:
            for source_key, _stored_key in compound_key_forms(first, second):
                sensitive = f"CYCLE8-SENSITIVE-{len(sensitive_values)}"
                assignments.append(f"{source_key}={sensitive};")
                sensitive_values.append(sensitive)
        source = " ".join(
            [
                *assignments,
                "monkey=CYCLE8-MONKEY;",
                "accessibility=CYCLE8-ACCESSIBILITY;",
                "Ordinary rules prose remains.",
                "<!-- ordinary comment remains -->",
            ]
        )

        redacted = redact_rules_values(source)

        for sensitive in sensitive_values:
            with self.subTest(sensitive=sensitive):
                self.assertNotIn(sensitive, redacted)
        self.assertIn("monkey=CYCLE8-MONKEY;", redacted)
        self.assertIn("accessibility=CYCLE8-ACCESSIBILITY;", redacted)
        self.assertIn("Ordinary rules prose remains.", redacted)
        self.assertIn("<!-- ordinary comment remains -->", redacted)

    def test_metadata_anchoring_preserves_ordinary_keys_prose_and_comments(self):
        ordinary = {
            "monkey": "banana",
            "accessibility": "public",
            "tokenizer": "ordinary",
            "comment": (
                "Ordinary prose mentions username and monkey. "
                "<!-- comment remains -->"
            ),
        }

        self.assertEqual(safe_metadata(ordinary), ordinary)


if __name__ == "__main__":
    unittest.main()
