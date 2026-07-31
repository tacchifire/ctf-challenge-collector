"""Gate cycle 15 regressions added before their fixes."""

from html.parser import HTMLParser
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from ctf_collector.archive import render_challenge_html, render_rules_html
from ctf_collector import collector
from ctf_collector.collector import (
    _trusted_html_for_storage,
    collect_all,
    collect_ctf,
)
from ctf_collector.errors import CollectorError
from ctf_collector.safety import safe_json_text

from .support import FakeOpener, make_config


VALID_PNG = b"\x89PNG\r\n\x1a\ncycle fifteen"
IMPOSSIBLE_JSON_CREDENTIALS = (
    "null",
    "true",
    "false",
    "{",
    "}",
    "[",
    "]",
    ":",
    ",",
    '"',
    "\\",
    "u",
    "0000",
    "12",
    "1e9",
    "-2.3E+4",
)


def _config(tmp, *, platform, name, host, token):
    token_file = Path(tmp) / f"{host}.token"
    token_file.write_text(token + "\n", encoding="ascii")
    return make_config(
        tmp,
        platform=platform,
        name=name,
        base_url=f"https://{host}",
        token_file=token_file,
    )


def _response(platform, path, challenge=None):
    if platform == "ctfd":
        if path == "/api/v1/challenges":
            summaries = [] if challenge is None else [
                {key: challenge[key] for key in ("id", "name", "category")}
            ]
            return 200, {}, {
                "data": summaries,
                "meta": {
                    "pagination": {
                        "next": None,
                        "page": 1,
                        "pages": 1 if summaries else 0,
                    }
                },
            }
        if path == "/api/v1/challenges/1" and challenge is not None:
            return 200, {}, {"data": challenge}
        if path == "/rules":
            return 404, {}, b"missing"
    else:
        if path == "/api/v1/challs":
            return 200, {}, {
                "kind": "goodChallenges",
                "data": [] if challenge is None else [challenge],
            }
        if path == "/api/v1/integrations/client/config":
            return 404, {}, b"missing"
    raise AssertionError(f"unexpected {platform} request: {path!r}")


class _Events(HTMLParser):
    """DOM-relevant HTMLParser events, including decoded CSP attributes."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.events = []

    def handle_decl(self, decl):
        self.events.append(("decl", decl))

    def handle_starttag(self, tag, attrs):
        self.events.append(("start", tag, tuple(attrs)))

    def handle_startendtag(self, tag, attrs):
        self.events.append(("startend", tag, tuple(attrs)))

    def handle_endtag(self, tag):
        self.events.append(("end", tag))

    def handle_data(self, data):
        self.events.append(("data", data))

    def handle_comment(self, data):
        self.events.append(("comment", data))


def _events(source):
    parser = _Events()
    parser.feed(source)
    parser.close()
    return parser.events


class JsonSemanticSerializationTests(unittest.TestCase):
    def test_strings_keys_controls_overlap_substrings_and_nfkc_round_trip(self):
        value = {
            "alpha": "alpha/pha/Ａ/A",
            "controls": "\x00\b\f\n\r\t quote=\" slash=\\",
            "nested": [{"pha": "alphabet"}],
            "integer": 12,
            "boolean": True,
            "nothing": None,
        }
        secrets = ("alpha", "pha", "Ａ")

        payload = safe_json_text(value, secrets)

        self.assertEqual(json.loads(payload), value)
        self.assertIs(type(json.loads(payload)["integer"]), int)
        self.assertIs(json.loads(payload)["boolean"], True)
        self.assertIsNone(json.loads(payload)["nothing"])
        for spelling in ("alpha", "pha", "Ａ", "A"):
            self.assertNotIn(spelling.encode("utf-8"), payload.encode("utf-8"))

    def test_short_json_control_escape_letters_do_not_change_values(self):
        controls = "\b\f\n\r\t"
        for credential in ("b", "f", "n", "r", "t"):
            with self.subTest(credential=credential):
                value = {credential: f"{credential}:{controls}:{credential}"}
                payload = safe_json_text(value, (credential,))
                self.assertEqual(json.loads(payload), value)
                self.assertNotIn(credential.encode("ascii"), payload.encode("utf-8"))

    def test_control_uses_short_escape_when_both_hex_cases_are_credentials(self):
        value = {"value": "line one\nline two"}
        payload = safe_json_text(value, ("000A", "000a"))
        self.assertEqual(json.loads(payload), value)
        self.assertNotIn(b"000A", payload.encode("utf-8"))
        self.assertNotIn(b"000a", payload.encode("utf-8"))

    def test_reviewer_0000_nul_repro_is_a_bounded_valid_refusal(self):
        with self.assertRaises(CollectorError) as caught:
            safe_json_text({"value": "\x00"}, ("0000",))
        self.assertEqual(caught.exception.code, "unsafe_credential")
        self.assertNotIn("0000", caught.exception.message)
        self.assertLessEqual(len(caught.exception.message), 120)

    def test_quote_and_backslash_overlap_never_returns_malformed_json(self):
        for credential in ('"', "\\"):
            with self.subTest(credential=credential):
                with self.assertRaises(CollectorError) as caught:
                    safe_json_text({"value": 'quote=" slash=\\'}, (credential,))
                self.assertNotIn(credential, caught.exception.code)
                self.assertNotIn(credential, caught.exception.message)

    def test_isolated_surrogate_is_a_bounded_credential_safe_refusal(self):
        for credential in ("ordinary-secret", "u", "invalid_output"):
            with self.subTest(credential=credential):
                with self.assertRaises(CollectorError) as caught:
                    safe_json_text({"k": "\ud800"}, (credential,))
                self.assertLessEqual(len(caught.exception.code), 64)
                self.assertLessEqual(len(caught.exception.message), 120)
                self.assertNotIn(credential, caught.exception.code)
                self.assertNotIn(credential, caught.exception.message)


class JsonGrammarPreflightTests(unittest.TestCase):
    def test_ctfd_and_rctf_current_impossible_credentials_are_per_ctf_results(self):
        for platform in ("ctfd", "rctf"):
            for credential in IMPOSSIBLE_JSON_CREDENTIALS:
                with (
                    self.subTest(platform=platform, credential=credential),
                    tempfile.TemporaryDirectory() as tmp,
                ):
                    first = _config(
                        tmp,
                        platform=platform,
                        name="zero",
                        host="zero.example",
                        token=credential,
                    )
                    later = _config(
                        tmp,
                        platform=platform,
                        name="later",
                        host="later.example",
                        token="ordinary-later-secret",
                    )
                    fake = FakeOpener(
                        lambda request: self.fail("preflight must precede HTTP")
                    )
                    with patch("ctf_collector.http.build_opener", return_value=fake):
                        results = collect_all([first, later])

                    self.assertEqual(len(results), 2)
                    self.assertTrue(all(result["error"] is not None for result in results))
                    self.assertEqual(fake.requests, [])
                    self.assertFalse((Path(tmp) / "out").exists())
                    for result in results:
                        error = result["error"]
                        self.assertNotIn(credential, error.code)
                        self.assertNotIn(credential, error.message)
                        self.assertLessEqual(len(error.code), 64)
                        self.assertLessEqual(len(error.message), 120)

    def test_direct_preflight_keeps_generated_numbers_typed(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = _config(
                tmp,
                platform="ctfd",
                name="direct",
                host="direct.example",
                token="12",
            )
            fake = FakeOpener(lambda request: self.fail("HTTP must not be attempted"))
            with (
                patch("ctf_collector.http.build_opener", return_value=fake),
                self.assertRaises(CollectorError),
            ):
                collect_ctf(config)
            self.assertEqual(fake.requests, [])
            self.assertFalse((Path(tmp) / "out").exists())


class HtmlSemanticSerializationTests(unittest.TestCase):
    def test_existing_entity_substrings_are_refused_without_rewriting(self):
        source = '<p title="&amp;">&#x27; &amp; safe</p>'
        for credential in ("x27", "#x27", "amp"):
            with self.subTest(credential=credential):
                with self.assertRaises(CollectorError) as caught:
                    _trusted_html_for_storage(source, (credential,))
                self.assertEqual(caught.exception.code, "unsafe_credential")
                self.assertNotIn(credential, caught.exception.message)

    def test_script_and_style_quoted_syntax_is_not_an_attribute_value(self):
        source = (
            '<script>const value="alpha";</script>'
            '<style>x[data-note="alpha"]{color:red}</style>'
        )
        with self.assertRaises(CollectorError):
            _trusted_html_for_storage(source, ("alpha",))

    def test_comment_quoted_syntax_is_not_an_attribute_value(self):
        with self.assertRaises(CollectorError):
            _trusted_html_for_storage('<!-- note="alpha" -->', ("alpha",))

    def test_complete_text_and_quoted_attribute_occurrences_preserve_events(self):
        source = '<main data-note="alpha/pha"><p>alpha/pha</p></main>'
        transformed = _trusted_html_for_storage(source, ("alpha", "pha"))
        self.assertEqual(_events(transformed), _events(source))
        self.assertNotIn(b"alpha", transformed.encode("utf-8"))
        self.assertNotIn(b"pha", transformed.encode("utf-8"))

    def test_all_render_branches_preserve_dom_text_and_csp(self):
        challenge = {
            "category": "alpha",
            "connection_info": "alpha",
            "description": "alpha & ordinary",
            "hints": ["alpha"],
            "id": "alpha",
            "name": "alpha",
            "points": 100,
            "value": 100,
        }
        files = [
            {
                "html_path": "files/alpha.bin",
                "local_path": "files/alpha.bin",
                "status": "downloaded",
            },
            {"local_path": "failed-alpha.bin", "status": "failed"},
        ]
        for media_kind in ("image", "audio", "video"):
            with self.subTest(media_kind=media_kind):
                source = render_challenge_html(
                    challenge,
                    files,
                    [
                        {
                            "html_path": f"media/alpha-{media_kind}",
                            "media_kind": media_kind,
                            "status": "downloaded",
                        }
                    ],
                )
                transformed = _trusted_html_for_storage(source, ("alpha",))
                self.assertEqual(_events(transformed), _events(source))
                self.assertNotIn(b"alpha", transformed.encode("utf-8"))

        rules = render_rules_html("alpha & ordinary")
        transformed_rules = _trusted_html_for_storage(rules, ("alpha",))
        self.assertEqual(_events(transformed_rules), _events(rules))
        self.assertNotIn(b"alpha", transformed_rules.encode("utf-8"))

    def test_entity_collisions_are_rejected_by_direct_preflight(self):
        for credential in ("x27", "#x27", "amp"):
            with self.subTest(credential=credential), tempfile.TemporaryDirectory() as tmp:
                config = _config(
                    tmp,
                    platform="ctfd",
                    name="direct",
                    host="direct.example",
                    token=credential,
                )
                fake = FakeOpener(lambda request: self.fail("HTTP must not be attempted"))
                with (
                    patch("ctf_collector.http.build_opener", return_value=fake),
                    self.assertRaises(CollectorError),
                ):
                    collect_ctf(config)
                self.assertEqual(fake.requests, [])
                self.assertFalse((Path(tmp) / "out").exists())


class PerCtfAndPerItemScopeTests(unittest.TestCase):
    def test_global_config_directory_collision_remains_global(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = _config(
                tmp,
                platform="ctfd",
                name="same/name",
                host="one.example",
                token="first-secret",
            )
            second = _config(
                tmp,
                platform="rctf",
                name="same_name",
                host="two.example",
                token="second-secret",
            )
            with self.assertRaises(CollectorError) as caught:
                collect_all([first, second])
            self.assertEqual(caught.exception.code, "invalid_config")

    def test_manifest_path_credential_returns_each_ctf_result_without_global_abort(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = _config(
                tmp,
                platform="ctfd",
                name="first",
                host="first.example",
                token="ordinary-first-secret",
            )
            second = _config(
                tmp,
                platform="rctf",
                name="second",
                host="second.example",
                token="manifest.json",
            )
            fake = FakeOpener(lambda request: self.fail("HTTP must not be attempted"))
            with patch("ctf_collector.http.build_opener", return_value=fake):
                results = collect_all([first, second])

            self.assertEqual(len(results), 2)
            self.assertTrue(all(result["error"] is not None for result in results))
            self.assertEqual(fake.requests, [])
            self.assertFalse((Path(tmp) / "out").exists())
            for result in results:
                self.assertNotIn("manifest.json", result["error"].code)
                self.assertNotIn("manifest.json", result["error"].message)

    def test_other_files_or_media_token_is_item_partial_in_both_positions(self):
        for platform in ("ctfd", "rctf"):
            for kind in ("files", "media"):
                for target_first in (True, False):
                    with (
                        self.subTest(
                            platform=platform,
                            kind=kind,
                            target_first=target_first,
                        ),
                        tempfile.TemporaryDirectory() as tmp,
                    ):
                        target_host = f"target-{platform}.example"
                        blocked_host = f"blocked-{platform}.example"
                        target = _config(
                            tmp,
                            platform=platform,
                            name="target",
                            host=target_host,
                            token="ordinary-target-secret",
                        )
                        blocked = _config(
                            tmp,
                            platform=platform,
                            name="blocked",
                            host=blocked_host,
                            token=kind,
                        )
                        challenge = {
                            "id": 1,
                            "name": "One",
                            "category": "web",
                            "description": (
                                '<img src="/pixel.png">' if kind == "media" else "body"
                            ),
                            "files": (
                                [{"name": "handout.bin", "url": "/handout.bin"}]
                                if kind == "files"
                                else []
                            ),
                        }

                        def responder(request):
                            parsed = urlsplit(request["url"])
                            if parsed.hostname == blocked_host:
                                self.fail("the current impossible CTF must not use HTTP")
                            if parsed.path in {"/handout.bin", "/pixel.png"}:
                                self.fail("unsafe item path must fail before download")
                            return _response(platform, parsed.path, challenge)

                        configs = [target, blocked] if target_first else [blocked, target]
                        fake = FakeOpener(responder)
                        with patch("ctf_collector.http.build_opener", return_value=fake):
                            results = collect_all(configs)

                        by_name = {result["name"]: result for result in results}
                        self.assertEqual(len(results), 2)
                        self.assertIsNone(by_name["target"]["error"])
                        self.assertTrue(by_name["target"]["partial"])
                        self.assertIsNotNone(by_name["blocked"]["error"])

                        root = Path(tmp) / "out" / "target"
                        manifest_path = root / "manifest.json"
                        self.assertTrue(manifest_path.is_file())
                        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                        self.assertEqual(manifest["status"], "partial")
                        self.assertEqual(len(manifest["challenges"]), 1)
                        entries = manifest["challenges"][0][kind]
                        self.assertEqual(len(entries), 1)
                        self.assertEqual(entries[0]["status"], "failed")
                        self.assertIn("failure", entries[0])
                        self.assertFalse(any(path.name == kind for path in root.rglob("*")))
                        self.assertFalse((Path(tmp) / "out" / "blocked").exists())


class CredentialSafeFailureTests(unittest.TestCase):
    def test_dynamic_error_fields_cover_one_character_credentials(self):
        for credential in ("a", "e", "n"):
            with self.subTest(credential=credential), tempfile.TemporaryDirectory() as tmp:
                config = _config(
                    tmp,
                    platform="ctfd",
                    name="0",
                    host="zero.example",
                    token=credential,
                )
                progress = []
                fake = FakeOpener(lambda request: self.fail("HTTP must not be attempted"))
                with patch("ctf_collector.http.build_opener", return_value=fake):
                    result = collect_all([config], progress=progress.append)[0]

                error = result["error"]
                self.assertIsNotNone(error)
                self.assertNotIn(credential, error.code)
                self.assertNotIn(credential, error.message)
                self.assertLessEqual(len(error.code), 64)
                self.assertLessEqual(len(error.message), 120)
                for event in progress:
                    for value in event.values():
                        self.assertNotIn(credential, str(value))

    def test_all_visible_ascii_has_empty_fail_safe_fields(self):
        secrets = tuple(chr(codepoint) for codepoint in range(33, 127))
        error = getattr(collector, "_credential_safe_error")(
            "unsafe_credential",
            "authentication credential conflicts with the required output contract",
            secrets,
        )
        self.assertEqual(error.code, "")
        self.assertEqual(error.message, "")

    def test_direct_ctf_name_refusal_has_credential_safe_fields(self):
        credential = "name"
        with tempfile.TemporaryDirectory() as tmp:
            config = _config(
                tmp,
                platform="ctfd",
                name="event-name-collision",
                host="direct.example",
                token=credential,
            )
            fake = FakeOpener(lambda request: self.fail("HTTP must not be attempted"))
            with (
                patch("ctf_collector.http.build_opener", return_value=fake),
                self.assertRaises(CollectorError) as caught,
            ):
                collect_ctf(config)

            self.assertNotIn(credential, caught.exception.code)
            self.assertNotIn(credential, caught.exception.message)
            self.assertEqual(fake.requests, [])
            self.assertFalse((Path(tmp) / "out").exists())

    def test_progress_and_persisted_item_failure_use_safe_dynamic_fields(self):
        credential = "http_error"
        with tempfile.TemporaryDirectory() as tmp:
            config = _config(
                tmp,
                platform="ctfd",
                name="zero",
                host="zero.example",
                token=credential,
            )
            challenge = {
                "id": 1,
                "name": "One",
                "category": "web",
                "description": "body",
                "files": [{"name": "handout.bin", "url": "/handout.bin"}],
            }

            def responder(request):
                path = urlsplit(request["url"]).path
                if path == "/handout.bin":
                    return 500, {}, b"failed"
                return _response("ctfd", path, challenge)

            progress = []
            fake = FakeOpener(responder)
            with patch("ctf_collector.http.build_opener", return_value=fake):
                result = collect_all([config], progress=progress.append)[0]

            self.assertIsNone(result["error"])
            self.assertTrue(result["partial"])
            manifest_path = Path(tmp) / "out" / "zero" / "manifest.json"
            manifest_bytes = manifest_path.read_bytes()
            manifest = json.loads(manifest_bytes)
            failure = manifest["challenges"][0]["files"][0]["failure"]
            self.assertNotIn(credential, failure["code"])
            self.assertNotIn(credential, failure["message"])
            self.assertLessEqual(len(failure["code"]), 64)
            self.assertLessEqual(len(failure["message"]), 120)
            self.assertNotIn(credential.encode("ascii"), manifest_bytes)
            self.assertNotIn(credential, json.dumps(progress, sort_keys=True))

    def test_ordinary_token_preserves_standard_error_code(self):
        error = getattr(collector, "_credential_safe_error")(
            "unsafe_credential",
            "authentication credential conflicts with the required output contract",
            ("ordinary-secret",),
        )
        self.assertEqual(error.code, "unsafe_credential")
        self.assertLessEqual(len(error.message), 120)


if __name__ == "__main__":
    unittest.main()
