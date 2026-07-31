"""Gate cycle 13 regressions added before their fixes."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from ctf_collector.collector import collect_all, collect_ctf
from ctf_collector.errors import CollectorError

from .support import FakeOpener, make_config


SCHEMA_COLLISIONS = (
    "status",
    "complete",
    "partial",
    "challenges",
    "failures",
    "files",
    "media",
    "rules",
    "source_url",
)
PATH_COLLISIONS = {"files", "media", "rules"}
MANIFEST_KEYS = {"challenges", "ctf", "failures", "platform", "rules", "status"}
MANIFEST_CHALLENGE_KEYS = {
    "category",
    "directory",
    "files",
    "html",
    "id",
    "media",
    "name",
}
CHALLENGE_KEYS = {"category", "id", "name", "platform", "raw"}


def _config(tmp, *, platform, name, host, token):
    root = Path(tmp)
    token_file = root / f"{name}.token"
    token_file.write_text(token + "\n", encoding="ascii")
    return make_config(
        tmp,
        platform=platform,
        name=name,
        base_url=f"https://{host}",
        token_file=token_file,
    )


def _response(platform, path, *, challenge):
    if platform == "ctfd":
        if path == "/api/v1/challenges":
            items = (
                [{"id": 1, "name": "One", "category": "web"}]
                if challenge is not None
                else []
            )
            return 200, {}, {
                "data": items,
                "meta": {
                    "pagination": {
                        "next": None,
                        "page": 1,
                        "pages": 1 if items else 0,
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
                "data": [challenge] if challenge is not None else [],
            }
        if path == "/api/v1/integrations/client/config":
            return 404, {}, b"missing"
    raise AssertionError(f"unexpected {platform} request: {path!r}")


def _documents(root):
    return [path for path in root.rglob("*") if path.is_file()]


def _contains_string(value, needle):
    if isinstance(value, dict):
        return any(
            needle in str(key) or _contains_string(item, needle)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_string(item, needle) for item in value)
    return isinstance(value, str) and needle in value


class CurrentCredentialSchemaCollisionTests(unittest.TestCase):
    def test_each_collision_is_safe_and_later_ctf_completes(self):
        for platform in ("ctfd", "rctf"):
            for credential in SCHEMA_COLLISIONS:
                with (
                    self.subTest(platform=platform, credential=credential),
                    tempfile.TemporaryDirectory() as tmp,
                ):
                    blocked_host = f"blocked-{platform}.example"
                    later_host = f"later-{platform}.example"
                    blocked = _config(
                        tmp,
                        platform=platform,
                        name=f"blocked-{platform}",
                        host=blocked_host,
                        token=credential,
                    )
                    later = _config(
                        tmp,
                        platform=platform,
                        name=f"later-{platform}",
                        host=later_host,
                        token=f"later-{platform}-credential",
                    )
                    challenge = {
                        "id": 1,
                        "name": "One",
                        "category": "web",
                        "description": f"attacker supplied {credential}",
                        "attacker_metadata": {
                            credential: f"attacker supplied {credential}"
                        },
                        "files": [],
                    }

                    def responder(request):
                        parsed = urlsplit(request["url"])
                        if parsed.hostname == blocked_host:
                            self.assertNotIn(credential, PATH_COLLISIONS)
                            if credential == "partial" and (
                                (platform == "ctfd" and parsed.path == "/rules")
                                or (
                                    platform == "rctf"
                                    and parsed.path
                                    == "/api/v1/integrations/client/config"
                                )
                            ):
                                return 500, {}, b"failed rules"
                            return _response(platform, parsed.path, challenge=challenge)
                        self.assertEqual(parsed.hostname, later_host)
                        return _response(platform, parsed.path, challenge=None)

                    fake = FakeOpener(responder)
                    with patch("ctf_collector.http.build_opener", return_value=fake):
                        results = collect_all([blocked, later])

                    output_root = Path(tmp) / "out"
                    blocked_root = output_root / f"blocked-{platform}"
                    later_root = output_root / f"later-{platform}"
                    stored_text = (later_root / "manifest.json").read_text(
                        encoding="utf-8"
                    )
                    stored = json.loads(stored_text)
                    paths = [
                        path.relative_to(output_root).as_posix()
                        for path in output_root.rglob("*")
                    ]
                    documents = [path.read_bytes() for path in _documents(output_root)]

                    if credential in PATH_COLLISIONS:
                        blocked_error = results[0]["error"]
                        self.assertIsInstance(blocked_error, CollectorError)
                        self.assertEqual(blocked_error.code, "unsafe_credential")
                        self.assertNotIn(credential, blocked_error.message)
                        self.assertLessEqual(len(blocked_error.message), 120)
                        self.assertFalse(blocked_root.exists())
                        self.assertFalse(
                            any(
                                urlsplit(request["url"]).hostname == blocked_host
                                for request in fake.requests
                            )
                        )
                    else:
                        self.assertIsNone(results[0]["error"])
                        blocked_manifest = json.loads(
                            (blocked_root / "manifest.json").read_text(encoding="utf-8")
                        )
                        expected_status = "partial" if credential == "partial" else "complete"
                        self.assertEqual(set(blocked_manifest), MANIFEST_KEYS)
                        self.assertEqual(blocked_manifest["status"], expected_status)
                        self.assertEqual(len(blocked_manifest["challenges"]), 1)
                        self.assertEqual(
                            set(blocked_manifest["challenges"][0]),
                            MANIFEST_CHALLENGE_KEYS,
                        )
                    self.assertIsNone(results[1]["error"])
                    self.assertFalse(results[1]["partial"])
                    self.assertEqual(set(stored), MANIFEST_KEYS)
                    self.assertEqual(stored["status"], "complete")
                    self.assertEqual(stored["challenges"], [])
                    self.assertEqual(stored["failures"], [])
                    self.assertEqual(stored["platform"], platform)
                    self.assertTrue(all(credential not in path for path in paths))
                    self.assertTrue(
                        all(credential.encode("ascii") not in item for item in documents)
                    )

    def test_direct_collect_ctf_preserves_status_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = _config(
                tmp,
                platform="ctfd",
                name="direct",
                host="direct.example",
                token="status",
            )
            fake = FakeOpener(
                lambda request: _response(
                    "ctfd", urlsplit(request["url"]).path, challenge=None
                )
            )
            with patch("ctf_collector.http.build_opener", return_value=fake):
                manifest = collect_ctf(config)

            manifest_bytes = (
                Path(tmp) / "out" / "direct" / "manifest.json"
            ).read_bytes()
            self.assertEqual(manifest["status"], "complete")
            self.assertEqual(json.loads(manifest_bytes)["status"], "complete")
            self.assertNotIn(b"status", manifest_bytes)

    def test_direct_collect_ctf_rejects_impossible_output_before_output_or_http(self):
        for credential in ("files", "body", ":"):
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
                    self.assertRaises(CollectorError) as caught,
                ):
                    collect_ctf(config)

                self.assertEqual(caught.exception.code, "unsafe_credential")
                self.assertNotIn(credential, caught.exception.message)
                self.assertLessEqual(len(caught.exception.message), 120)
                self.assertEqual(fake.requests, [])
                self.assertFalse((Path(tmp) / "out").exists())


class OtherConfiguredCredentialSchemaCollisionTests(unittest.TestCase):
    def test_trusted_schema_survives_while_raw_metadata_is_redacted(self):
        for platform in ("ctfd", "rctf"):
            for credential in SCHEMA_COLLISIONS:
                with (
                    self.subTest(platform=platform, credential=credential),
                    tempfile.TemporaryDirectory() as tmp,
                ):
                    primary_host = f"primary-{platform}.example"
                    blocked_host = f"blocked-{platform}.example"
                    primary = _config(
                        tmp,
                        platform=platform,
                        name=f"primary-{platform}",
                        host=primary_host,
                        token=f"primary-{platform}-credential",
                    )
                    blocked = _config(
                        tmp,
                        platform=platform,
                        name=f"blocked-{platform}",
                        host=blocked_host,
                        token=credential,
                    )
                    challenge = {
                        "id": 1,
                        "name": "One",
                        "category": "web",
                        "description": f"attacker supplied {credential}",
                        "attacker_metadata": {
                            credential: f"attacker supplied {credential}"
                        },
                        "files": [],
                    }

                    def responder(request):
                        parsed = urlsplit(request["url"])
                        if parsed.hostname == primary_host:
                            if credential == "rules" and (
                                (platform == "ctfd" and parsed.path == "/rules")
                                or (
                                    platform == "rctf"
                                    and parsed.path
                                    == "/api/v1/integrations/client/config"
                                )
                            ):
                                if platform == "ctfd":
                                    return 200, {"Content-Type": "text/plain"}, b"ordinary"
                                return 200, {}, {
                                    "kind": "goodClientConfig",
                                    "data": {"homeContent": "ordinary"},
                                }
                            return _response(platform, parsed.path, challenge=challenge)
                        self.assertEqual(parsed.hostname, blocked_host)
                        self.assertNotIn(credential, PATH_COLLISIONS)
                        return _response(platform, parsed.path, challenge=None)

                    fake = FakeOpener(responder)
                    with patch("ctf_collector.http.build_opener", return_value=fake):
                        results = collect_all([primary, blocked])

                    output_root = Path(tmp) / "out"
                    event_root = output_root / f"primary-{platform}"
                    manifest_bytes = (event_root / "manifest.json").read_bytes()
                    manifest = json.loads(manifest_bytes.decode("utf-8"))
                    challenge_path = next(event_root.glob("*/*/challenge.json"))
                    challenge_bytes = challenge_path.read_bytes()
                    stored_challenge = json.loads(challenge_bytes.decode("utf-8"))
                    paths = [
                        path.relative_to(output_root).as_posix()
                        for path in output_root.rglob("*")
                    ]
                    documents = [path.read_bytes() for path in _documents(output_root)]

                    self.assertIsNone(results[0]["error"])
                    self.assertEqual(results[0]["partial"], credential == "rules")
                    if credential in PATH_COLLISIONS:
                        self.assertEqual(results[1]["error"].code, "unsafe_credential")
                    else:
                        self.assertIsNone(results[1]["error"])
                    self.assertEqual(set(manifest), MANIFEST_KEYS)
                    self.assertEqual(
                        manifest["status"],
                        "partial" if credential == "rules" else "complete",
                    )
                    self.assertEqual(len(manifest["challenges"]), 1)
                    self.assertEqual(
                        set(manifest["challenges"][0]), MANIFEST_CHALLENGE_KEYS
                    )
                    self.assertEqual(manifest["challenges"][0]["files"], [])
                    self.assertEqual(manifest["challenges"][0]["media"], [])
                    self.assertEqual(set(stored_challenge), CHALLENGE_KEYS)
                    self.assertEqual(stored_challenge["platform"], platform)
                    self.assertFalse(
                        _contains_string(stored_challenge["raw"], credential)
                    )
                    self.assertTrue(all(credential not in path for path in paths))
                    self.assertTrue(
                        all(credential.encode("ascii") not in item for item in documents)
                    )


if __name__ == "__main__":
    unittest.main()
