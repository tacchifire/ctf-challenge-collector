import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from urllib.parse import parse_qs, urlsplit


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "ctf-collect"


class ScenarioServer:
    def __init__(self, responder):
        self.responder = responder
        self.requests = []
        self.server = None
        self.thread = None

    def __enter__(self):
        scenario = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length) if length else b""
                scenario.requests.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "headers": {key.lower(): value for key, value in self.headers.items()},
                        "body": body,
                    }
                )
                status, headers, response = scenario.responder(
                    self.command, self.path, self.headers, body
                )
                if isinstance(response, (dict, list)):
                    response = json.dumps(response).encode("utf-8")
                    headers = {"Content-Type": "application/json", **headers}
                elif isinstance(response, str):
                    response = response.encode("utf-8")
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            do_GET = _handle
            do_POST = _handle
            do_PUT = _handle
            do_PATCH = _handle
            do_DELETE = _handle

            def log_message(self, format, *args):
                pass

        try:
            self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        except PermissionError as exc:
            raise unittest.SkipTest(
                "loopback sockets are disabled by this execution sandbox"
            ) from exc
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    @property
    def origin(self):
        host, port = self.server.server_address
        return f"http://{host}:{port}"


class SyncCliTests(unittest.TestCase):
    def run_sync(self, config_path, *extra):
        return subprocess.run(
            [str(LAUNCHER), "sync", "--config", str(config_path), *extra],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def write_config(self, directory, ctfs):
        path = Path(directory) / "config.json"
        path.write_text(
            json.dumps({"ctfs": ctfs}, indent=2) + "\n",
            encoding="utf-8",
        )
        return path

    def ctf_config(self, tmp, origin, platform="ctfd", **overrides):
        token_file = Path(tmp) / f"{platform}.token"
        token_file.write_text(f"{platform}-secret\n", encoding="utf-8")
        config = {
            "name": f"sample-{platform}",
            "platform": platform,
            "base_url": origin,
            "token_file": str(token_file),
            "output_root": str(Path(tmp) / "output"),
            "timeouts": {"request_seconds": 2},
            "retries": {
                "max_attempts": 2,
                "backoff_seconds": 0,
                "max_retry_after_seconds": 0,
            },
            "limits": {
                "page_size": 2,
                "max_pages": 10,
                "max_file_bytes": 1024 * 1024,
                "max_total_bytes": 1024 * 1024,
            },
        }
        config.update(overrides)
        return config

    def test_ctfd_multipage_detail_attachment_manifest_and_idempotent_rerun(self):
        file_body = b"flag{downloaded}\n"
        file_gets = 0

        def responder(method, raw_path, headers, body):
            nonlocal file_gets
            parsed = urlsplit(raw_path)
            if parsed.path == "/api/v1/challenges":
                page = int(parse_qs(parsed.query)["page"][0])
                if page == 1:
                    return 200, {}, {
                        "data": [
                            {"id": 1, "name": "First", "category": "Web"},
                            {"id": 2, "name": "Second", "category": "Pwn"},
                        ]
                    }
                return 200, {}, {"data": []}
            if parsed.path == "/api/v1/challenges/1":
                return 200, {}, {
                    "data": {
                        "id": 1,
                        "name": "First",
                        "category": "Web",
                        "description": "raw detail retained",
                        "files": ["/files/flag.txt?signature=do-not-store"],
                    }
                }
            if parsed.path == "/api/v1/challenges/2":
                return 200, {}, {
                    "data": {
                        "id": 2,
                        "name": "Second",
                        "category": "Pwn",
                        "files": [],
                    }
                }
            if parsed.path == "/files/flag.txt":
                file_gets += 1
                return 200, {"Content-Type": "text/plain"}, file_body
            return 404, {}, b"missing"

        with tempfile.TemporaryDirectory() as tmp, ScenarioServer(responder) as server:
            config = self.ctf_config(tmp, server.origin)
            config_path = self.write_config(tmp, [config])

            first = self.run_sync(config_path)
            second = self.run_sync(config_path)

            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(file_gets, 1, "verified files must not be downloaded again")
            ctf_root = Path(tmp) / "output" / "sample-ctfd"
            challenge = ctf_root / "Web" / "1-First"
            stored = challenge / "files" / "flag.txt"
            self.assertEqual(stored.read_bytes(), file_body)
            metadata = json.loads((challenge / "challenge.json").read_text())
            self.assertEqual(metadata["raw"]["description"], "raw detail retained")

            manifest_text = (ctf_root / "manifest.json").read_text(encoding="utf-8")
            manifest = json.loads(manifest_text)
            entry = manifest["challenges"][1]["files"][0]
            self.assertEqual(entry["sha256"], hashlib.sha256(file_body).hexdigest())
            self.assertEqual(entry["size"], len(file_body))
            self.assertEqual(entry["status"], "verified")
            self.assertNotIn("signature", manifest_text)
            self.assertNotIn("do-not-store", manifest_text)
            self.assertNotIn("ctfd-secret", manifest_text)

            api_requests = [
                request for request in server.requests
                if urlsplit(request["path"]).path.startswith("/api/")
            ]
            self.assertTrue(api_requests)
            self.assertTrue(
                all(
                    request["headers"].get("authorization") == "Token ctfd-secret"
                    for request in api_requests
                )
            )
            # CTFd only honours the token when the GET declares a JSON body.
            self.assertTrue(
                all(
                    request["headers"].get("content-type") == "application/json"
                    for request in api_requests
                )
            )
            attachment_requests = [
                request for request in server.requests
                if urlsplit(request["path"]).path == "/files/flag.txt"
            ]
            self.assertEqual(len(attachment_requests), 1)
            self.assertIsNone(attachment_requests[0]["headers"].get("content-type"))
            self.assertEqual(
                len(
                    [
                        request for request in server.requests
                        if urlsplit(request["path"]).path == "/api/v1/challenges"
                    ]
                ),
                4,
            )
            self.assertTrue(all(request["method"] == "GET" for request in server.requests))
            self.assertFalse(
                any(
                    word in urlsplit(request["path"]).path.lower()
                    for request in server.requests
                    for word in ("submit", "unlock")
                )
            )

    def test_rctf_list_fallback_direct_array_explicit_detail_and_url_field(self):
        file_body = b"rctf attachment"

        def responder(method, raw_path, headers, body):
            path = urlsplit(raw_path).path
            if path in ("/api/v1/challs", "/api/v1/challenges"):
                return 404, {}, b"not here"
            if path == "/api/challs":
                return 200, {}, [
                    {
                        "id": "r-1",
                        "name": "rCTF Task",
                        "category": "crypto",
                        "detail_url": "/api/challs/r-1",
                    }
                ]
            if path == "/api/challs/r-1":
                return 200, {}, {
                    "data": {
                        "id": "r-1",
                        "name": "rCTF Task",
                        "category": "crypto",
                        "description": "rctf raw",
                        "files": [{"name": "cipher.bin", "URL": "/dl/cipher.bin"}],
                    }
                }
            if path == "/dl/cipher.bin":
                return 200, {}, file_body
            return 404, {}, b"missing"

        with tempfile.TemporaryDirectory() as tmp, ScenarioServer(responder) as server:
            config = self.ctf_config(tmp, server.origin, platform="rctf")
            config_path = self.write_config(tmp, [config])

            result = self.run_sync(config_path)

            self.assertEqual(result.returncode, 0, result.stderr)
            ctf_root = Path(tmp) / "output" / "sample-rctf"
            challenge = ctf_root / "crypto" / "r-1-rCTF_Task"
            self.assertEqual(
                (challenge / "files" / "cipher.bin").read_bytes(),
                file_body,
            )
            raw = json.loads((challenge / "challenge.json").read_text())["raw"]
            self.assertEqual(raw["description"], "rctf raw")
            self.assertEqual(
                [urlsplit(item["path"]).path for item in server.requests[:4]],
                [
                    "/api/v1/challs",
                    "/api/v1/challenges",
                    "/api/challs",
                    "/api/challs/r-1",
                ],
            )
            self.assertTrue(
                all(
                    request["headers"].get("authorization") == "Bearer rctf-secret"
                    for request in server.requests
                    if urlsplit(request["path"]).path
                    != "/api/v1/integrations/client/config"
                )
            )
            client_config = [
                request
                for request in server.requests
                if urlsplit(request["path"]).path
                == "/api/v1/integrations/client/config"
            ]
            self.assertEqual(len(client_config), 1)
            self.assertNotIn("authorization", client_config[0]["headers"])
            self.assertTrue(
                all(
                    request["headers"].get("content-type") == "application/json"
                    for request in server.requests
                    if urlsplit(request["path"]).path.startswith("/api/")
                )
            )
            self.assertIsNone(
                [
                    request for request in server.requests
                    if urlsplit(request["path"]).path == "/dl/cipher.bin"
                ][0]["headers"].get("content-type")
            )
            self.assertTrue(all(request["method"] == "GET" for request in server.requests))

    def test_foreign_origins_redirects_credentials_and_traversal_are_safe(self):
        allowed_body = b"anonymous external file"

        def allowed_responder(method, raw_path, headers, body):
            if urlsplit(raw_path).path == "/public.bin":
                return 200, {}, allowed_body
            return 404, {}, b"missing"

        def blocked_responder(method, raw_path, headers, body):
            return 200, {}, b"must never be requested"

        with (
            tempfile.TemporaryDirectory() as tmp,
            ScenarioServer(allowed_responder) as allowed,
            ScenarioServer(blocked_responder) as blocked,
        ):
            def base_responder(method, raw_path, headers, body):
                path = urlsplit(raw_path).path
                if path == "/api/v1/challenges":
                    return 200, {}, {
                        "data": [
                            {
                                "id": "../CON",
                                "name": "/absolute\\name",
                                "category": "../../Web",
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
                if path == "/api/v1/challenges/..%2FCON":
                    return 200, {}, {
                        "data": {
                            "id": "../CON",
                            "name": "/absolute\\name",
                            "category": "../../Web",
                            "files": [
                                {
                                    "name": "../../CON",
                                    "url": f"{allowed.origin}/public.bin?secret=signed",
                                },
                                {
                                    "name": "blocked.bin",
                                    "url": f"{blocked.origin}/blocked.bin?signature=hidden",
                                },
                                {"name": "redirect.bin", "url": "/redirect"},
                            ],
                        }
                    }
                if path == "/redirect":
                    return 302, {"Location": f"{blocked.origin}/via-redirect"}, b""
                return 404, {}, b"missing"

            with ScenarioServer(base_responder) as base:
                config = self.ctf_config(
                    tmp,
                    base.origin,
                    unauthenticated_attachment_origins=[allowed.origin],
                    fail_on_partial=True,
                )
                config_path = self.write_config(tmp, [config])

                result = self.run_sync(config_path)

                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(len(allowed.requests), 1)
                self.assertNotIn("authorization", allowed.requests[0]["headers"])
                self.assertIsNone(allowed.requests[0]["headers"].get("content-type"))
                self.assertEqual(blocked.requests, [])
                self.assertTrue(
                    all(
                        request["headers"].get("authorization")
                        == "Token ctfd-secret"
                        for request in base.requests
                    )
                )

                ctf_root = Path(tmp) / "output" / "sample-ctfd"
                stored_files = [
                    path for path in ctf_root.rglob("*")
                    if path.is_file() and path.parent.name == "files"
                ]
                self.assertEqual(len(stored_files), 1)
                self.assertEqual(stored_files[0].read_bytes(), allowed_body)
                self.assertEqual(stored_files[0].name, "_CON")
                self.assertTrue(stored_files[0].resolve().is_relative_to(ctf_root.resolve()))
                self.assertFalse(list(ctf_root.rglob("*.part")))
                manifest_text = (ctf_root / "manifest.json").read_text()
                manifest = json.loads(manifest_text)
                self.assertEqual(manifest["status"], "partial")
                self.assertEqual(
                    [failure["error"]["code"] for failure in manifest["failures"]],
                    ["foreign_origin", "foreign_origin"],
                )
                self.assertNotIn("signed", manifest_text)
                self.assertNotIn("hidden", manifest_text)
                self.assertNotIn("ctfd-secret", manifest_text)

                config["fail_on_partial"] = False
                config_path.write_text(json.dumps({"ctfs": [config]}), encoding="utf-8")
                opted_out = self.run_sync(config_path)
                self.assertEqual(opted_out.returncode, 0, opted_out.stderr)

    def test_file_and_total_limits_fail_partially_and_clean_parts(self):
        bodies = {
            "/files/oversize.bin": b"123456",
            "/files/first.bin": b"1234",
            "/files/total.bin": b"5678",
        }

        def responder(method, raw_path, headers, body):
            path = urlsplit(raw_path).path
            if path == "/api/v1/challenges":
                return 200, {}, {
                    "data": [{"id": 7, "name": "Limits", "category": "misc"}],
                    "meta": {
                        "pagination": {
                            "page": 1,
                            "pages": 1,
                            "next": None,
                        }
                    },
                }
            if path == "/api/v1/challenges/7":
                return 200, {}, {
                    "data": {
                        "id": 7,
                        "name": "Limits",
                        "category": "misc",
                        "files": list(bodies),
                    }
                }
            if path in bodies:
                return 200, {}, bodies[path]
            return 404, {}, b"missing"

        with tempfile.TemporaryDirectory() as tmp, ScenarioServer(responder) as server:
            config = self.ctf_config(tmp, server.origin)
            config["limits"].update({"max_file_bytes": 5, "max_total_bytes": 6})
            config_path = self.write_config(tmp, [config])

            result = self.run_sync(config_path)

            self.assertEqual(result.returncode, 1, result.stderr)
            ctf_root = Path(tmp) / "output" / "sample-ctfd"
            manifest = json.loads((ctf_root / "manifest.json").read_text())
            self.assertEqual(
                [failure["error"]["code"] for failure in manifest["failures"]],
                ["file_too_large", "total_too_large"],
            )
            challenge_files = manifest["challenges"][0]["files"]
            self.assertEqual(
                [item["status"] for item in challenge_files],
                ["failed", "downloaded", "failed"],
            )
            self.assertFalse(list(ctf_root.rglob("*.part")))
            stored = [
                path.read_bytes()
                for path in ctf_root.rglob("*")
                if path.is_file() and path.parent.name == "files"
            ]
            self.assertEqual(stored, [b"1234"])

    def test_retry_after_retries_only_bounded_get(self):
        attempts = 0

        def responder(method, raw_path, headers, body):
            nonlocal attempts
            path = urlsplit(raw_path).path
            if path == "/api/v1/challenges":
                attempts += 1
                if attempts == 1:
                    return 503, {"Retry-After": "0"}, b"later"
                return 200, {}, {"data": []}
            return 404, {}, b"missing"

        with tempfile.TemporaryDirectory() as tmp, ScenarioServer(responder) as server:
            config = self.ctf_config(tmp, server.origin)
            config["limits"]["page_size"] = 100
            config_path = self.write_config(tmp, [config])

            result = self.run_sync(config_path)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(attempts, 2)
            self.assertEqual(
                [request["method"] for request in server.requests],
                ["GET", "GET", "GET"],
            )

    def test_ctf_selector_does_not_contact_unselected_ctf(self):
        def responder(method, raw_path, headers, body):
            if urlsplit(raw_path).path == "/api/v1/challenges":
                return 200, {}, {"data": []}
            return 404, {}, b"missing"

        with tempfile.TemporaryDirectory() as tmp, ScenarioServer(responder) as server:
            first = self.ctf_config(tmp, server.origin)
            first["name"] = "chosen"
            second = self.ctf_config(tmp, server.origin)
            second["name"] = "not-chosen"
            config_path = self.write_config(tmp, [first, second])

            result = self.run_sync(config_path, "--ctf", "chosen")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                [urlsplit(request["path"]).path for request in server.requests],
                ["/api/v1/challenges", "/rules"],
            )
            self.assertIn("chosen: complete", result.stdout)


if __name__ == "__main__":
    unittest.main()
