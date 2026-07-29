"""Shared in-memory HTTP fakes so tests run without sockets."""

from email.message import Message
from io import BytesIO
import json
from pathlib import Path
from urllib.error import HTTPError


class FakeResponse:
    def __init__(self, body=b"", status=200, headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode("utf-8")
        self._stream = BytesIO(body)
        self.status = status
        self.headers = Message()
        for key, value in (headers or {}).items():
            self.headers[key] = str(value)

    def read(self, size=-1):
        return self._stream.read(size)

    def getcode(self):
        return self.status

    def close(self):
        self._stream.close()


class FakeOpener:
    def __init__(self, responder):
        self.responder = responder
        self.requests = []

    def open(self, request, timeout=None):
        record = {
            "method": request.get_method(),
            "url": request.full_url,
            "headers": {key.lower(): value for key, value in request.header_items()},
            "timeout": timeout,
        }
        self.requests.append(record)
        result = self.responder(record)
        if isinstance(result, BaseException):
            raise result
        if not isinstance(result, tuple):
            # A responder may hand back a pre-built response to model a stream
            # that misbehaves partway through the body.
            return result
        status, headers, body = result
        if status >= 300:
            message = Message()
            for key, value in headers.items():
                message[key] = value
            raise HTTPError(
                request.full_url,
                status,
                "redirect" if status < 400 else "error",
                message,
                BytesIO(body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")),
            )
        return FakeResponse(body, status, headers)


def make_config(tmp, platform="ctfd", **overrides):
    root = Path(tmp)
    token_file = root / f"{platform}.token"
    token_file.write_text(f"{platform}-secret\n", encoding="utf-8")
    config = {
        "name": f"fake-{platform}",
        "platform": platform,
        "base_url": "https://base.example",
        "token_file": token_file,
        "output_root": root / "out",
        "tls": {"verify": True},
        "timeout": 2.0,
        "retries": {
            "max_attempts": 2,
            "backoff_seconds": 0.0,
            "max_retry_after_seconds": 0.0,
        },
        "limits": {
            "page_size": 2,
            "max_pages": 10,
            "max_file_bytes": 1024,
            "max_total_bytes": 2048,
            "max_redirects": 3,
            "max_metadata_bytes": 1024 * 1024,
        },
        "unauthenticated_attachment_origins": [],
        "fail_on_partial": True,
    }
    config.update(overrides)
    return config
