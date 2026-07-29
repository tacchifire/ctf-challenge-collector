import email.utils
from http.client import HTTPException
import json
import ssl
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.request import (
    HTTPHandler,
    HTTPSHandler,
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from .errors import CollectorError


RETRYABLE_STATUSES = {408, 425, 429, 500, 502, 503, 504}
REDIRECT_STATUSES = {301, 302, 303, 307, 308}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def normalized_origin(url):
    parsed = urlsplit(str(url))
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise CollectorError("invalid_url", "only http and https URLs are allowed")
    if parsed.username is not None or parsed.password is not None:
        raise CollectorError("invalid_url", "URL user information is forbidden")
    if not parsed.hostname:
        raise CollectorError("invalid_url", "URL has no host")
    try:
        port = parsed.port
    except ValueError as exc:
        raise CollectorError("invalid_url", "URL has an invalid port") from exc
    if port is None:
        port = 443 if scheme == "https" else 80
    return scheme, parsed.hostname.lower().rstrip("."), port


def validated_url(url):
    value = str(url)
    if any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in value):
        raise CollectorError("invalid_url", "URL contains whitespace or control characters")
    normalized_origin(value)
    parsed = urlsplit(value)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


class HttpClient:
    def __init__(
        self,
        base_url,
        token,
        auth_scheme,
        platform,
        allowed_attachment_origins,
        timeout,
        retries,
        tls,
        limits,
    ):
        self.base_url = validated_url(base_url).rstrip("/")
        self.base_origin = normalized_origin(self.base_url)
        self.token = token
        self.auth_scheme = auth_scheme
        self.platform = platform
        self.allowed_attachment_origins = {
            normalized_origin(url) for url in allowed_attachment_origins
        }
        self.timeout = timeout
        self.max_attempts = retries["max_attempts"]
        self.backoff = retries["backoff_seconds"]
        self.max_retry_after = retries["max_retry_after_seconds"]
        self.max_redirects = limits["max_redirects"]
        self.max_metadata_bytes = limits["max_metadata_bytes"]

        verify = tls["verify"]
        ca_file = tls.get("ca_file")
        if verify:
            context = ssl.create_default_context(cafile=ca_file)
        else:
            context = ssl._create_unverified_context()
        self.opener = build_opener(
            ProxyHandler({}),
            HTTPHandler(),
            HTTPSHandler(context=context),
            NoRedirect(),
        )

    def resolve(self, value):
        return validated_url(urljoin(f"{self.base_url}/", str(value)))

    def _allowed(self, url, attachment):
        origin = normalized_origin(url)
        if origin == self.base_origin:
            return
        if attachment and origin in self.allowed_attachment_origins:
            return
        raise CollectorError(
            "foreign_origin",
            "request target origin is not allowed",
        )

    def _headers(self, url, attachment):
        if attachment:
            # A byte stream download has no request body to describe, and a
            # foreign CDN has no reason to see a JSON content negotiation.
            headers = {
                "Accept": "application/octet-stream;q=0.9, */*;q=0.8",
                "User-Agent": "ctf-challenge-collector/1.0",
            }
        else:
            # CTFd 3.8.6 only resolves an Authorization token when
            # `request.is_json` holds, and Flask derives that from the request
            # Content-Type alone. Without this header the API answers as if the
            # client were anonymous, even on GET.
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "ctf-challenge-collector/1.0",
            }
        if self.token and normalized_origin(url) == self.base_origin:
            headers["Authorization"] = f"{self.auth_scheme} {self.token}"
        return headers

    def _retry_delay(self, headers, attempt):
        value = headers.get("Retry-After") if headers else None
        if value:
            try:
                delay = max(0.0, float(value))
            except ValueError:
                try:
                    retry_time = email.utils.parsedate_to_datetime(value)
                    delay = max(0.0, retry_time.timestamp() - time.time())
                except (TypeError, ValueError, OverflowError):
                    delay = 0.0
            return min(delay, self.max_retry_after)
        return min(self.backoff * (2 ** (attempt - 1)), self.max_retry_after)

    def _sleep_for_retry(self, headers, attempt):
        delay = self._retry_delay(headers, attempt)
        if delay > 0:
            time.sleep(delay)

    def _rctf_unauthorized(self, response, status):
        if self.platform != "rctf" or status != 401:
            return None
        try:
            data = response.read(self.max_metadata_bytes + 1)
        except (OSError, TimeoutError, HTTPException):
            return None
        if len(data) > self.max_metadata_bytes:
            return CollectorError(
                "metadata_too_large",
                "rCTF error response exceeds metadata limit",
                status=status,
            )
        try:
            payload = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(payload, dict):
            return None
        if payload.get("kind") == "badNotStarted":
            return CollectorError(
                "rctf_not_started",
                "rCTF event has not started",
                status=status,
            )
        if payload.get("kind") == "badToken":
            return CollectorError(
                "auth_error",
                "rCTF authentication failed",
                status=status,
            )
        return None

    def open_get(self, url, *, attachment=False):
        current = validated_url(url)
        redirects = 0
        attempt = 1
        while True:
            self._allowed(current, attachment)
            request = Request(
                current,
                headers=self._headers(current, attachment),
                method="GET",
            )
            try:
                response = self.opener.open(request, timeout=self.timeout)
            except HTTPError as exc:
                if exc.code in REDIRECT_STATUSES:
                    location = exc.headers.get("Location")
                    exc.close()
                    if not location:
                        raise CollectorError(
                            "redirect_without_location",
                            "redirect response has no Location header",
                            status=exc.code,
                        )
                    if redirects >= self.max_redirects:
                        raise CollectorError(
                            "too_many_redirects",
                            "redirect limit exceeded",
                            status=exc.code,
                        )
                    destination = validated_url(urljoin(current, location))
                    self._allowed(destination, attachment)
                    current = destination
                    redirects += 1
                    continue
                if exc.code in RETRYABLE_STATUSES and attempt < self.max_attempts:
                    headers = exc.headers
                    exc.close()
                    self._sleep_for_retry(headers, attempt)
                    attempt += 1
                    continue
                message = f"HTTP {exc.code} for GET request"
                classified = self._rctf_unauthorized(exc, exc.code)
                exc.close()
                if classified is not None:
                    raise classified from exc
                raise CollectorError("http_error", message, status=exc.code) from exc
            except (URLError, TimeoutError, OSError) as exc:
                if attempt < self.max_attempts:
                    self._sleep_for_retry({}, attempt)
                    attempt += 1
                    continue
                raise CollectorError("network_error", f"GET request failed: {exc}") from exc

            status = getattr(response, "status", response.getcode())
            if status in REDIRECT_STATUSES:
                location = response.headers.get("Location")
                response.close()
                if not location:
                    raise CollectorError(
                        "redirect_without_location",
                        "redirect response has no Location header",
                        status=status,
                    )
                if redirects >= self.max_redirects:
                    raise CollectorError(
                        "too_many_redirects",
                        "redirect limit exceeded",
                        status=status,
                    )
                destination = validated_url(urljoin(current, location))
                self._allowed(destination, attachment)
                current = destination
                redirects += 1
                continue
            if status in RETRYABLE_STATUSES and attempt < self.max_attempts:
                headers = response.headers
                response.close()
                self._sleep_for_retry(headers, attempt)
                attempt += 1
                continue
            if status < 200 or status >= 300:
                classified = self._rctf_unauthorized(response, status)
                response.close()
                if classified is not None:
                    raise classified
                raise CollectorError(
                    "http_error",
                    f"HTTP {status} for GET request",
                    status=status,
                )
            return response, current

    def get_json(self, url):
        response, final_url = self.open_get(url, attachment=False)
        try:
            data = response.read(self.max_metadata_bytes + 1)
        except (OSError, TimeoutError, HTTPException) as exc:
            raise CollectorError("network_error", f"failed reading JSON response: {exc}") from exc
        finally:
            response.close()
        if len(data) > self.max_metadata_bytes:
            raise CollectorError("metadata_too_large", "JSON response exceeds metadata limit")
        try:
            return json.loads(data.decode("utf-8")), final_url
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CollectorError("invalid_json", "response is not valid UTF-8 JSON") from exc
