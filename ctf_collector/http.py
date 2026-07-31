import email.utils
from http.client import HTTPException
import json
import math
import re
import ssl
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urljoin, urlsplit, urlunsplit
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
MAX_JSON_INTEGER_DIGITS = 4300
PERCENT_ESCAPE_RE = re.compile(r"%[0-9A-Fa-f]{2}")
PATH_SAFE_CHARACTERS = "/:@!$&'()*+,;=-._~"
QUERY_SAFE_CHARACTERS = f"{PATH_SAFE_CHARACTERS}?"


def _unicode_scalar_text(value):
    """Return URL input that can always cross a UTF-8 boundary.

    URL handling is deliberately kept below the collector/safety layers, so
    this small ingress normalizer lives here instead of importing either and
    creating a dependency cycle. JSON may contain an isolated UTF-16
    surrogate even though a URL identity can only contain Unicode scalars.
    """
    text = str(value)
    if not any(0xD800 <= ord(character) <= 0xDFFF for character in text):
        return text
    return "".join(
        "\ufffd" if 0xD800 <= ord(character) <= 0xDFFF else character
        for character in text
    )


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _split(url):
    """`urlsplit` that reports a malformed URL the way every caller expects.

    An unterminated IPv6 literal makes `urlsplit` raise `ValueError`, which
    would leave the URL text in a traceback and end a collection that should
    only have lost one attachment.
    """
    try:
        return urlsplit(_unicode_scalar_text(url))
    except ValueError as exc:
        raise CollectorError("invalid_url", "URL cannot be parsed") from exc


def _joined(base, reference):
    """`urljoin` that cannot end a run over a malformed reference."""
    try:
        return urljoin(
            _unicode_scalar_text(base),
            _unicode_scalar_text(reference),
        )
    except ValueError as exc:
        raise CollectorError("invalid_url", "URL cannot be parsed") from exc


def _quoted_component(value, safe):
    """UTF-8 quote a URL component without double-encoding valid escapes."""
    result = []
    position = 0
    for match in PERCENT_ESCAPE_RE.finditer(value):
        result.append(quote(value[position : match.start()], safe=safe))
        result.append(match.group(0))
        position = match.end()
    result.append(quote(value[position:], safe=safe))
    return "".join(result)


def _bounded_json_int(value):
    if len(value.removeprefix("-")) > MAX_JSON_INTEGER_DIGITS:
        raise ValueError("JSON integer exceeds digit limit")
    return int(value)


def _finite_json_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("JSON float is not finite")
    return number


def _reject_json_constant(_value):
    raise ValueError("JSON constant is not finite")


def _loads_json(value):
    return json.loads(
        value,
        parse_int=_bounded_json_int,
        parse_float=_finite_json_float,
        parse_constant=_reject_json_constant,
    )


def normalized_origin(url):
    parsed = _split(url)
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
    value = _unicode_scalar_text(url)
    if any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in value):
        raise CollectorError("invalid_url", "URL contains whitespace or control characters")
    normalized_origin(value)
    parsed = _split(value)
    path = _quoted_component(parsed.path or "/", PATH_SAFE_CHARACTERS)
    query = _quoted_component(parsed.query, QUERY_SAFE_CHARACTERS)
    return urlunsplit((parsed.scheme, parsed.netloc, path, query, ""))


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
        value = _unicode_scalar_text(value)
        if any(
            character.isspace()
            or ord(character) < 32
            or ord(character) == 127
            for character in value
        ):
            raise CollectorError(
                "invalid_url",
                "URL contains whitespace or control characters",
            )
        return validated_url(_joined(f"{self.base_url}/", value))

    def resolve_attachment(self, value):
        url = self.resolve(value)
        self._allowed(url, attachment=True)
        return url

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

    def _headers(self, url, attachment, *, authenticated=True, accept=None):
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
        if accept is not None:
            headers["Accept"] = accept
        if (
            authenticated
            and self.token
            and normalized_origin(url) == self.base_origin
        ):
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
            payload = _loads_json(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
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

    def open_get(
        self,
        url,
        *,
        attachment=False,
        authenticated=True,
        accept=None,
    ):
        current = validated_url(url)
        redirects = 0
        attempt = 1
        while True:
            self._allowed(current, attachment)
            request = Request(
                current,
                headers=self._headers(
                    current,
                    attachment,
                    authenticated=authenticated,
                    accept=accept,
                ),
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
                    destination = validated_url(_joined(current, location))
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
                destination = validated_url(_joined(current, location))
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

    def get_json(self, url, *, authenticated=True):
        response, final_url = self.open_get(
            url,
            attachment=False,
            authenticated=authenticated,
        )
        try:
            data = response.read(self.max_metadata_bytes + 1)
        except (OSError, TimeoutError, HTTPException) as exc:
            raise CollectorError("network_error", f"failed reading JSON response: {exc}") from exc
        finally:
            response.close()
        if len(data) > self.max_metadata_bytes:
            raise CollectorError("metadata_too_large", "JSON response exceeds metadata limit")
        try:
            return _loads_json(data.decode("utf-8")), final_url
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise CollectorError("invalid_json", "response is not valid UTF-8 JSON") from exc

    def get_text(self, url, *, accepted_types, authenticated=True):
        response, final_url = self.open_get(
            url,
            attachment=False,
            authenticated=authenticated,
            accept=", ".join(accepted_types),
        )
        try:
            content_type = response.headers.get("Content-Type")
            media_type = (
                content_type.split(";", 1)[0].strip().lower()
                if content_type is not None
                else ""
            )
            if media_type not in accepted_types:
                raise CollectorError(
                    "invalid_rules_type",
                    "rules response has an unsupported Content-Type",
                )
            try:
                data = response.read(self.max_metadata_bytes + 1)
            except (OSError, TimeoutError, HTTPException) as exc:
                raise CollectorError(
                    "network_error",
                    f"failed reading text response: {exc}",
                ) from exc
            if len(data) > self.max_metadata_bytes:
                raise CollectorError(
                    "metadata_too_large",
                    "text response exceeds metadata limit",
                )
            charset = response.headers.get_content_charset() or "utf-8"
            try:
                return data.decode(charset), final_url
            except (LookupError, UnicodeDecodeError) as exc:
                raise CollectorError(
                    "invalid_text",
                    "rules response is not valid text in its declared charset",
                ) from exc
        finally:
            response.close()
