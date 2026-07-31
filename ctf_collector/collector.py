import hashlib
import hmac
from http.client import HTTPException
import json
import os
import re
import unicodedata
from pathlib import Path
from urllib.parse import quote, urlsplit

from .archive import (
    MEDIA_SIGNATURE_PREFIX_BYTES,
    extract_media_sources,
    is_supported_media_type,
    media_signature_matches,
    passive_media_name,
    redact_rules_values,
    render_challenge_html,
    render_rules_html,
    strip_session_markup,
)
from .config import (
    MAX_FILE_BYTES,
    MAX_METADATA_BYTES,
    MAX_PAGES,
    MAX_PAGE_SIZE,
    MAX_REDIRECTS,
    MAX_TOTAL_BYTES,
    MIN_METADATA_BYTES,
)
from .errors import CollectorError
from .http import HttpClient, normalized_origin
from .safety import (
    credential_safe_error as _credential_safe_error,
    display_name,
    filename_from_url,
    normalize_unicode_text,
    path_spells_secret,
    redact_url,
    redact_urls_in_text,
    redact_secrets,
    SafeOutput,
    safe_metadata,
    safe_json_text,
    safe_unique_component,
    sanitize_component_without_secrets,
    ctf_directory_name,
    temporary_output_name,
    UniqueNameAllocator,
)


RCTF_LIST_PATHS = ("/api/v1/challs", "/api/v1/challenges", "/api/challs")
MAX_TOKEN_BYTES = 64 * 1024
MAX_CONTENT_LENGTH_DIGITS = 20
SOURCE_IDENTITY_CONTEXT = b"ctf-challenge-collector source identity\x00"
MANIFEST_NAME = "manifest.json"
CHALLENGE_NAME = "challenge.json"
CHALLENGE_HTML_NAME = "challenge.html"
MEDIA_DIRECTORY_NAME = "media"
RULES_NAME = "rules.html"
# What every run writes at a fixed place below a directory it named. A name is
# settled against these as well as against itself, because the join is ours and
# it is the finished path that reaches the disk.
CTF_DIRECTORY_CHILDREN = (
    (MANIFEST_NAME,),
    (temporary_output_name(MANIFEST_NAME),),
    (RULES_NAME,),
    (temporary_output_name(RULES_NAME),),
)
# A manifest is the only fixed child every successful CTF must write. Rules
# and challenge children are possible outputs, but whether they exist is not
# known until after the API responds.
CTF_GUARANTEED_CHILDREN = (
    (MANIFEST_NAME,),
    (temporary_output_name(MANIFEST_NAME),),
)
CHALLENGE_DIRECTORY_CHILDREN = (
    (CHALLENGE_NAME,),
    (temporary_output_name(CHALLENGE_NAME),),
    (CHALLENGE_HTML_NAME,),
    (temporary_output_name(CHALLENGE_HTML_NAME),),
    ("files",),
    (MEDIA_DIRECTORY_NAME,),
)
CHALLENGE_GUARANTEED_CHILDREN = CHALLENGE_DIRECTORY_CHILDREN[:4]
# An attachment is written beside its target rather than beneath it, so its
# temporary name is a suffix of the name we are choosing.
ATTACHMENT_TEMPORARY_SUFFIX = ".part"

# Collector-owned keys and enum values form a public, fixed output contract.
# They must never be run through the untrusted-metadata key rewriter. JSON can
# safely encode a coincidental credential spelling without changing this
# decoded contract; fixed filesystem paths cannot, and are handled separately.
GENERATED_SCHEMA_LITERALS = frozenset(
    {
        "attachment_index",
        "audio",
        "category",
        "challenge_id",
        "challenges",
        "code",
        "complete",
        "content_type",
        "ctf",
        "ctfd",
        "ctfd_rules_page",
        "directory",
        "downloaded",
        "error",
        "failed",
        "failure",
        "failures",
        "files",
        "html",
        "id",
        "image",
        "local_path",
        "media",
        "media_index",
        "media_kind",
        "message",
        "name",
        "partial",
        "path",
        "platform",
        "raw",
        "rctf",
        "rctf_home_content",
        "rules",
        "sha256",
        "size",
        "source_identity",
        "source_kind",
        "source_url",
        "status",
        "unavailable",
        "verified",
        "video",
        "written",
    }
)
TRUSTED_GENERATED_VALUES = frozenset(
    {
        "audio",
        "complete",
        "ctfd",
        "ctfd_rules_page",
        "downloaded",
        "failed",
        "image",
        "partial",
        "rctf",
        "rctf_home_content",
        "unavailable",
        "verified",
        "video",
        "written",
    }
)
POTENTIAL_FIXED_PATH_PARTS = frozenset(
    {
        MANIFEST_NAME,
        temporary_output_name(MANIFEST_NAME),
        RULES_NAME,
        temporary_output_name(RULES_NAME),
        CHALLENGE_NAME,
        temporary_output_name(CHALLENGE_NAME),
        CHALLENGE_HTML_NAME,
        temporary_output_name(CHALLENGE_HTML_NAME),
        "files",
        MEDIA_DIRECTORY_NAME,
    }
)
HTML_QUOTED_VALUE_RE = re.compile(r'''=\s*(["'])(.*?)\1''', re.DOTALL)
HTML_TEXT_RE = re.compile(r">([^<]*)<", re.DOTALL)
HTML_RAW_TEXT_RE = re.compile(
    r"<(?:style|script)\b[^>]*>(.*?)</(?:style|script)\s*>",
    re.IGNORECASE | re.DOTALL,
)
HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
HTML_ENTITY_RE = re.compile(
    r"&(?:#[0-9]+;?|#[xX][0-9A-Fa-f]+;?|[A-Za-z][A-Za-z0-9]+;?)"
)
JSON_NUMERIC_LIKE_CREDENTIAL_RE = re.compile(r"(?=.*[0-9])[0-9eE+.-]+\Z")
JSON_UNAVOIDABLE_CREDENTIALS = frozenset(
    {"null", "true", "false", "{", "}", "[", "]", ":", ",", '"', "\\", "u"}
)
PROGRESS_CONTRACT_TEXT = " ".join(
    {
        "event",
        "ctf",
        "index",
        "total",
        "platform",
        "count",
        "name",
        "category",
        "local_path",
        "declared",
        "received",
        "size",
        "status",
        "failures",
        "code",
        "ctf_start",
        "ctf_done",
        "ctf_failed",
        "listing_start",
        "listing_done",
        "challenge",
        "attachment_start",
        "attachment_progress",
        "attachment_done",
        "attachment_failed",
    }
)


class _SafeProgress:
    """Fail-open wrapper around a caller-supplied reporter.

    Progress is a display, not part of the result, so a reporter that raises
    must never cost us a collection. One that failed once will keep failing,
    so it is dropped instead of being retried on every chunk.
    """

    def __init__(self, callback):
        self._callback = callback

    def __call__(self, event):
        callback = self._callback
        if callback is None:
            return
        try:
            callback(event)
        except Exception:
            self._callback = None


def _safe_progress(callback):
    if callback is None or isinstance(callback, _SafeProgress):
        return callback
    return _SafeProgress(callback)


class _RunApproval:
    """The one answer a run gets about attachments that exceed its limits.

    The operator is asked about the first oversized attachment and answered
    for the whole run, because a collection that stops to ask again at every
    attachment is a collection nobody is watching by the end of it. What is
    approved is the exceeding, not an amount: each attachment is still held to
    a finite limit derived from the size it declares, and the absolute caps are
    settled before this is consulted at all.
    """

    def __init__(self, approver):
        self._approver = approver
        self._decision = None

    def __call__(self, request):
        if self._decision is None:
            self._decision = self._ask(request)
        return self._decision

    def _ask(self, request):
        """The operator's answer, with anything that is not a yes read as no.

        A prompt that fails has not approved anything, and asking it again for
        every later attachment would only repeat the failure, so the refusal
        is recorded like any other. An interrupt is not an answer: it is the
        operator stopping the run, so it is left to reach them.
        """
        if self._approver is None:
            return False
        try:
            return self._approver(request) is True
        except Exception:
            return False


def _run_approval(approver):
    if isinstance(approver, _RunApproval):
        return approver
    return _RunApproval(approver)


def _notify(progress, event, **fields):
    """Report a milestone so a long run never looks hung.

    Only values that already passed redaction reach the reporter, because the
    display is as public as any other terminal output.
    """
    if progress is None:
        return
    progress({"event": event, **fields})


def _collection(payload, *, preserve_items=False):
    def collected(items):
        if preserve_items:
            return list(items)
        return [item for item in items if isinstance(item, dict)]

    if isinstance(payload, list):
        return collected(payload)
    if not isinstance(payload, dict):
        raise CollectorError("invalid_api_data", "challenge list is not an array/object")
    for key in ("data", "challs", "challenges"):
        if key in payload:
            value = payload[key]
            if isinstance(value, list):
                return collected(value)
            if isinstance(value, dict):
                for nested in ("challs", "challenges", "data"):
                    if isinstance(value.get(nested), list):
                        return collected(value[nested])
                if "id" in value:
                    return [value]
                if all(isinstance(item, dict) for item in value.values()):
                    return list(value.values())
    if "id" in payload:
        return [payload]
    raise CollectorError("invalid_api_data", "cannot locate challenge array")


def _object(payload):
    if isinstance(payload, dict) and isinstance(payload.get("data"), dict):
        return payload["data"]
    if (
        isinstance(payload, dict)
        and isinstance(payload.get("data"), list)
        and len(payload["data"]) == 1
        and isinstance(payload["data"][0], dict)
    ):
        return payload["data"][0]
    if (
        isinstance(payload, list)
        and len(payload) == 1
        and isinstance(payload[0], dict)
    ):
        return payload[0]
    if isinstance(payload, dict):
        return payload
    raise CollectorError("invalid_api_data", "challenge detail is not an object")


def _challenge_id(challenge):
    if not isinstance(challenge, dict):
        raise CollectorError("invalid_api_data", "challenge is not an object")
    value = challenge.get("id", challenge.get("_id"))
    if value is None or isinstance(value, (dict, list, bool)):
        raise CollectorError("invalid_api_data", "challenge has no scalar id")
    return normalize_unicode_text(value)


def _detail_url(challenge, client):
    candidates = []
    explicit = False
    for key in ("detail_url", "detailUrl"):
        if key in challenge and challenge[key] is not None:
            explicit = True
            if isinstance(challenge.get(key), str) and challenge[key]:
                candidates.append(challenge[key])
    links = challenge.get("_links")
    if isinstance(links, dict) and "detail" in links:
        explicit = True
        detail = links.get("detail")
        if isinstance(detail, str) and detail:
            candidates.append(detail)
        elif (
            isinstance(detail, dict)
            and isinstance(detail.get("href"), str)
            and detail["href"]
        ):
            candidates.append(detail["href"])
    value = challenge.get("url")
    if isinstance(value, str):
        try:
            resolved = client.resolve(value)
            if urlsplit(resolved).path.startswith("/api/"):
                candidates.append(value)
        except CollectorError:
            pass
    for candidate in candidates:
        try:
            resolved = client.resolve(candidate)
            if normalized_origin(resolved) == client.base_origin:
                return resolved
        except CollectorError:
            continue
    if explicit:
        raise CollectorError(
            "invalid_api_data",
            "rCTF fallback challenge has an invalid detail URL",
        )
    return None


def _attachments(challenge, client):
    files = challenge.get("files", [])
    if files is None:
        return [], []
    if isinstance(files, (str, dict)):
        files = [files]
    if not isinstance(files, list):
        return [], [
            (
                CollectorError(
                    "invalid_api_data",
                    "challenge files must be an array",
                ),
                None,
            )
        ]
    result = []
    errors = []
    for index, item in enumerate(files):
        name = None
        value = None
        if isinstance(item, str):
            value = item
        elif isinstance(item, dict):
            for key in ("url", "URL", "href", "location", "path"):
                if isinstance(item.get(key), str) and item[key]:
                    value = item[key]
                    break
            for key in ("name", "filename", "file_name"):
                if isinstance(item.get(key), str) and item[key]:
                    name = item[key]
                    break
        if not value:
            errors.append(
                (
                    CollectorError(
                        "invalid_api_data",
                        f"attachment {index} has no URL",
                    ),
                    index,
                )
            )
            continue
        try:
            url = client.resolve(value)
        except CollectorError as exc:
            errors.append((exc, index))
            continue
        result.append({"url": url, "name": name or filename_from_url(url)})
    return result, errors


def _failure(
    code,
    message,
    *,
    attachment_index=None,
    media_index=None,
    challenge_id=None,
    source_url=None,
):
    failure = {"error": {"code": code, "message": message}}
    if attachment_index is not None:
        failure["attachment_index"] = attachment_index
    if media_index is not None:
        failure["media_index"] = media_index
    if challenge_id is not None:
        failure["challenge_id"] = str(challenge_id)
    if source_url is not None:
        failure["source_url"] = redact_url(source_url, force=True)
    return failure


def _html_failure(exc):
    """One failure shape for a page write, whichever layer refused it."""
    if isinstance(exc, CollectorError):
        return {"code": exc.code, "message": exc.message}
    return {"code": "io_error", "message": f"I/O failure: {exc}"}


def _safe_error_fields(exc, secrets):
    if isinstance(exc, CollectorError):
        error = _credential_safe_error(
            exc.code,
            exc.message,
            secrets,
            status=exc.status,
        )
    else:
        error = _credential_safe_error(
            "io_error",
            f"I/O failure: {exc}",
            secrets,
        )
    return {"code": error.code, "message": error.message}


def _media_references(description, client):
    references = []
    errors = []
    seen = set()
    for index, (kind, value) in enumerate(extract_media_sources(description)):
        raw_key = ("raw", str(value))
        try:
            url = client.resolve_attachment(value)
        except CollectorError as exc:
            if raw_key not in seen:
                seen.add(raw_key)
                errors.append((exc, index, value))
            continue
        key = ("url", url)
        if key in seen:
            continue
        seen.add(key)
        references.append(
            {
                "kind": kind,
                "name": filename_from_url(url),
                "source_index": index,
                "url": url,
            }
        )
    return references, errors


def _read_old_manifest(output, parts):
    try:
        payload = output.read_bytes(parts)
    except FileNotFoundError:
        return {}
    try:
        manifest = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return {}
    entries = {}
    if not isinstance(manifest, dict):
        return entries
    for challenge in manifest.get("challenges", []):
        if not isinstance(challenge, dict):
            continue
        for collection_name in ("files", "media"):
            for item in challenge.get(collection_name, []):
                if (
                    isinstance(item, dict)
                    and isinstance(item.get("local_path"), str)
                    and isinstance(item.get("source_url"), str)
                    and isinstance(item.get("source_identity"), str)
                    and re.fullmatch(r"[0-9a-f]{64}", item["source_identity"])
                    and isinstance(item.get("size"), int)
                    and isinstance(item.get("sha256"), str)
                ):
                    entries[item["local_path"]] = {
                        "source_url": item["source_url"],
                        "source_identity": item["source_identity"],
                        "size": item["size"],
                        "sha256": item["sha256"],
                        "content_type": item.get("content_type"),
                        "media_kind": item.get("media_kind"),
                    }
    return entries


def _source_identity(source_url, token):
    # URL ingress normally settles isolated surrogates. Keep the persistence
    # identity defensive as well: this hash must never be the UTF-8 exception
    # that aborts the current challenge and every CTF after it.
    source_url = normalize_unicode_text(source_url)
    return hmac.new(
        token.encode("ascii"),
        SOURCE_IDENTITY_CONTEXT + source_url.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _verified_existing(
    output,
    parts,
    expected,
    source_identity,
    maximum,
    *,
    prefix_bytes=0,
):
    if not expected or not hmac.compare_digest(
        expected["source_identity"],
        source_identity,
    ):
        return None
    # Reading past the size the manifest recorded cannot produce a match, so
    # the recorded size bounds the read as well as the absolute cap does. The
    # cap alone would let a file that grew on disk be read in full before the
    # mismatch it was always going to be.
    if isinstance(expected.get("size"), int):
        maximum = min(maximum, expected["size"])
    try:
        if prefix_bytes:
            verified = output.hash_file(
                parts,
                maximum,
                prefix_bytes=prefix_bytes,
            )
        else:
            verified = output.hash_file(parts, maximum)
    except OSError as exc:
        raise CollectorError(
            "cache_read_failed",
            f"cached file could not be read: {exc}",
        ) from exc
    except CollectorError as exc:
        if exc.code == "file_too_large":
            return None
        raise
    if verified is None:
        return None
    size, digest = verified[:2]
    if size == expected["size"] and digest == expected["sha256"]:
        return verified
    return None


def _approved_cached_size(
    size,
    total_used,
    limits,
    limit_approver,
    *,
    ctf_name,
    local_path,
):
    """The error a cached file of this size earns, or ``None`` if it is kept.

    A file already on disk still counts against the run's limits, and the
    operator configured those limits for this run rather than for the run that
    fetched the file. So the same question is asked here as for a fresh
    download, through the same run-wide approval: a file we would not download
    today is not one we silently keep today either. The absolute caps are
    settled first, because nothing approves those.
    """
    file_limit = limits["max_file_bytes"]
    total_limit = limits["max_total_bytes"]
    total_required = total_used + size
    file_exceeded = size > file_limit
    total_exceeded = total_required > total_limit
    if not (file_exceeded or total_exceeded):
        return None
    within_hard_limits = (
        size <= MAX_FILE_BYTES and total_required <= MAX_TOTAL_BYTES
    )
    request = {
        "ctf_name": ctf_name,
        "local_path": local_path,
        "exceeded": (
            "both"
            if file_exceeded and total_exceeded
            else "file" if file_exceeded else "total"
        ),
        "required_file_bytes": size,
        "required_total_bytes": total_required,
        "current_file_limit": file_limit,
        "current_total_limit": total_limit,
    }
    approved = (
        within_hard_limits
        and limit_approver is not None
        and limit_approver(request) is True
    )
    if approved:
        return None
    if file_exceeded:
        return CollectorError("file_too_large", "attachment exceeds file limit")
    return CollectorError("total_too_large", "attachments exceed total limit")


def _runtime_limit(limits, key, hard_maximum, *, minimum=1):
    value = limits.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise CollectorError(
            "invalid_config",
            f"{key} must be an integer within runtime bounds",
        )
    return min(value, hard_maximum)


def _download(
    client,
    url,
    output,
    parent_parts,
    target_name,
    limits,
    total_used,
    *,
    ctf_name,
    local_path,
    limit_approver=None,
    progress=None,
    require_media_type=False,
    response_metadata=None,
):
    effective_file_limit = _runtime_limit(
        limits,
        "max_file_bytes",
        MAX_FILE_BYTES,
    )
    effective_total_limit = _runtime_limit(
        limits,
        "max_total_bytes",
        MAX_TOTAL_BYTES,
    )
    response, final_url = client.open_get(url, attachment=True)
    temporary_name = f"{target_name}{ATTACHMENT_TEMPORARY_SUFFIX}"
    directory = None
    content_type = None
    try:
        if require_media_type:
            content_type_header = response.headers.get("Content-Type")
            content_type = (
                content_type_header.split(";", 1)[0].strip().lower()
                if content_type_header is not None
                else ""
            )
            if not is_supported_media_type(content_type):
                raise CollectorError(
                    "invalid_media_type",
                    "media response has an unsupported Content-Type",
                )
            if response_metadata is not None:
                response_metadata["content_type"] = content_type
        declared = None
        content_length = response.headers.get("Content-Length")
        if content_length is not None:
            if (
                len(content_length) > MAX_CONTENT_LENGTH_DIGITS
                or re.fullmatch(r"[0-9]+", content_length) is None
            ):
                raise CollectorError(
                    "invalid_content_length",
                    "attachment has an invalid Content-Length",
                )
            declared = int(content_length)
            file_exceeded = declared > effective_file_limit
            total_required = total_used + declared
            total_exceeded = total_required > effective_total_limit
            if file_exceeded or total_exceeded:
                exceeded = (
                    "both"
                    if file_exceeded and total_exceeded
                    else "file" if file_exceeded else "total"
                )
                request = {
                    "ctf_name": ctf_name,
                    "local_path": local_path,
                    "exceeded": exceeded,
                    "required_file_bytes": declared,
                    "required_total_bytes": total_required,
                    "current_file_limit": effective_file_limit,
                    "current_total_limit": effective_total_limit,
                }
                within_hard_limits = (
                    declared <= MAX_FILE_BYTES
                    and total_required <= MAX_TOTAL_BYTES
                )
                approved = (
                    within_hard_limits
                    and limit_approver is not None
                    and limit_approver(request) is True
                )
                if not approved:
                    if file_exceeded:
                        raise CollectorError(
                            "file_too_large", "attachment exceeds file limit"
                        )
                    raise CollectorError(
                        "total_too_large", "attachments exceed total limit"
                    )
                effective_file_limit = max(effective_file_limit, declared)
                effective_total_limit = max(
                    effective_total_limit, total_required
                )

        directory, descriptor, temporary_identity = output.open_temporary(
            parent_parts,
            target_name,
            temporary_name,
        )
        digest = hashlib.sha256()
        media_prefix = bytearray()
        size = 0
        _notify(
            progress,
            "attachment_start",
            ctf=ctf_name,
            local_path=local_path,
            declared=declared,
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                while True:
                    chunk = response.read(128 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    _notify(
                        progress,
                        "attachment_progress",
                        ctf=ctf_name,
                        local_path=local_path,
                        received=size,
                        declared=declared,
                    )
                    if size > effective_file_limit:
                        raise CollectorError(
                            "file_too_large", "attachment exceeds file limit"
                        )
                    if total_used + size > effective_total_limit:
                        raise CollectorError(
                            "total_too_large", "attachments exceed total limit"
                        )
                    if len(media_prefix) < MEDIA_SIGNATURE_PREFIX_BYTES:
                        remaining = MEDIA_SIGNATURE_PREFIX_BYTES - len(media_prefix)
                        media_prefix.extend(chunk[:remaining])
                    stream.write(chunk)
                    digest.update(chunk)
                stream.flush()
                os.fsync(stream.fileno())
            if declared is not None and size != declared:
                # A short or over-long body is not the advertised file, so it
                # must never reach the target name.
                raise CollectorError(
                    "truncated_download",
                    f"attachment body is {size} bytes but Content-Length declared {declared}",
                )
            if require_media_type and not media_signature_matches(
                content_type,
                media_prefix,
                total_size=size,
            ):
                raise CollectorError(
                    "invalid_media_content",
                    "media body does not match its Content-Type",
                )
            output.replace_temporary(
                parent_parts,
                directory,
                temporary_name,
                target_name,
                temporary_identity,
            )
            return size, digest.hexdigest(), final_url
        except BaseException:
            output.cleanup_temporary(directory, temporary_name)
            raise
    except CollectorError:
        raise
    except (OSError, TimeoutError, HTTPException) as exc:
        raise CollectorError("download_failed", f"attachment download failed: {exc}") from exc
    finally:
        if directory is not None:
            os.close(directory)
        response.close()


def _read_token(path):
    try:
        with Path(path).open("rb") as stream:
            payload = stream.read(MAX_TOKEN_BYTES + 1)
    except OSError as exc:
        raise CollectorError("token_file", f"cannot read token file: {exc}") from exc
    if len(payload) > MAX_TOKEN_BYTES:
        raise CollectorError("token_file", "token file is too large")
    try:
        token = payload.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise CollectorError(
            "token_file",
            "token must contain one visible ASCII value",
        ) from exc
    if not token:
        raise CollectorError("token_file", "token file is empty")
    if any(ord(character) < 33 or ord(character) > 126 for character in token):
        raise CollectorError(
            "token_file",
            "token must contain one visible ASCII value",
        )
    return token


def _validate_storage_contract(token, secrets):
    """Refuse an impossible current credential before output or HTTP exists.

    Credentials may coincide with public schema text. Their raw bytes can be
    escaped at the JSON/HTML serialization boundary without changing decoded
    semantics. A fixed filesystem component has no equivalent encoding: if
    the current CTF may need one that contains its own token, it is rejected
    before the API can select that path and leave a partial tree.
    """
    if any(
        token in literal for literal in POTENTIAL_FIXED_PATH_PARTS
    ):
        raise _credential_safe_error(
            "unsafe_credential",
            "authentication credential conflicts with the required output contract",
            secrets,
        )

    if any(
        spelling in JSON_UNAVOIDABLE_CREDENTIALS
        or JSON_NUMERIC_LIKE_CREDENTIAL_RE.fullmatch(spelling) is not None
        for secret in secrets
        for spelling in {
            normalize_unicode_text(secret),
            unicodedata.normalize("NFKC", normalize_unicode_text(secret)),
        }
        if spelling
    ):
        raise _credential_safe_error(
            "unsafe_credential",
            "authentication credential conflicts with the required output contract",
            secrets,
        )

    # Exercise the storage alphabet with every configured credential now. A
    # token that collides with unavoidable JSON grammar cannot be repaired by
    # string escaping, and discovering that after collection would leave a
    # partial tree.
    safe_json_text(
        {
            "contract": sorted(GENERATED_SCHEMA_LITERALS),
            "integer": 120,
            "boolean_true": True,
            "boolean_false": False,
            "nothing": None,
            "json_escapes": "\x00\b\f\n\r\t\"\\",
        },
        secrets,
    )
    probe = "\ue000"
    challenge_probe = render_challenge_html(
        {
            "category": probe,
            "connection_info": probe,
            "description": probe,
            "hints": probe,
            "id": probe,
            "name": probe,
            "points": probe,
            "value": probe,
        },
        [
            {
                "html_path": f"files/{probe}",
                "local_path": f"files/{probe}",
                "status": "downloaded",
            },
            {"local_path": probe, "status": "failed"},
        ],
        [
            {
                "html_path": f"media/{probe}-{kind}",
                "media_kind": kind,
                "status": "downloaded",
            }
            for kind in ("image", "audio", "video")
        ],
    )
    for document in (challenge_probe, render_rules_html(probe)):
        _trusted_html_for_storage(document, secrets)
    # These are the entity spellings produced by html.escape in ordinary
    # rendered text and attributes. An entity substring cannot be rewritten
    # without changing what HTMLParser and browsers decode.
    _trusted_html_for_storage("<p>&amp;&#x27;</p>", secrets)


def _generated_values_for_storage(value, secrets, key=""):
    """Redact generated variable values while preserving generated keys.

    Every mapping key in a manifest is collector-owned. API-owned mappings are
    confined to ``challenge.json.raw`` and were already sanitized at the item
    boundary. Re-running the metadata key rewriter here would therefore cross
    the trust boundary and corrupt fixed schema keys.
    """
    if isinstance(value, dict):
        return {
            item_key: _generated_values_for_storage(item_value, secrets, item_key)
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [
            _generated_values_for_storage(item, secrets, key)
            for item in value
        ]
    if isinstance(value, str) and value in TRUSTED_GENERATED_VALUES:
        return value
    return safe_metadata(value, key=key, secrets=secrets)


def _challenge_for_storage(item, platform, secrets):
    """The fixed challenge envelope around already-safe API metadata."""
    return {
        "category": safe_metadata(item["category"], key="category", secrets=secrets),
        "id": safe_metadata(item["id"], key="id", secrets=secrets),
        "name": safe_metadata(item["name"], key="name", secrets=secrets),
        "platform": platform,
        "raw": item["safe_raw"],
    }


def _manifest_for_storage(manifest, secrets):
    return _generated_values_for_storage(manifest, secrets)


def _credential_safe_failure_fields(value, secrets):
    """Bound every persisted error pair without changing non-error data."""
    if isinstance(value, dict):
        result = {
            key: _credential_safe_failure_fields(item, secrets)
            for key, item in value.items()
        }
        if isinstance(result.get("code"), str) and isinstance(
            result.get("message"), str
        ):
            error = _credential_safe_error(
                result["code"],
                result["message"],
                secrets,
            )
            result["code"] = error.code
            result["message"] = error.message
        return result
    if isinstance(value, list):
        return [_credential_safe_failure_fields(item, secrets) for item in value]
    return value


def _trusted_html_for_storage(value, secrets):
    """Encode residual public HTML spellings without persisting token bytes.

    Server-controlled values have already been redacted. Residual matches are
    therefore collector-owned prose or attribute values; decimal character
    references preserve their browser-visible meaning without storing the
    coincidental credential spelling.
    """
    spellings = sorted(
        {
            spelling
            for secret in secrets
            for spelling in (
                normalize_unicode_text(secret),
                unicodedata.normalize("NFKC", normalize_unicode_text(secret)),
            )
            if spelling
        },
        key=lambda item: (-len(item), item),
    )
    raw_text_ranges = [match.span(1) for match in HTML_RAW_TEXT_RE.finditer(value)]
    unsafe_ranges = [*raw_text_ranges]
    unsafe_ranges.extend(match.span() for match in HTML_COMMENT_RE.finditer(value))
    entity_ranges = [match.span() for match in HTML_ENTITY_RE.finditer(value)]
    safe_ranges = [
        match.span(2)
        for match in HTML_QUOTED_VALUE_RE.finditer(value)
        if not any(
            unsafe_start <= match.start(2) and match.end(2) <= unsafe_end
            for unsafe_start, unsafe_end in unsafe_ranges
        )
    ]
    safe_ranges.extend(
        match.span(1)
        for match in HTML_TEXT_RE.finditer(value)
        if not any(
            raw_start <= match.start(1) and match.end(1) <= raw_end
            for raw_start, raw_end in raw_text_ranges
        )
    )

    def safely_encodable(start, end):
        inside_safe_range = any(
            safe_start <= start and end <= safe_end
            for safe_start, safe_end in safe_ranges
        )
        intersects_entity = any(
            start < entity_end and entity_start < end
            for entity_start, entity_end in entity_ranges
        )
        return inside_safe_range and not intersects_entity

    result = []
    index = 0
    while index < len(value):
        spelling = next(
            (item for item in spellings if value.startswith(item, index)),
            None,
        )
        if spelling is None:
            result.append(value[index])
            index += 1
            continue
        end = index + len(spelling)
        if not safely_encodable(index, end):
            raise _credential_safe_error(
                "unsafe_credential",
                "required HTML cannot be encoded without disclosing a credential",
                secrets,
            )
        result.append(
            "".join(f"&#{ord(character)};" for character in spelling)
        )
        index = end
    result = "".join(result)
    if any(spelling in result for spelling in spellings):
        raise _credential_safe_error(
            "unsafe_credential",
            "required HTML cannot be encoded without disclosing a credential",
            secrets,
        )
    return result


def _positive_page_number(value):
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _ctfd_pagination(payload, requested_page, page_items):
    if not isinstance(payload, dict):
        return False, requested_page + 1, None
    meta = payload.get("meta")
    if meta is None or (isinstance(meta, dict) and "pagination" not in meta):
        return not page_items, requested_page + 1, None
    if not isinstance(meta, dict) or not isinstance(meta.get("pagination"), dict):
        return False, None, "meta.pagination must be an object"

    pagination = meta["pagination"]
    current = requested_page
    if "page" in pagination:
        if not _positive_page_number(pagination["page"]):
            return False, None, "meta.pagination.page must be a positive integer"
        current = pagination["page"]
        if current != requested_page:
            return (
                False,
                None,
                "meta.pagination.page does not match the requested page",
            )

    pages = None
    if "pages" in pagination:
        pages = pagination["pages"]
        if (
            not isinstance(pages, int)
            or isinstance(pages, bool)
            or pages < 0
        ):
            return False, None, "meta.pagination.pages must be a non-negative integer"
        if page_items and pages == 0:
            return False, None, "meta.pagination.pages is zero for a non-empty page"
        if pages > 0 and current > pages:
            return False, None, "meta.pagination.page exceeds meta.pagination.pages"

    if "next" in pagination:
        next_page = pagination["next"]
        if next_page is None:
            if pages is not None and pages > 0 and current < pages:
                return (
                    False,
                    None,
                    "meta.pagination.next is null before the final page",
                )
            return True, None, None
        if not _positive_page_number(next_page):
            return False, None, "meta.pagination.next must be null or a positive integer"
        if next_page <= current:
            return False, None, "meta.pagination.next does not advance"
        if next_page != current + 1:
            return (
                False,
                None,
                "meta.pagination.next must equal the current page plus one",
            )
        if pages is not None and next_page > pages:
            return False, None, "meta.pagination.next exceeds meta.pagination.pages"
        if pages is not None and current >= pages:
            return False, None, "meta.pagination.next exists after the final page"
        if not page_items:
            return False, None, "empty page advertises a next page"
        return False, next_page, None

    if pages is not None:
        if pages == 0 or current >= pages:
            return True, None, None
        if not page_items:
            return False, None, "empty page occurs before meta.pagination.pages"
    elif not page_items:
        return True, None, None
    return False, current + 1, None


def _fetch_ctfd(client, limits, failures):
    challenges = []
    seen_ids = set()
    seen_signatures = set()
    requested_pages = set()
    page = 1
    for _attempt in range(limits["max_pages"]):
        if page in requested_pages:
            failures.append(
                _failure(
                    "pagination_no_progress",
                    "CTFd pagination repeated a page number",
                )
            )
            break
        requested_pages.add(page)
        url = (
            f"{client.base_url}/api/v1/challenges"
            f"?page={page}&per_page={limits['page_size']}"
        )
        payload, _ = client.get_json(url)
        page_items = _collection(payload, preserve_items=True)
        valid_page_items = []
        for item in page_items:
            if not isinstance(item, dict):
                failures.append(
                    _failure(
                        "invalid_api_data",
                        "challenge summary item is not an object",
                    )
                )
                continue
            try:
                challenge_id = _challenge_id(item)
            except CollectorError:
                failures.append(
                    _failure(
                        "invalid_api_data",
                        "challenge summary has no scalar id",
                    )
                )
                continue
            valid_page_items.append((item, challenge_id))

        signature = tuple(
            challenge_id for _item, challenge_id in valid_page_items
        )
        if valid_page_items and signature in seen_signatures:
            failures.append(
                _failure(
                    "pagination_no_progress",
                    "CTFd pagination repeated a challenge page",
                )
            )
            break
        if valid_page_items:
            seen_signatures.add(signature)
        new_count = 0
        for item, challenge_id in valid_page_items:
            if challenge_id not in seen_ids:
                seen_ids.add(challenge_id)
                challenges.append(item)
                new_count += 1
        if valid_page_items and new_count == 0:
            failures.append(
                _failure(
                    "pagination_no_progress",
                    "CTFd pagination returned no new challenge IDs",
                )
            )
            break
        terminal, next_page, inconsistency = _ctfd_pagination(
            payload,
            page,
            page_items,
        )
        if inconsistency is not None:
            failures.append(
                _failure(
                    "pagination_inconsistent",
                    f"CTFd pagination is inconsistent: {inconsistency}",
                )
            )
            break
        if terminal:
            break
        page = next_page
    else:
        failures.append(
            _failure(
                "pagination_limit",
                "CTFd pagination stopped at the configured page limit",
            )
        )

    detailed = []
    for summary in challenges:
        challenge_id = _challenge_id(summary)
        if summary.get("type") == "hidden":
            failures.append(
                _failure(
                    "challenge_inaccessible",
                    "hidden challenge summary is not accessible",
                    challenge_id=challenge_id,
                )
            )
            detailed.append(summary)
            continue
        detail_url = f"{client.base_url}/api/v1/challenges/{quote(challenge_id, safe='')}"
        try:
            payload, _ = client.get_json(detail_url)
            detail = _object(payload)
            try:
                detail_id = _challenge_id(detail)
            except CollectorError as exc:
                failures.append(
                    _failure(exc.code, exc.message, challenge_id=challenge_id)
                )
            else:
                if detail_id != challenge_id:
                    failures.append(
                        _failure(
                            "invalid_api_data",
                            "challenge detail id does not match its summary id",
                            challenge_id=challenge_id,
                        )
                    )
            # The list response selected the detail route, so its validated
            # identity remains authoritative. Detail fields enrich the item
            # but cannot replace either spelling of that identity.
            detail_fields = {
                key: value
                for key, value in detail.items()
                if key not in {"id", "_id"}
            }
            detailed.append({**summary, **detail_fields})
        except CollectorError as exc:
            failures.append(
                _failure(exc.code, exc.message, challenge_id=challenge_id)
            )
            detailed.append(summary)
    return detailed


def _fetch_rctf(client, failures):
    summaries = None
    list_path = None
    last_error = None
    for path in RCTF_LIST_PATHS:
        try:
            payload, _ = client.get_json(f"{client.base_url}{path}")
            if (
                path == RCTF_LIST_PATHS[0]
                and (
                    not isinstance(payload, dict)
                    or payload.get("kind") != "goodChallenges"
                )
            ):
                raise CollectorError(
                    "invalid_api_data",
                    "official rCTF challenge list kind must be goodChallenges",
                )
            summaries = _collection(payload)
            list_path = path
            break
        except CollectorError as exc:
            last_error = exc
            if exc.status == 404:
                continue
            raise
    if summaries is None:
        raise last_error or CollectorError("invalid_api_data", "no rCTF list route")

    if list_path == RCTF_LIST_PATHS[0]:
        return summaries

    detailed = []
    for summary in summaries:
        try:
            challenge_id = _challenge_id(summary)
        except CollectorError as exc:
            failures.append(_failure(exc.code, exc.message))
            continue
        try:
            detail_url = _detail_url(summary, client)
        except CollectorError as exc:
            failures.append(
                _failure(exc.code, exc.message, challenge_id=challenge_id)
            )
            detailed.append(summary)
            continue
        if detail_url is None:
            detailed.append(summary)
            continue
        try:
            payload, _ = client.get_json(detail_url)
            detail = _object(payload)
            try:
                detail_id = _challenge_id(detail)
            except CollectorError as exc:
                failures.append(
                    _failure(exc.code, exc.message, challenge_id=challenge_id)
                )
            else:
                if detail_id != challenge_id:
                    failures.append(
                        _failure(
                            "invalid_api_data",
                            "challenge detail id does not match its summary id",
                            challenge_id=challenge_id,
                        )
                    )
            # The summary owns fallback identity. Detail fields enrich it but
            # cannot replace either spelling of that identity, even when the
            # detail's validation above succeeded.
            detail_fields = {
                key: value
                for key, value in detail.items()
                if key not in {"id", "_id"}
            }
            detailed.append({**summary, **detail_fields})
        except CollectorError as exc:
            failures.append(
                _failure(exc.code, exc.message, challenge_id=challenge_id)
            )
            detailed.append(summary)
    return detailed


def _is_rules_page(source_url, final_url):
    """Whether the response we read is still the rules page we asked for.

    A CTFd instance that wants a session answers `/rules` with a redirect to
    its login page, and that page is a perfectly valid HTML document: without
    checking where the request ended, the archive would file the login form as
    the event's rules. Only the same origin and the same path count, with the
    trailing slash a server may add to it.
    """
    try:
        if normalized_origin(final_url) != normalized_origin(source_url):
            return False
    except CollectorError:
        return False
    expected = urlsplit(source_url).path
    return urlsplit(final_url).path in {expected, f"{expected}/"}


def _inert_rules_source(source):
    inert = strip_session_markup(source)
    if inert is None:
        raise CollectorError(
            "invalid_rules_source",
            "rules source could not be parsed for session state",
        )
    # Settle URL userinfo before the general rules scrubber sees an `@` as an
    # email address. Otherwise a tab/newline-split password can be replaced in
    # pieces while leaving its username behind and losing the safe host.
    return redact_rules_values(redact_urls_in_text(inert))


def _rules_source(config, client):
    if config["platform"] == "ctfd":
        source_url = f"{client.base_url}/rules"
        source, final_url = client.get_text(
            source_url,
            accepted_types=("text/html", "text/plain"),
        )
        if not _is_rules_page(source_url, final_url):
            raise CollectorError(
                "rules_redirected",
                "rules request ended on a page that is not the rules page",
            )
        return "ctfd_rules_page", source_url, _inert_rules_source(source)

    source_url = f"{client.base_url}/api/v1/integrations/client/config"
    payload, _final_url = client.get_json(source_url, authenticated=False)
    if not isinstance(payload, dict) or payload.get("kind") != "goodClientConfig":
        raise CollectorError(
            "invalid_api_data",
            "official rCTF client config kind must be goodClientConfig",
        )
    data = payload.get("data")
    if not isinstance(data, dict):
        raise CollectorError(
            "invalid_api_data",
            "official rCTF client config data must be an object",
        )
    source = data.get("homeContent")
    if source is None:
        source = ""
    if not isinstance(source, str):
        raise CollectorError(
            "invalid_api_data",
            "official rCTF homeContent must be text",
        )
    return "rctf_home_content", source_url, _inert_rules_source(source)


def _archive_rules(config, client, output, ctf_parts, failures, secrets):
    source_kind = (
        "ctfd_rules_page"
        if config["platform"] == "ctfd"
        else "rctf_home_content"
    )
    source_url = (
        f"{client.base_url}/rules"
        if config["platform"] == "ctfd"
        else f"{client.base_url}/api/v1/integrations/client/config"
    )
    entry = {
        "path": None,
        "source_kind": source_kind,
        "source_url": redact_url(source_url),
        "status": "unavailable",
    }
    try:
        source_kind, source_url, source = _rules_source(config, client)
    except CollectorError as exc:
        if exc.status in {404, 410}:
            return entry
        entry["status"] = "failed"
        failures.append(
            _failure(
                exc.code,
                exc.message,
                source_url=source_url,
            )
        )
        return entry

    if not source.strip():
        return entry
    safe_source = redact_secrets(redact_urls_in_text(source), secrets)
    try:
        if path_spells_secret((*ctf_parts, RULES_NAME), secrets):
            raise CollectorError(
                "unsafe_credential",
                "fixed output path conflicts with a configured credential",
            )
        output.atomic_text(
            (*ctf_parts, RULES_NAME),
            _trusted_html_for_storage(render_rules_html(safe_source), secrets),
        )
    except (CollectorError, OSError) as exc:
        failure = _html_failure(exc)
        entry.update(
            {
                "source_kind": source_kind,
                "status": "failed",
                "failure": failure,
            }
        )
        failures.append(
            _failure(
                failure["code"],
                failure["message"],
                source_url=source_url,
            )
        )
        return entry
    entry.update(
        {
            "path": RULES_NAME,
            "source_kind": source_kind,
            "source_url": redact_url(source_url),
            "status": "written",
        }
    )
    return entry


def _validated_ctf_directory(config, secrets):
    # The directory is checked as well as the name it came from: sanitizing
    # normalizes, so a token spelled in a compatibility form reaches the
    # filesystem as the token even though the configured name never matched it.
    # The manifest and the name it is written under first are checked with it,
    # because a directory that only completes a token once its own fixed files
    # hang under it still writes the token to the disk. This name comes from
    # the configuration rather than from the API, so there is no next candidate
    # to fall back to: we refuse here, before an output tree exists.
    directory_name = ctf_directory_name(config["name"])
    paths = [
        (directory_name,),
        *((directory_name, *child) for child in CTF_GUARANTEED_CHILDREN),
    ]
    if any(secret and secret in config["name"] for secret in secrets) or any(
        path_spells_secret(path, secrets) for path in paths
    ):
        raise _credential_safe_error(
            "invalid_config",
            "CTF name must not contain an authentication token",
            secrets,
        )
    return directory_name


def _preflight_configs(configs):
    tokens = [_read_token(config["token_file"]) for config in configs]
    output_directories = set()
    for config in configs:
        # Cross-config directory uniqueness is a global configuration fact.
        # Credential/path contracts belong to the individual CTF and are
        # checked inside collect_all's per-CTF try block.
        directory_name = ctf_directory_name(config["name"])
        output_directory = (
            Path(config["output_root"]),
            directory_name.casefold(),
        )
        if output_directory in output_directories:
            raise CollectorError(
                "invalid_config",
                "CTF names collide in the same output directory after sanitization",
            )
        output_directories.add(output_directory)
    return tokens


def collect_ctf(
    config,
    *,
    _token=None,
    _secrets=None,
    limit_approver=None,
    progress=None,
):
    progress = _safe_progress(progress)
    limit_approver = _run_approval(limit_approver)
    token = _read_token(config["token_file"]) if _token is None else _token
    secrets = tuple(dict.fromkeys((*(_secrets or ()), token)))
    if redact_secrets(PROGRESS_CONTRACT_TEXT, secrets) != PROGRESS_CONTRACT_TEXT:
        progress = None
    _validate_storage_contract(token, secrets)
    ctf_name = _validated_ctf_directory(config, secrets)
    limits = dict(config["limits"])
    runtime_bounds = (
        ("page_size", MAX_PAGE_SIZE, 1),
        ("max_pages", MAX_PAGES, 1),
        ("max_file_bytes", MAX_FILE_BYTES, 1),
        ("max_total_bytes", MAX_TOTAL_BYTES, 1),
        ("max_redirects", MAX_REDIRECTS, 0),
        ("max_metadata_bytes", MAX_METADATA_BYTES, MIN_METADATA_BYTES),
    )
    for key, hard_maximum, minimum in runtime_bounds:
        limits[key] = _runtime_limit(
            limits,
            key,
            hard_maximum,
            minimum=minimum,
        )
    client = HttpClient(
        config["base_url"],
        token,
        "Token" if config["platform"] == "ctfd" else "Bearer",
        config["platform"],
        config["unauthenticated_attachment_origins"],
        config["timeout"],
        config["retries"],
        config["tls"],
        limits,
    )
    ctf_parts = (ctf_name,)
    with SafeOutput(config["output_root"]) as output:
        output.ensure_directory(ctf_parts)
        manifest_parts = (*ctf_parts, MANIFEST_NAME)
        old_files = _read_old_manifest(output, manifest_parts)
        failures = []
        _notify(
            progress,
            "listing_start",
            ctf=ctf_name,
            platform=config["platform"],
        )
        if config["platform"] == "ctfd":
            raw_challenges = _fetch_ctfd(client, limits, failures)
        else:
            raw_challenges = _fetch_rctf(client, failures)
        _notify(progress, "listing_done", ctf=ctf_name, count=len(raw_challenges))

        prepared = []
        # Category directories share the CTF root with these fixed outputs.
        # Reserve them before considering API names so a category can never
        # turn manifest.json or rules.html into a directory. A sanitized
        # category key is allocated once and then reused, preserving the
        # established grouping for repeated/colliding category spellings.
        used_categories = UniqueNameAllocator(
            child[0] for child in CTF_DIRECTORY_CHILDREN
        )
        category_directories = {}
        used_directories = {}
        for raw in raw_challenges:
            challenge_id = None
            try:
                challenge_id = redact_secrets(
                    redact_urls_in_text(
                        redact_secrets(_challenge_id(raw), secrets)
                    ),
                    secrets,
                )
                safe_raw = safe_metadata(raw, secrets=secrets)
                name = str(
                    safe_raw.get("name", safe_raw.get("title", "unnamed"))
                )
                category = str(safe_raw.get("category", "uncategorized"))
                base_directory = (
                    f"{sanitize_component_without_secrets(challenge_id, secrets, 'id')}-"
                    f"{sanitize_component_without_secrets(name, secrets, 'challenge')}"
                )
                base_category_name = sanitize_component_without_secrets(
                    category,
                    secrets,
                    "uncategorized",
                )
                category_key = base_category_name.casefold()
                category_name = category_directories.get(category_key)
                if category_name is None:
                    category_name = safe_unique_component(
                        ctf_parts,
                        base_category_name,
                        used_categories,
                        secrets,
                        fallback="uncategorized",
                        seed=category,
                        keep_extension=False,
                    )
                    category_directories[category_key] = category_name
                # Each component is safe by itself; the directory is settled
                # against the path it completes, including the files that will
                # be written under it and the suffix resolving a collision.
                directory_name = safe_unique_component(
                    (*ctf_parts, category_name),
                    base_directory,
                    used_directories.setdefault(
                        category_name.casefold(),
                        UniqueNameAllocator(),
                    ),
                    secrets,
                    fallback="challenge",
                    seed=f"{challenge_id}/{name}",
                    # Attachment/media directories are created only when an
                    # item actually uses them. Their final paths are checked
                    # at that point; reserving them here would reject a safe
                    # challenge merely because another CTF's token equals an
                    # optional public directory name.
                    children=CHALLENGE_GUARANTEED_CHILDREN,
                    keep_extension=False,
                )
            except CollectorError as exc:
                failures.append(
                    _failure(
                        exc.code,
                        exc.message,
                        challenge_id=challenge_id,
                    )
                )
                continue
            prepared.append(
                {
                    "id": challenge_id,
                    "name": name,
                    "category": category,
                    "category_name": category_name,
                    "directory_name": directory_name,
                    "raw": raw,
                    "safe_raw": safe_raw,
                }
            )
        prepared.sort(
            key=lambda item: (
                item["category_name"].casefold(),
                item["directory_name"].casefold(),
                item["id"],
            )
        )

        total_used = 0
        manifest_challenges = []
        for position, item in enumerate(prepared, 1):
            _notify(
                progress,
                "challenge",
                ctf=ctf_name,
                index=position,
                total=len(prepared),
                name=display_name(item["name"]),
                category=display_name(item["category"]),
            )
            challenge_parts = (
                *ctf_parts,
                item["category_name"],
                item["directory_name"],
            )
            output.ensure_directory(challenge_parts)
            safe_raw = item["safe_raw"]
            output.atomic_json(
                (*challenge_parts, CHALLENGE_NAME),
                _challenge_for_storage(item, config["platform"], secrets),
                secrets=secrets,
            )
            manifest_files = []
            attachments, attachment_errors = _attachments(item["raw"], client)
            for exc, attachment_index in attachment_errors:
                failures.append(
                    _failure(
                        exc.code,
                        exc.message,
                        attachment_index=attachment_index,
                        challenge_id=item["id"],
                    )
                )
            used_filenames = UniqueNameAllocator()
            for attachment in attachments:
                safe_attachment_name = redact_secrets(
                    redact_url(
                        redact_secrets(attachment["name"], secrets),
                        force=True,
                    ),
                    secrets,
                )
                source_url = redact_url(attachment["url"])
                try:
                    filename = safe_unique_component(
                        (*challenge_parts, "files"),
                        sanitize_component_without_secrets(
                            safe_attachment_name,
                            secrets,
                            "attachment",
                        ),
                        used_filenames,
                        secrets,
                        fallback="attachment",
                        seed=safe_attachment_name,
                        siblings=(ATTACHMENT_TEMPORARY_SUFFIX,),
                    )
                except CollectorError as exc:
                    failure = _safe_error_fields(exc, secrets)
                    manifest_files.append(
                        {
                            "source_url": source_url,
                            "status": "failed",
                            "failure": failure,
                        }
                    )
                    failures.append(
                        _failure(
                            failure["code"],
                            failure["message"],
                            challenge_id=item["id"],
                            source_url=attachment["url"],
                        )
                    )
                    _notify(
                        progress,
                        "attachment_failed",
                        ctf=ctf_name,
                        local_path="",
                        code=failure["code"],
                    )
                    continue
                target_parts = (*challenge_parts, "files", filename)
                local_path = "/".join(target_parts[1:])
                source_identity = _source_identity(attachment["url"], token)
                entry = {
                    "local_path": local_path,
                    "source_identity": source_identity,
                    "source_url": source_url,
                }
                try:
                    verified = _verified_existing(
                        output,
                        target_parts,
                        old_files.get(local_path),
                        source_identity,
                        # The soft limit is what the operator is asked about,
                        # so the hash is bounded by the absolute cap instead.
                        MAX_FILE_BYTES,
                    )
                    verification_error = None
                except CollectorError as exc:
                    verified = None
                    verification_error = exc
                if verification_error is not None:
                    error = verification_error
                elif verified is not None:
                    size, digest = verified
                    error = _approved_cached_size(
                        size,
                        total_used,
                        limits,
                        limit_approver,
                        ctf_name=ctf_name,
                        local_path=local_path,
                    )
                    if error is None:
                        total_used += size
                        entry.update(
                            {
                                "sha256": digest,
                                "size": size,
                                "status": "verified",
                            }
                        )
                        manifest_files.append(entry)
                        _notify(
                            progress,
                            "attachment_done",
                            ctf=ctf_name,
                            local_path=local_path,
                            size=size,
                            status="verified",
                        )
                        continue
                else:
                    error = None
                try:
                    if error is not None:
                        raise error
                    size, digest, _final_url = _download(
                        client,
                        attachment["url"],
                        output,
                        target_parts[:-1],
                        filename,
                        limits,
                        total_used,
                        ctf_name=ctf_name,
                        local_path=local_path,
                        limit_approver=limit_approver,
                        progress=progress,
                    )
                    total_used += size
                    entry.update(
                        {
                            "sha256": digest,
                            "size": size,
                            "status": "downloaded",
                        }
                    )
                    _notify(
                        progress,
                        "attachment_done",
                        ctf=ctf_name,
                        local_path=local_path,
                        size=size,
                        status="downloaded",
                    )
                except CollectorError as exc:
                    safe_error = _safe_error_fields(exc, secrets)
                    entry.update(
                        {
                            "status": "failed",
                            "failure": safe_error,
                        }
                    )
                    failures.append(
                        _failure(
                            safe_error["code"],
                            safe_error["message"],
                            challenge_id=item["id"],
                            source_url=attachment["url"],
                        )
                    )
                    _notify(
                        progress,
                        "attachment_failed",
                        ctf=ctf_name,
                        local_path=local_path,
                        code=safe_error["code"],
                    )
                manifest_files.append(entry)

            manifest_media = []
            render_media = []
            description = item["raw"].get("description", "")
            media_references, media_errors = _media_references(
                description,
                client,
            )
            for exc, media_index, source_value in media_errors:
                source_url = safe_metadata(
                    str(source_value),
                    secrets=secrets,
                )
                media_entry = {
                    "source_url": source_url,
                    "status": "failed",
                    "failure": {
                        "code": exc.code,
                        "message": exc.message,
                    },
                }
                manifest_media.append(media_entry)
                failures.append(
                    _failure(
                        exc.code,
                        exc.message,
                        challenge_id=item["id"],
                        media_index=media_index,
                        source_url=source_url,
                    )
                )

            used_media_names = UniqueNameAllocator()
            for media in media_references:
                source_url = redact_url(media["url"])
                try:
                    filename = safe_unique_component(
                        (*challenge_parts, MEDIA_DIRECTORY_NAME),
                        # The name is settled after sanitizing, so what the archive
                        # keeps can never be an active document suffix however the
                        # server spelled it. The rule is idempotent, so the next
                        # run derives the same name and reuses the same file.
                        passive_media_name(
                            sanitize_component_without_secrets(
                                media["name"],
                                secrets,
                                "media",
                            )
                        ),
                        used_media_names,
                        secrets,
                        fallback="media",
                        seed=media["url"],
                        siblings=(ATTACHMENT_TEMPORARY_SUFFIX,),
                    )
                except CollectorError as exc:
                    failure = _safe_error_fields(exc, secrets)
                    manifest_media.append(
                        {
                            "source_url": source_url,
                            "status": "failed",
                            "failure": failure,
                        }
                    )
                    failures.append(
                        _failure(
                            failure["code"],
                            failure["message"],
                            challenge_id=item["id"],
                            media_index=media["source_index"],
                            source_url=media["url"],
                        )
                    )
                    _notify(
                        progress,
                        "attachment_failed",
                        ctf=ctf_name,
                        local_path="",
                        code=failure["code"],
                    )
                    continue
                target_parts = (
                    *challenge_parts,
                    MEDIA_DIRECTORY_NAME,
                    filename,
                )
                local_path = "/".join(target_parts[1:])
                source_identity = _source_identity(media["url"], token)
                entry = {
                    "local_path": local_path,
                    "source_identity": source_identity,
                    "source_url": source_url,
                }
                expected = old_files.get(local_path)
                try:
                    verified = _verified_existing(
                        output,
                        target_parts,
                        expected,
                        source_identity,
                        MAX_FILE_BYTES,
                        prefix_bytes=MEDIA_SIGNATURE_PREFIX_BYTES,
                    )
                    verification_error = None
                except CollectorError as exc:
                    verified = None
                    verification_error = exc
                content_type = (
                    expected.get("content_type")
                    if expected is not None
                    else None
                )
                cache_media_valid = False
                if (
                    verified is not None
                    and isinstance(content_type, str)
                    and is_supported_media_type(content_type)
                ):
                    size, _digest, prefix = verified
                    cache_media_valid = media_signature_matches(
                        content_type,
                        prefix,
                        total_size=size,
                    )
                if verification_error is not None:
                    error = verification_error
                elif verified is not None and cache_media_valid:
                    assert isinstance(content_type, str)
                    size, digest, _prefix = verified
                    error = _approved_cached_size(
                        size,
                        total_used,
                        limits,
                        limit_approver,
                        ctf_name=ctf_name,
                        local_path=local_path,
                    )
                    if error is None:
                        total_used += size
                        media_kind = content_type.split("/", 1)[0]
                        entry.update(
                            {
                                "content_type": content_type,
                                "media_kind": media_kind,
                                "sha256": digest,
                                "size": size,
                                "status": "verified",
                            }
                        )
                        manifest_media.append(entry)
                        render_media.append(
                            {
                                **entry,
                                "html_path": f"{MEDIA_DIRECTORY_NAME}/{filename}",
                            }
                        )
                        _notify(
                            progress,
                            "attachment_done",
                            ctf=ctf_name,
                            local_path=local_path,
                            size=size,
                            status="verified",
                        )
                        continue
                else:
                    error = None

                response_metadata = {}
                try:
                    if error is not None:
                        raise error
                    size, digest, _final_url = _download(
                        client,
                        media["url"],
                        output,
                        target_parts[:-1],
                        filename,
                        limits,
                        total_used,
                        ctf_name=ctf_name,
                        local_path=local_path,
                        limit_approver=limit_approver,
                        progress=progress,
                        require_media_type=True,
                        response_metadata=response_metadata,
                    )
                    total_used += size
                    content_type = response_metadata["content_type"]
                    media_kind = content_type.split("/", 1)[0]
                    entry.update(
                        {
                            "content_type": content_type,
                            "media_kind": media_kind,
                            "sha256": digest,
                            "size": size,
                            "status": "downloaded",
                        }
                    )
                    render_media.append(
                        {
                            **entry,
                            "html_path": f"{MEDIA_DIRECTORY_NAME}/{filename}",
                        }
                    )
                    _notify(
                        progress,
                        "attachment_done",
                        ctf=ctf_name,
                        local_path=local_path,
                        size=size,
                        status="downloaded",
                    )
                except CollectorError as exc:
                    safe_error = _safe_error_fields(exc, secrets)
                    entry.update(
                        {
                            "status": "failed",
                            "failure": safe_error,
                        }
                    )
                    failures.append(
                        _failure(
                            safe_error["code"],
                            safe_error["message"],
                            challenge_id=item["id"],
                            media_index=media["source_index"],
                            source_url=media["url"],
                        )
                    )
                    _notify(
                        progress,
                        "attachment_failed",
                        ctf=ctf_name,
                        local_path=local_path,
                        code=safe_error["code"],
                    )
                manifest_media.append(entry)

            challenge_html_path = "/".join(
                (*challenge_parts[1:], CHALLENGE_HTML_NAME)
            )
            archive_challenge = {
                "category": item["category"],
                "connection_info": safe_raw.get(
                    "connection_info",
                    safe_raw.get("connectionInfo"),
                ),
                "description": safe_raw.get("description", ""),
                "hints": safe_raw.get("hints"),
                "id": item["id"],
                "name": item["name"],
                "points": safe_raw.get("points"),
                "value": safe_raw.get("value"),
            }
            # A page we cannot write is one challenge's page. The manifest is
            # what tells the operator which parts of the archive are real, so
            # it is the one thing a failed page must not cost them.
            html_entry = {"path": challenge_html_path, "status": "written"}
            try:
                output.atomic_text(
                    (*challenge_parts, CHALLENGE_HTML_NAME),
                    _trusted_html_for_storage(
                        render_challenge_html(
                            archive_challenge,
                            manifest_files,
                            render_media,
                        ),
                        secrets,
                    ),
                )
            except (CollectorError, OSError) as exc:
                failure = _html_failure(exc)
                html_entry = {
                    "path": None,
                    "status": "failed",
                    "failure": failure,
                }
                failures.append(
                    _failure(
                        failure["code"],
                        failure["message"],
                        challenge_id=item["id"],
                    )
                )
            manifest_challenges.append(
                {
                    "category": item["category"],
                    "directory": "/".join(challenge_parts[1:]),
                    "files": manifest_files,
                    "html": html_entry,
                    "id": item["id"],
                    "media": manifest_media,
                    "name": item["name"],
                }
            )

        rules = _archive_rules(
            config,
            client,
            output,
            ctf_parts,
            failures,
            secrets,
        )
        failures.sort(
            key=lambda failure: (
                failure.get("challenge_id", ""),
                failure["error"]["code"],
                failure.get("attachment_index", -1),
                failure.get("media_index", -1),
                failure.get("source_url", ""),
                failure["error"]["message"],
            )
        )
        manifest = {
            "challenges": manifest_challenges,
            "ctf": config["name"],
            "failures": failures,
            "platform": config["platform"],
            "rules": rules,
            "status": "partial" if failures else "complete",
        }
        manifest = _credential_safe_failure_fields(manifest, secrets)
        manifest = _manifest_for_storage(manifest, secrets)
        output.atomic_json(manifest_parts, manifest, secrets=secrets)
        return manifest


def collect_all(configs, selected=None, *, limit_approver=None, progress=None):
    progress = _safe_progress(progress)
    # One run, one answer: the approval is settled here so that every CTF
    # below shares it instead of asking the operator again.
    limit_approver = _run_approval(limit_approver)
    if selected is not None:
        configs = [config for config in configs if config["name"] == selected]
        if not configs:
            raise CollectorError("unknown_ctf", f"unknown CTF name: {selected}")
    tokens = _preflight_configs(configs)
    if redact_secrets(PROGRESS_CONTRACT_TEXT, tokens) != PROGRESS_CONTRACT_TEXT:
        progress = None
    results = []
    for position, (config, token) in enumerate(zip(configs, tokens), 1):
        public_name = redact_secrets(config["name"], tokens)
        progress_name = display_name(public_name)
        _notify(
            progress,
            "ctf_start",
            ctf=progress_name,
            index=position,
            total=len(configs),
        )
        try:
            manifest = collect_ctf(
                config,
                _token=token,
                _secrets=tokens,
                limit_approver=limit_approver,
                progress=progress,
            )
            _notify(
                progress,
                "ctf_done",
                ctf=progress_name,
                status=manifest["status"],
                failures=len(manifest.get("failures", ())),
            )
            results.append(
                {
                    "name": public_name,
                    "partial": manifest["status"] == "partial",
                    "fail_on_partial": config["fail_on_partial"],
                    "error": None,
                }
            )
        except CollectorError as exc:
            safe_error = _credential_safe_error(
                exc.code,
                exc.message,
                tokens,
                status=exc.status,
            )
            _notify(
                progress,
                "ctf_failed",
                ctf=progress_name,
                code=safe_error.code,
            )
            results.append(
                {
                    "name": public_name,
                    "partial": True,
                    "fail_on_partial": True,
                    "error": safe_error,
                }
            )
        except OSError as exc:
            safe_error = _credential_safe_error(
                "io_error",
                f"I/O failure: {exc}",
                tokens,
            )
            _notify(
                progress,
                "ctf_failed",
                ctf=progress_name,
                code=safe_error.code,
            )
            results.append(
                {
                    "name": public_name,
                    "partial": True,
                    "fail_on_partial": True,
                    "error": safe_error,
                }
            )
    return results
