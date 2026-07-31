import hashlib
import hmac
from http.client import HTTPException
import json
import os
import re
from pathlib import Path
from urllib.parse import quote, urlsplit

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
    display_name,
    filename_from_url,
    path_spells_secret,
    redact_url,
    redact_secrets,
    SafeOutput,
    safe_metadata,
    safe_unique_component,
    sanitize_component_without_secrets,
    ctf_directory_name,
    temporary_output_name,
)


RCTF_LIST_PATHS = ("/api/v1/challs", "/api/v1/challenges", "/api/challs")
MAX_TOKEN_BYTES = 64 * 1024
SOURCE_IDENTITY_CONTEXT = b"ctf-challenge-collector source identity\x00"
MANIFEST_NAME = "manifest.json"
CHALLENGE_NAME = "challenge.json"
# What every run writes at a fixed place below a directory it named. A name is
# settled against these as well as against itself, because the join is ours and
# it is the finished path that reaches the disk.
CTF_DIRECTORY_CHILDREN = (
    (MANIFEST_NAME,),
    (temporary_output_name(MANIFEST_NAME),),
)
CHALLENGE_DIRECTORY_CHILDREN = (
    (CHALLENGE_NAME,),
    (temporary_output_name(CHALLENGE_NAME),),
    ("files",),
)
# An attachment is written beside its target rather than beneath it, so its
# temporary name is a suffix of the name we are choosing.
ATTACHMENT_TEMPORARY_SUFFIX = ".part"


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


def _notify(progress, event, **fields):
    """Report a milestone so a long run never looks hung.

    Only values that already passed redaction reach the reporter, because the
    display is as public as any other terminal output.
    """
    if progress is None:
        return
    progress({"event": event, **fields})


def _collection(payload):
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        raise CollectorError("invalid_api_data", "challenge list is not an array/object")
    for key in ("data", "challs", "challenges"):
        if key in payload:
            value = payload[key]
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
            if isinstance(value, dict):
                for nested in ("challs", "challenges", "data"):
                    if isinstance(value.get(nested), list):
                        return [
                            item for item in value[nested] if isinstance(item, dict)
                        ]
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
    value = challenge.get("id", challenge.get("_id"))
    if value is None or isinstance(value, (dict, list, bool)):
        raise CollectorError("invalid_api_data", "challenge has no scalar id")
    return str(value)


def _detail_url(challenge, client):
    candidates = []
    for key in ("detail_url", "detailUrl"):
        if isinstance(challenge.get(key), str):
            candidates.append(challenge[key])
    links = challenge.get("_links")
    if isinstance(links, dict):
        detail = links.get("detail")
        if isinstance(detail, str):
            candidates.append(detail)
        elif isinstance(detail, dict) and isinstance(detail.get("href"), str):
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
    challenge_id=None,
    source_url=None,
):
    failure = {"error": {"code": code, "message": message}}
    if attachment_index is not None:
        failure["attachment_index"] = attachment_index
    if challenge_id is not None:
        failure["challenge_id"] = str(challenge_id)
    if source_url is not None:
        failure["source_url"] = redact_url(source_url)
    return failure


def _read_old_manifest(output, parts):
    try:
        payload = output.read_bytes(parts)
    except FileNotFoundError:
        return {}
    try:
        manifest = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    entries = {}
    if not isinstance(manifest, dict):
        return entries
    for challenge in manifest.get("challenges", []):
        if not isinstance(challenge, dict):
            continue
        for item in challenge.get("files", []):
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
                }
    return entries


def _source_identity(source_url, token):
    return hmac.new(
        token.encode("ascii"),
        SOURCE_IDENTITY_CONTEXT + source_url.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _verified_existing(output, parts, expected, source_identity, maximum):
    if not expected or not hmac.compare_digest(
        expected["source_identity"],
        source_identity,
    ):
        return None
    try:
        verified = output.hash_file(parts, maximum)
    except OSError:
        return None
    except CollectorError as exc:
        if exc.code == "file_too_large":
            return None
        raise
    if verified is None:
        return None
    size, digest = verified
    if size == expected["size"] and digest == expected["sha256"]:
        return size, digest
    return None


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
    try:
        declared = None
        content_length = response.headers.get("Content-Length")
        if content_length is not None:
            if re.fullmatch(r"[0-9]+", content_length) is None:
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
        page_items = _collection(payload)
        signature = tuple(_challenge_id(item) for item in page_items)
        if page_items and signature in seen_signatures:
            failures.append(
                _failure(
                    "pagination_no_progress",
                    "CTFd pagination repeated a challenge page",
                )
            )
            break
        if page_items:
            seen_signatures.add(signature)
        new_count = 0
        for item in page_items:
            challenge_id = _challenge_id(item)
            if challenge_id not in seen_ids:
                seen_ids.add(challenge_id)
                challenges.append(item)
                new_count += 1
        if page_items and new_count == 0:
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
            detailed.append({**summary, **_object(payload)})
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
        detail_url = _detail_url(summary, client)
        if detail_url is None:
            detailed.append(summary)
            continue
        challenge_id = _challenge_id(summary)
        try:
            payload, _ = client.get_json(detail_url)
            detailed.append(_object(payload))
        except CollectorError as exc:
            failures.append(
                _failure(exc.code, exc.message, challenge_id=challenge_id)
            )
            detailed.append(summary)
    return detailed


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
        *((directory_name, *child) for child in CTF_DIRECTORY_CHILDREN),
    ]
    if any(secret and secret in config["name"] for secret in secrets) or any(
        path_spells_secret(path, secrets) for path in paths
    ):
        raise CollectorError(
            "invalid_config",
            "CTF name must not contain an authentication token",
        )
    return directory_name


def _preflight_configs(configs):
    tokens = [_read_token(config["token_file"]) for config in configs]
    output_directories = set()
    for config in configs:
        directory_name = _validated_ctf_directory(config, tokens)
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


def collect_ctf(config, *, _token=None, limit_approver=None, progress=None):
    progress = _safe_progress(progress)
    token = _read_token(config["token_file"]) if _token is None else _token
    ctf_name = _validated_ctf_directory(config, (token,))
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
        used_directories = {}
        for raw in raw_challenges:
            challenge_id = redact_secrets(_challenge_id(raw), (token,))
            name = safe_metadata(
                str(raw.get("name", raw.get("title", "unnamed"))),
                secrets=(token,),
            )
            category = safe_metadata(
                str(raw.get("category", "uncategorized")),
                secrets=(token,),
            )
            base_directory = (
                f"{sanitize_component_without_secrets(challenge_id, (token,), 'id')}-"
                f"{sanitize_component_without_secrets(name, (token,), 'challenge')}"
            )
            category_name = sanitize_component_without_secrets(
                category,
                (token,),
                "uncategorized",
            )
            # Each component is safe by itself; the directory is settled
            # against the path it completes, including the files that will be
            # written under it and the suffix that resolves a collision.
            directory_name = safe_unique_component(
                (*ctf_parts, category_name),
                base_directory,
                used_directories.setdefault(category_name.casefold(), set()),
                (token,),
                fallback="challenge",
                seed=f"{challenge_id}/{name}",
                children=CHALLENGE_DIRECTORY_CHILDREN,
                keep_extension=False,
            )
            prepared.append(
                {
                    "id": challenge_id,
                    "name": name,
                    "category": category,
                    "category_name": category_name,
                    "directory_name": directory_name,
                    "raw": raw,
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
            output.atomic_json(
                (*challenge_parts, CHALLENGE_NAME),
                {
                    "category": item["category"],
                    "id": item["id"],
                    "name": item["name"],
                    "platform": config["platform"],
                    "raw": safe_metadata(item["raw"], secrets=(token,)),
                },
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
            used_filenames = set()
            for attachment in attachments:
                filename = safe_unique_component(
                    (*challenge_parts, "files"),
                    sanitize_component_without_secrets(
                        attachment["name"],
                        (token,),
                        "attachment",
                    ),
                    used_filenames,
                    (token,),
                    fallback="attachment",
                    seed=attachment["name"],
                    siblings=(ATTACHMENT_TEMPORARY_SUFFIX,),
                )
                target_parts = (*challenge_parts, "files", filename)
                local_path = "/".join(target_parts[1:])
                source_url = redact_url(attachment["url"])
                source_identity = _source_identity(attachment["url"], token)
                entry = {
                    "local_path": local_path,
                    "source_identity": source_identity,
                    "source_url": source_url,
                }
                verified = _verified_existing(
                    output,
                    target_parts,
                    old_files.get(local_path),
                    source_identity,
                    limits["max_file_bytes"],
                )
                if verified is not None:
                    size, digest = verified
                    if total_used + size > limits["max_total_bytes"]:
                        error = CollectorError(
                            "total_too_large", "attachments exceed total limit"
                        )
                    else:
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
                    entry.update(
                        {
                            "status": "failed",
                            "failure": {"code": exc.code, "message": exc.message},
                        }
                    )
                    failures.append(
                        _failure(
                            exc.code,
                            exc.message,
                            challenge_id=item["id"],
                            source_url=attachment["url"],
                        )
                    )
                    _notify(
                        progress,
                        "attachment_failed",
                        ctf=ctf_name,
                        local_path=local_path,
                        code=exc.code,
                    )
                manifest_files.append(entry)
            manifest_challenges.append(
                {
                    "category": item["category"],
                    "directory": "/".join(challenge_parts[1:]),
                    "files": manifest_files,
                    "id": item["id"],
                    "name": item["name"],
                }
            )

        failures.sort(
            key=lambda failure: (
                failure.get("challenge_id", ""),
                failure["error"]["code"],
                failure.get("attachment_index", -1),
                failure.get("source_url", ""),
                failure["error"]["message"],
            )
        )
        manifest = {
            "challenges": manifest_challenges,
            "ctf": config["name"],
            "failures": failures,
            "platform": config["platform"],
            "status": "partial" if failures else "complete",
        }
        manifest = safe_metadata(manifest, secrets=(token,))
        output.atomic_json(manifest_parts, manifest)
        return manifest


def collect_all(configs, selected=None, *, limit_approver=None, progress=None):
    progress = _safe_progress(progress)
    if selected is not None:
        configs = [config for config in configs if config["name"] == selected]
        if not configs:
            raise CollectorError("unknown_ctf", f"unknown CTF name: {selected}")
    tokens = _preflight_configs(configs)
    results = []
    for position, (config, token) in enumerate(zip(configs, tokens), 1):
        display_name = ctf_directory_name(config["name"])
        _notify(
            progress,
            "ctf_start",
            ctf=display_name,
            index=position,
            total=len(configs),
        )
        try:
            manifest = collect_ctf(
                config,
                _token=token,
                limit_approver=limit_approver,
                progress=progress,
            )
            _notify(
                progress,
                "ctf_done",
                ctf=display_name,
                status=manifest["status"],
                failures=len(manifest.get("failures", ())),
            )
            results.append(
                {
                    "name": config["name"],
                    "partial": manifest["status"] == "partial",
                    "fail_on_partial": config["fail_on_partial"],
                    "error": None,
                }
            )
        except CollectorError as exc:
            _notify(progress, "ctf_failed", ctf=display_name, code=exc.code)
            results.append(
                {
                    "name": config["name"],
                    "partial": True,
                    "fail_on_partial": True,
                    "error": exc,
                }
            )
        except OSError as exc:
            _notify(progress, "ctf_failed", ctf=display_name, code="io_error")
            results.append(
                {
                    "name": config["name"],
                    "partial": True,
                    "fail_on_partial": True,
                    "error": CollectorError(
                        "io_error",
                        f"I/O failure: {exc}",
                    ),
                }
            )
    return results
