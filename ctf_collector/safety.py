import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import unicodedata
from urllib.parse import unquote, urlsplit, urlunsplit

from .errors import CollectorError


WINDOWS_DEVICE_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}
SENSITIVE_KEY_PARTS = {
    "authorization",
    "cookie",
    "password",
    "secret",
    "token",
}
WITHHELD = "[REDACTED]"
SAFE_COMPONENT = "redacted"
DISPLAY_PUNCTUATION = frozenset(" !\"&'(),-.:;+@_")
# How many collision suffixes one candidate name may be asked for before the
# next candidate is tried instead. A secret that survives every suffix of one
# name is a name we should stop spelling, not one to keep counting on.
SAFE_NAME_ATTEMPTS = 8


def sanitize_component(value, fallback="unnamed", max_length=120):
    value = unicodedata.normalize("NFKC", str(value))
    cleaned = []
    for character in value:
        category = unicodedata.category(character)
        if (
            character in "/\\:"
            or character.isspace()
            or category.startswith("C")
            or character in '<>"|?*'
        ):
            cleaned.append("_")
        elif character.isalnum() or character in "._-":
            cleaned.append(character)
        else:
            cleaned.append("_")
    result = re.sub(r"_+", "_", "".join(cleaned))
    result = result.strip(" ._")
    if result in {"", ".", ".."}:
        result = fallback
    stem = result.split(".", 1)[0].upper()
    if stem in WINDOWS_DEVICE_NAMES:
        result = f"_{result}"
    if len(result.encode("utf-8")) > max_length:
        digest = hashlib.sha256(result.encode("utf-8")).hexdigest()[:10]
        budget = max_length - 12
        prefix = []
        used_bytes = 0
        for character in result:
            encoded_length = len(character.encode("utf-8"))
            if used_bytes + encoded_length > budget:
                break
            prefix.append(character)
            used_bytes += encoded_length
        result = f"{''.join(prefix)}__{digest}"
    return result


def display_text(value, max_length=80):
    """Text that is safe to write to a terminal.

    Progress output interleaves attacker-influenced names with our own labels,
    so a name must never be able to end the line, move the cursor, or start an
    escape sequence. Only a plain space survives from the whitespace class.
    """
    value = unicodedata.normalize("NFKC", str(value))
    cleaned = []
    for character in value:
        if character != " " and (
            character.isspace()
            or unicodedata.category(character).startswith("C")
        ):
            cleaned.append("_")
        else:
            cleaned.append(character)
    result = "".join(cleaned)
    if len(result) > max_length:
        result = result[: max(0, max_length - 3)] + "..."
    return result


def display_name(value, max_length=80):
    """A value chosen by the API that is safe to name on the terminal.

    The display boundary is closed by default: only a plain scalar of ordinary
    text survives. A mapping or a list is a structure we never meant to print,
    and a value shaped like a URL, a query, a fragment or a flag carries the
    very thing the display exists to withhold, so those are replaced whole
    instead of being trimmed into something that merely looks harmless.
    """
    if not isinstance(value, (str, int, float)):
        return WITHHELD
    text = unicodedata.normalize("NFKC", str(value))
    if any(
        character not in DISPLAY_PUNCTUATION
        and not character.isalnum()
        and not unicodedata.category(character).startswith("M")
        for character in text
    ):
        return WITHHELD
    return display_text(text, max_length)


def display_path(value, max_length=80):
    """An output path that is safe to name on the terminal.

    A path describes our own layout, so unlike a name it keeps its separators.
    A query or a fragment is never part of that layout, so both are dropped:
    otherwise a signed URL smuggled into a file name would put its signature
    on the terminal.
    """
    text = str(value)
    for separator in ("?", "#"):
        text = text.split(separator, 1)[0]
    return display_text(text, max_length)


def ctf_directory_name(name):
    return sanitize_component(name, "ctf")


def temporary_output_name(name):
    """The name a document is written under while it is not yet the document.

    It is derived from the target rather than chosen, so every caller that has
    to reason about what reaches the disk - the writer here and the boundary
    that settles a name before the write - derives it the same way.
    """
    return f".{name}.part"


def unique_name(name, used, *, keep_extension=True):
    """The first spelling of `name` that this directory has not used yet.

    An attachment keeps its extension, so the suffix goes before it rather
    than changing what the file claims to be. A directory has no extension to
    keep, so the suffix goes at the end of it.
    """
    candidate = name
    stem, suffix = os.path.splitext(name) if keep_extension else (name, "")
    counter = 2
    while candidate.casefold() in used:
        candidate = f"{stem}__{counter}{suffix}"
        counter += 1
    used.add(candidate.casefold())
    return candidate


def filename_from_url(url):
    path = unquote(urlsplit(url).path)
    return path.rsplit("/", 1)[-1] or "attachment"


def redact_url(url, *, force=False):
    parsed = urlsplit(str(url))
    if parsed.scheme.lower() in {"http", "https"}:
        netloc = parsed.netloc
        if parsed.username is not None or parsed.password is not None:
            hostname = parsed.hostname or ""
            if ":" in hostname:
                hostname = f"[{hostname}]"
            try:
                port = parsed.port
            except ValueError:
                port = None
            netloc = f"{hostname}:{port}" if port is not None else hostname
        return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))
    if (force or str(url).startswith("/") or str(url).startswith("./")) and (
        parsed.query or parsed.fragment
    ):
        return urlunsplit(("", "", parsed.path, "", ""))
    return str(url)


def redact_secrets(value, secrets=()):
    """Remove every secret, including the spellings that only look different.

    Names travel on to `sanitize_component` and to the display, and both
    normalize first, so a token written in a compatibility form is the token:
    it is redacted here rather than reconstituted downstream. Text that holds
    no secret keeps its own spelling, because normalizing it would rewrite a
    value we were only asked to inspect.
    """
    result = str(value)
    for secret in secrets:
        if not secret:
            continue
        secret = str(secret)
        result = result.replace(secret, WITHHELD)
        normalized = unicodedata.normalize("NFKC", result)
        if secret in normalized:
            result = normalized.replace(secret, WITHHELD)
    return result


def _spells_secret(component, secrets):
    """Whether an already sanitized component spells a secret.

    `sanitize_component` normalized it, so the component's own spelling is the
    last one left to check.
    """
    return any(secret and str(secret) in component for secret in secrets)


def sanitize_component_without_secrets(
    value,
    secrets=(),
    fallback="unnamed",
    max_length=120,
):
    """A path component that cannot spell a secret, however it was written.

    Redacting before sanitizing is not enough on its own, because sanitizing
    folds a run of separators: `abc__def` and `abc//def` both come out of it
    spelling a token written `abc_def` that redaction never had the chance to
    match. So the component is checked once more afterwards, and one that
    spells a secret is replaced whole - trimming it would keep the very part
    we withheld. A fallback is a name like any other, so it is checked the
    same way, and when nothing is left to name the component with we refuse
    instead of writing the secret into a path.
    """
    candidates = (
        sanitize_component(redact_secrets(value, secrets), fallback, max_length),
        sanitize_component(fallback, SAFE_COMPONENT, max_length),
        SAFE_COMPONENT,
    )
    for candidate in candidates:
        if not _spells_secret(candidate, secrets):
            return candidate
    raise CollectorError(
        "unsafe_name",
        "cannot name an output path without disclosing a token",
    )


def path_spells_secret(parts, secrets=()):
    """Whether the finished path spells a secret no component spells alone.

    A component is checked on its own, but what gets written, recorded and
    displayed is the whole path, and the joins are ours: an id joined to a
    name, a category joined to a directory, a directory joined to the file
    beneath it. Any of them can complete a token that no single component ever
    contained. Each component was normalized as it was sanitized and the
    separators are plain ASCII, so the join carries no new spelling of its
    own - the normalized form is checked all the same, because a path that
    only needs normalizing to spell the token is the token.
    """
    joined = "/".join(str(part) for part in parts)
    return _spells_secret(joined, secrets) or _spells_secret(
        unicodedata.normalize("NFKC", joined),
        secrets,
    )


def _name_candidates(preferred, seed, fallback, max_length):
    """Bounded deterministic names for one component, most wanted first.

    The name the input asked for keeps the tree readable, so it is tried
    first. What follows carries a digest of that same input: it names the
    component without quoting it, it is the same on every run so a second
    collection recognizes what the first one wrote, and it keeps two
    challenges apart where the bare fallback word would merge them.
    """
    digest = hashlib.sha256(str(seed).encode("utf-8")).hexdigest()[:16]
    return (
        preferred,
        sanitize_component(f"{fallback}_{digest}", SAFE_COMPONENT, max_length),
        f"{SAFE_COMPONENT}_{digest}",
        sanitize_component(fallback, SAFE_COMPONENT, max_length),
        SAFE_COMPONENT,
    )


def safe_unique_component(
    parent_parts,
    preferred,
    used,
    secrets=(),
    *,
    fallback="unnamed",
    seed=None,
    children=(),
    siblings=(),
    keep_extension=True,
    max_length=120,
):
    """A name that is unique here and leaves no path here spelling a secret.

    The component is chosen for the paths it completes rather than for itself:
    the parent it hangs under, the fixed children written beneath it, the
    temporary names derived from it beside it and the suffix that resolves a
    collision are all part of what reaches the disk, so all of them are
    checked, and they are checked after the suffix is chosen rather than
    before. A name that completes a secret is passed over for the next
    candidate; when the bounded list of candidates runs out we refuse, because
    a path we cannot name safely is one we must not write.
    """
    seed = preferred if seed is None else seed
    for candidate in _name_candidates(preferred, seed, fallback, max_length):
        # `unique_name` reserves what it hands back, so asking a copy of the
        # reservations again yields the next suffix rather than the name that
        # was just refused.
        offered = set(used)
        for _attempt in range(SAFE_NAME_ATTEMPTS):
            name = unique_name(candidate, offered, keep_extension=keep_extension)
            paths = [(*parent_parts, name)]
            paths.extend((*parent_parts, name, *child) for child in children)
            paths.extend(
                (*parent_parts, f"{name}{suffix}") for suffix in siblings
            )
            if not any(path_spells_secret(path, secrets) for path in paths):
                used.add(name.casefold())
                return name
    raise CollectorError(
        "unsafe_name",
        "cannot name an output path without disclosing a token",
    )


def _normalized_key_parts(key):
    value = str(key)
    value = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", value)
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return tuple(
        part for part in re.split(r"[^a-z0-9]+", value.casefold()) if part
    )


def _sensitive_key(key):
    parts = _normalized_key_parts(key)
    return bool(
        SENSITIVE_KEY_PARTS.intersection(parts)
        or any(
            parts[index : index + 2] == ("api", "key")
            for index in range(max(0, len(parts) - 1))
        )
    )


def safe_metadata(value, key="", secrets=()):
    if key and _sensitive_key(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {
            str(item_key): safe_metadata(item_value, str(item_key), secrets)
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [safe_metadata(item, key, secrets) for item in value]
    if isinstance(value, str):
        lowered_key = str(key).lower()
        url_value = (
            lowered_key in {
                "files",
                "href",
                "location",
                "path",
                "source_url",
                "detail_url",
                "detailurl",
                "download",
            }
            or lowered_key.endswith("_url")
            or lowered_key == "url"
        )
        return redact_url(redact_secrets(value, secrets), force=url_value)
    return value


def _dirfd_capability_error():
    if os.name != "posix":
        return "safe output requires POSIX directory file descriptors"
    for name in ("O_DIRECTORY", "O_NOFOLLOW"):
        if not hasattr(os, name):
            return f"safe output requires {name}"
    required_dir_fd = (os.open, os.mkdir, os.stat, os.unlink, os.rename)
    if any(function not in os.supports_dir_fd for function in required_dir_fd):
        return "safe output requires open/mkdir/stat/unlink/rename dir_fd support"
    if os.stat not in os.supports_follow_symlinks:
        return "safe output requires no-follow stat support"
    return None


class SafeOutput:
    """Directory-fd anchored output tree that never follows a path symlink."""

    def __init__(self, root):
        capability_error = _dirfd_capability_error()
        if capability_error:
            raise CollectorError("unsupported_platform", capability_error)
        self.root_path = Path(root)
        if not self.root_path.is_absolute():
            raise CollectorError(
                "unsafe_path",
                "output root must be an absolute path",
            )
        self._directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        self._root_fd = self._open_absolute(self.root_path, create=True)
        self._root_identity = self._identity(self._root_fd)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    def close(self):
        if self._root_fd is not None:
            os.close(self._root_fd)
            self._root_fd = None

    @staticmethod
    def _identity(descriptor):
        info = os.fstat(descriptor)
        return info.st_dev, info.st_ino

    def _open_absolute(self, path, *, create):
        try:
            descriptor = os.open("/", self._directory_flags)
        except OSError as exc:
            raise CollectorError(
                "unsafe_path",
                f"cannot anchor output root: {exc}",
            ) from exc
        try:
            for component in path.parts[1:]:
                try:
                    child = os.open(
                        component,
                        self._directory_flags,
                        dir_fd=descriptor,
                    )
                except FileNotFoundError:
                    if not create:
                        raise
                    try:
                        os.mkdir(component, mode=0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                    child = os.open(
                        component,
                        self._directory_flags,
                        dir_fd=descriptor,
                    )
                except OSError as exc:
                    if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                        raise CollectorError(
                            "unsafe_path",
                            "output root contains a symlink or non-directory component",
                        ) from exc
                    raise CollectorError(
                        "unsafe_path",
                        f"cannot open output root component: {exc}",
                    ) from exc
                os.close(descriptor)
                descriptor = child
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    @staticmethod
    def _parts(parts):
        checked = tuple(str(part) for part in parts)
        if any(
            not part
            or part in {".", ".."}
            or "/" in part
            or os.sep in part
            or (os.altsep is not None and os.altsep in part)
            for part in checked
        ):
            raise CollectorError("unsafe_path", "invalid output path component")
        return checked

    def _check_root_path(self):
        try:
            current = self._open_absolute(self.root_path, create=False)
        except FileNotFoundError as exc:
            raise CollectorError(
                "unsafe_path",
                "output root disappeared during collection",
            ) from exc
        try:
            if self._identity(current) != self._root_identity:
                raise CollectorError(
                    "unsafe_path",
                    "output root changed during collection",
                )
        finally:
            os.close(current)

    def open_directory(self, parts=(), *, create=False):
        parts = self._parts(parts)
        self._check_root_path()
        descriptor = os.dup(self._root_fd)
        try:
            for component in parts:
                try:
                    child = os.open(
                        component,
                        self._directory_flags,
                        dir_fd=descriptor,
                    )
                except FileNotFoundError:
                    if not create:
                        raise
                    try:
                        os.mkdir(component, mode=0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                    child = os.open(
                        component,
                        self._directory_flags,
                        dir_fd=descriptor,
                    )
                except OSError as exc:
                    if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                        raise CollectorError(
                            "unsafe_path",
                            "output path contains a symlink or non-directory component",
                        ) from exc
                    raise CollectorError(
                        "unsafe_path",
                        f"cannot open output directory: {exc}",
                    ) from exc
                os.close(descriptor)
                descriptor = child
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def ensure_directory(self, parts):
        descriptor = self.open_directory(parts, create=True)
        os.close(descriptor)

    def revalidate_directory(self, parts, descriptor):
        current = self.open_directory(parts, create=False)
        try:
            if self._identity(current) != self._identity(descriptor):
                raise CollectorError(
                    "unsafe_path",
                    "output directory changed during write",
                )
        finally:
            os.close(current)

    @staticmethod
    def _entry_info(descriptor, name):
        try:
            return os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return None

    @classmethod
    def _ensure_regular_or_missing(cls, descriptor, name):
        info = cls._entry_info(descriptor, name)
        if info is None:
            return None
        if stat.S_ISLNK(info.st_mode):
            raise CollectorError("unsafe_path", "output file is a symlink")
        if not stat.S_ISREG(info.st_mode):
            raise CollectorError("unsafe_path", "output file is not a regular file")
        return info

    @classmethod
    def _remove_regular_if_present(cls, descriptor, name):
        info = cls._ensure_regular_or_missing(descriptor, name)
        if info is not None:
            os.unlink(name, dir_fd=descriptor)

    def read_bytes(self, parts):
        parts = self._parts(parts)
        directory = self.open_directory(parts[:-1], create=False)
        try:
            self._ensure_regular_or_missing(directory, parts[-1])
            try:
                descriptor = os.open(
                    parts[-1],
                    os.O_RDONLY | os.O_NOFOLLOW,
                    dir_fd=directory,
                )
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    raise CollectorError("unsafe_path", "output file is a symlink") from exc
                raise
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode):
                    raise CollectorError(
                        "unsafe_path",
                        "output file is not a regular file",
                    )
                with os.fdopen(descriptor, "rb") as stream:
                    descriptor = None
                    return stream.read()
            finally:
                if descriptor is not None:
                    os.close(descriptor)
        finally:
            os.close(directory)

    def hash_file(self, parts, maximum):
        parts = self._parts(parts)
        try:
            directory = self.open_directory(parts[:-1], create=False)
        except FileNotFoundError:
            return None
        try:
            info = self._ensure_regular_or_missing(directory, parts[-1])
            if info is None:
                return None
            try:
                descriptor = os.open(
                    parts[-1],
                    os.O_RDONLY | os.O_NOFOLLOW,
                    dir_fd=directory,
                )
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    raise CollectorError("unsafe_path", "output file is a symlink") from exc
                raise
            digest = hashlib.sha256()
            size = 0
            try:
                with os.fdopen(descriptor, "rb") as stream:
                    descriptor = None
                    while True:
                        chunk = stream.read(128 * 1024)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > maximum:
                            raise CollectorError(
                                "file_too_large",
                                "existing file exceeds file limit",
                            )
                        digest.update(chunk)
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            return size, digest.hexdigest()
        finally:
            os.close(directory)

    def open_temporary(self, parent_parts, target_name, temporary_name):
        parent_parts = self._parts(parent_parts)
        target_name, temporary_name = self._parts((target_name, temporary_name))
        directory = self.open_directory(parent_parts, create=True)
        try:
            self._ensure_regular_or_missing(directory, target_name)
            self._remove_regular_if_present(directory, temporary_name)
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory,
            )
            return directory, descriptor, self._identity(descriptor)
        except BaseException:
            os.close(directory)
            raise

    def cleanup_temporary(self, directory, temporary_name):
        self._remove_regular_if_present(directory, temporary_name)

    def cleanup_committed(self, directory, target_name, target_identity):
        info = self._entry_info(directory, target_name)
        if (
            info is not None
            and stat.S_ISREG(info.st_mode)
            and (info.st_dev, info.st_ino) == target_identity
        ):
            os.unlink(target_name, dir_fd=directory)
        os.fsync(directory)

    def replace_temporary(
        self,
        parent_parts,
        directory,
        temporary_name,
        target_name,
        temporary_identity,
    ):
        self.revalidate_directory(parent_parts, directory)
        info = self._ensure_regular_or_missing(directory, temporary_name)
        if info is None or (info.st_dev, info.st_ino) != temporary_identity:
            raise CollectorError(
                "unsafe_path",
                "temporary output file changed during write",
            )
        self._ensure_regular_or_missing(directory, target_name)
        try:
            os.replace(
                temporary_name,
                target_name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
            )
        except (TypeError, NotImplementedError) as exc:
            raise CollectorError(
                "unsupported_platform",
                "safe output requires atomic replace with directory file descriptors",
            ) from exc
        try:
            os.fsync(directory)
            self.revalidate_directory(parent_parts, directory)
        except BaseException as exc:
            try:
                self.cleanup_committed(
                    directory,
                    target_name,
                    temporary_identity,
                )
            except BaseException as cleanup_exc:
                raise CollectorError(
                    "unsafe_path",
                    "output directory changed after commit and cleanup failed",
                ) from cleanup_exc
            if isinstance(exc, CollectorError) and exc.code == "unsafe_path":
                raise
            if isinstance(exc, (FileNotFoundError, NotADirectoryError)):
                raise CollectorError(
                    "unsafe_path",
                    "output directory changed after commit",
                ) from exc
            raise

    def atomic_json(self, parts, value):
        parts = self._parts(parts)
        payload = (
            json.dumps(
                value,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
                separators=(",", ": "),
            )
            + "\n"
        ).encode("utf-8")
        temporary_name = temporary_output_name(parts[-1])
        directory = None
        try:
            directory, descriptor, identity = self.open_temporary(
                parts[:-1],
                parts[-1],
                temporary_name,
            )
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    descriptor = None
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            self.replace_temporary(
                parts[:-1],
                directory,
                temporary_name,
                parts[-1],
                identity,
            )
        except BaseException:
            if directory is not None:
                self.cleanup_temporary(directory, temporary_name)
            raise
        finally:
            if directory is not None:
                os.close(directory)
