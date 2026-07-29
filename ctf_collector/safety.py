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


def ctf_directory_name(name):
    return sanitize_component(name, "ctf")


def unique_name(name, used):
    candidate = name
    stem, suffix = os.path.splitext(name)
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
    result = str(value)
    for secret in secrets:
        if secret:
            result = result.replace(str(secret), "[REDACTED]")
    return result


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
        temporary_name = f".{parts[-1]}.part"
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
