import json
from pathlib import Path
from urllib.parse import urlsplit

from .errors import CollectorError
from .http import normalized_origin, validated_url
from .safety import ctf_directory_name


DEFAULT_RETRIES = {
    "max_attempts": 3,
    "backoff_seconds": 0.5,
    "max_retry_after_seconds": 30.0,
}
DEFAULT_LIMITS = {
    "page_size": 100,
    "max_pages": 100,
    "max_file_bytes": 100 * 1024 * 1024,
    "max_total_bytes": 1024 * 1024 * 1024,
    "max_redirects": 5,
    "max_metadata_bytes": 16 * 1024 * 1024,
}


def _number(mapping, key, default, minimum, maximum, integer=False):
    value = mapping.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CollectorError("invalid_config", f"{key} must be a number")
    if integer and not isinstance(value, int):
        raise CollectorError("invalid_config", f"{key} must be an integer")
    if value < minimum or value > maximum:
        raise CollectorError(
            "invalid_config",
            f"{key} must be between {minimum} and {maximum}",
        )
    return int(value) if integer else float(value)


def load_config(path):
    config_path = Path(path).resolve()
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CollectorError("invalid_config", f"cannot read config: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("ctfs"), list):
        raise CollectorError("invalid_config", "config must contain a ctfs array")
    if not raw["ctfs"]:
        raise CollectorError("invalid_config", "ctfs must not be empty")

    default_partial = raw.get("fail_on_partial", True)
    if not isinstance(default_partial, bool):
        raise CollectorError("invalid_config", "fail_on_partial must be boolean")
    ctfs = []
    names = set()
    output_directories = set()
    for index, item in enumerate(raw["ctfs"]):
        if not isinstance(item, dict):
            raise CollectorError("invalid_config", f"ctfs[{index}] must be an object")
        for required in ("name", "platform", "base_url", "token_file", "output_root"):
            if not isinstance(item.get(required), str) or not item[required]:
                raise CollectorError(
                    "invalid_config",
                    f"ctfs[{index}].{required} must be a non-empty string",
                )
        if item["name"] in names:
            raise CollectorError("invalid_config", f"duplicate CTF name: {item['name']}")
        names.add(item["name"])
        output_root = _relative(config_path, item["output_root"])
        output_directory = (
            output_root,
            ctf_directory_name(item["name"]).casefold(),
        )
        if output_directory in output_directories:
            raise CollectorError(
                "invalid_config",
                "CTF names collide in the same output directory after sanitization",
            )
        output_directories.add(output_directory)
        platform = item["platform"].lower()
        if platform not in {"ctfd", "rctf"}:
            raise CollectorError("invalid_config", "platform must be ctfd or rctf")
        base_url = validated_url(item["base_url"]).rstrip("/")
        if urlsplit(base_url).query:
            raise CollectorError("invalid_config", "base_url must not contain a query")

        tls_raw = item.get("tls", {})
        if not isinstance(tls_raw, dict):
            raise CollectorError("invalid_config", "tls must be an object")
        verify = tls_raw.get("verify", True)
        if not isinstance(verify, bool):
            raise CollectorError("invalid_config", "tls.verify must be boolean")
        tls = {"verify": verify}
        if "ca_file" in tls_raw:
            if not isinstance(tls_raw["ca_file"], str) or not tls_raw["ca_file"]:
                raise CollectorError("invalid_config", "tls.ca_file must be a path")
            tls["ca_file"] = str(_relative(config_path, tls_raw["ca_file"]))

        timeout_raw = item.get("timeouts", {})
        if not isinstance(timeout_raw, dict):
            raise CollectorError("invalid_config", "timeouts must be an object")
        timeout = _number(
            timeout_raw, "request_seconds", 30.0, 0.1, 300.0
        )

        retries_raw = item.get("retries", {})
        if not isinstance(retries_raw, dict):
            raise CollectorError("invalid_config", "retries must be an object")
        retries = {
            "max_attempts": _number(
                retries_raw, "max_attempts", 3, 1, 10, integer=True
            ),
            "backoff_seconds": _number(
                retries_raw, "backoff_seconds", 0.5, 0, 60
            ),
            "max_retry_after_seconds": _number(
                retries_raw, "max_retry_after_seconds", 30, 0, 300
            ),
        }

        limits_raw = item.get("limits", {})
        if not isinstance(limits_raw, dict):
            raise CollectorError("invalid_config", "limits must be an object")
        limits = {
            "page_size": _number(
                limits_raw, "page_size", 100, 1, 100, integer=True
            ),
            "max_pages": _number(
                limits_raw, "max_pages", 100, 1, 1000, integer=True
            ),
            "max_file_bytes": _number(
                limits_raw,
                "max_file_bytes",
                DEFAULT_LIMITS["max_file_bytes"],
                1,
                1024 ** 4,
                integer=True,
            ),
            "max_total_bytes": _number(
                limits_raw,
                "max_total_bytes",
                DEFAULT_LIMITS["max_total_bytes"],
                1,
                1024 ** 5,
                integer=True,
            ),
            "max_redirects": _number(
                limits_raw, "max_redirects", 5, 0, 10, integer=True
            ),
            "max_metadata_bytes": _number(
                limits_raw,
                "max_metadata_bytes",
                DEFAULT_LIMITS["max_metadata_bytes"],
                1024,
                1024 ** 3,
                integer=True,
            ),
        }
        if limits["max_total_bytes"] < limits["max_file_bytes"]:
            # A smaller total is useful and well-defined, so do not reject it.
            pass

        allowed = item.get("unauthenticated_attachment_origins", [])
        if not isinstance(allowed, list) or not all(
            isinstance(origin, str) for origin in allowed
        ):
            raise CollectorError(
                "invalid_config",
                "unauthenticated_attachment_origins must be an array of URLs",
            )
        for origin in allowed:
            normalized_origin(origin)

        fail_on_partial = item.get("fail_on_partial", default_partial)
        if not isinstance(fail_on_partial, bool):
            raise CollectorError("invalid_config", "fail_on_partial must be boolean")

        ctfs.append(
            {
                "name": item["name"],
                "platform": platform,
                "base_url": base_url,
                "token_file": _relative(config_path, item["token_file"]),
                "output_root": output_root,
                "tls": tls,
                "timeout": timeout,
                "retries": retries,
                "limits": limits,
                "unauthenticated_attachment_origins": allowed,
                "fail_on_partial": fail_on_partial,
            }
        )
    return ctfs


def _relative(config_path, value):
    path = Path(value)
    if not path.is_absolute():
        path = config_path.parent / path
    return path.resolve()
