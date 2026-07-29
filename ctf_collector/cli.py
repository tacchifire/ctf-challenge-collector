import argparse
import json
import os
from pathlib import Path
import sys

from .collector import collect_all
from .config import load_config
from .errors import CollectorError


EXAMPLE_CONFIG = {
    "ctfs": [
        {
            "name": "example-ctfd",
            "platform": "ctfd",
            "base_url": "https://ctf.example.invalid",
            "token_file": "./secrets/example-ctfd.token",
            "output_root": "./collected",
            "tls": {"verify": True},
            "timeouts": {"request_seconds": 30},
            "retries": {
                "max_attempts": 3,
                "backoff_seconds": 0.5,
                "max_retry_after_seconds": 30,
            },
            "limits": {
                "page_size": 100,
                "max_pages": 100,
                "max_file_bytes": 104857600,
                "max_total_bytes": 1073741824,
                "max_redirects": 5,
                "max_metadata_bytes": 16777216,
            },
            "unauthenticated_attachment_origins": [],
            "fail_on_partial": True,
        },
        {
            "name": "example-rctf",
            "platform": "rctf",
            "base_url": "https://rctf.example.invalid",
            "token_file": "./secrets/example-rctf.token",
            "output_root": "./collected",
            "tls": {"verify": True},
            "timeouts": {"request_seconds": 30},
            "retries": {
                "max_attempts": 3,
                "backoff_seconds": 0.5,
                "max_retry_after_seconds": 30,
            },
            "limits": {
                "page_size": 100,
                "max_pages": 100,
                "max_file_bytes": 104857600,
                "max_total_bytes": 1073741824,
                "max_redirects": 5,
                "max_metadata_bytes": 16777216,
            },
            "unauthenticated_attachment_origins": [],
            "fail_on_partial": True,
        },
    ]
}


def write_initial_config(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        json.dumps(EXAMPLE_CONFIG, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ValueError(f"config already exists: {path}") from exc
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def make_parser():
    parser = argparse.ArgumentParser(
        prog="ctf-collect",
        description="Pull-only CTF challenge collector",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="write a safe config template")
    init_parser.add_argument("--config", required=True)

    sync_parser = subparsers.add_parser("sync", help="collect CTF challenges")
    sync_parser.add_argument("--config", required=True)
    sync_parser.add_argument("--ctf")
    return parser


def main(argv=None):
    args = make_parser().parse_args(argv)
    try:
        if args.command == "init":
            write_initial_config(args.config)
            print(f"Created {args.config}")
            return 0
        configs = load_config(args.config)
        results = collect_all(configs, selected=args.ctf)
        failed = False
        for result in results:
            if result["error"] is not None:
                print(
                    f"{result['name']}: failed: {result['error'].message}",
                    file=sys.stderr,
                )
                failed = True
            elif result["partial"]:
                print(f"{result['name']}: partial")
                failed = failed or result["fail_on_partial"]
            else:
                print(f"{result['name']}: complete")
        return 1 if failed else 0
    except (OSError, ValueError, CollectorError) as exc:
        print(f"ctf-collect: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
