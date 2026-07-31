import argparse
import json
import os
from pathlib import Path
import sys

from .collector import collect_all
from .config import load_config
from .errors import CollectorError
from .progress import ProgressReporter


EXAMPLE_CONFIG = {
    "ctfs": [
        {
            "name": "example-ctfd",
            "platform": "ctfd",
            "base_url": "https://ctf.example.invalid",
            "token_file": "./secrets/example-ctfd.token",
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


def _terminal_limit_approver(request):
    """Ask once, for the run, in the terms the run will actually honour.

    The collector asks about the first oversized attachment and keeps the
    answer for everything after it, so a prompt that named only this file
    would be asking for less than it takes.
    """
    print(
        f"{request['ctf_name']}: {request['local_path']} requires "
        f"{request['required_file_bytes']} bytes for this file and "
        f"{request['required_total_bytes']} bytes total; current limits are "
        f"{request['current_file_limit']} and "
        f"{request['current_total_limit']} bytes. Answering yes approves "
        "every attachment that exceeds these limits for the rest of this "
        "sync run, each one only up to the finite size it declares and "
        "always within the absolute hard caps; the approval expires when "
        "this run ends. Continue? Type yes: ",
        file=sys.stderr,
        end="",
        flush=True,
    )
    answer = sys.stdin.readline()
    return answer.rstrip("\r\n") == "yes"


def _interactive_limit_approver():
    if sys.stdin.isatty() and sys.stderr.isatty():
        return _terminal_limit_approver
    return None


def _stderr_progress():
    """Narrate the run on stderr, whether or not anyone is watching a terminal.

    Unlike the oversized-attachment prompt, this needs no answer from the
    operator, so a piped or redirected run keeps the same visibility a
    terminal gets. stdout stays reserved for the machine-readable summary.
    """
    return ProgressReporter(sys.stderr)


def main(argv=None):
    args = make_parser().parse_args(argv)
    try:
        if args.command == "init":
            write_initial_config(args.config)
            print(f"Created {args.config}")
            return 0
        configs = load_config(args.config)
        results = collect_all(
            configs,
            selected=args.ctf,
            limit_approver=_interactive_limit_approver(),
            progress=_stderr_progress(),
        )
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
