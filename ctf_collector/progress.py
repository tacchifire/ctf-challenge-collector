"""Human-facing progress for long collections.

Everything written here is as public as any other terminal output, so the
reporter prints only values the collector has already redacted, and scrubs
them again for control sequences before they reach the stream.
"""

import time

from .safety import display_name, display_path, display_text


MEBIBYTE = 1024 * 1024
BYTE_UNITS = (
    ("GiB", 1024 ** 3),
    ("MiB", 1024 ** 2),
    ("KiB", 1024),
)


def format_bytes(count):
    count = int(count)
    for suffix, scale in BYTE_UNITS:
        if count >= scale:
            return f"{count / scale:.1f} {suffix}"
    return f"{count} B"


def _is_terminal(stream):
    """Whether the stream says it is a terminal.

    Only a terminal is redrawn in place, because a rewritten line is a line a
    log or a pipe never keeps. A stream that cannot answer - one that is
    closed, or that is not a file at all - has not said yes, so it is written
    to a line at a time like any other.
    """
    try:
        return bool(stream.isatty())
    except Exception:
        return False


class ProgressReporter:
    """Writes one self-contained line per milestone.

    A download that takes minutes still has to look alive, but a line per
    chunk would bury everything else, so in-flight lines are released by
    elapsed time or transferred bytes while start and end are unconditional.
    """

    def __init__(
        self,
        stream,
        *,
        now=time.monotonic,
        min_interval=1.0,
        min_bytes=4 * MEBIBYTE,
    ):
        self._stream = stream
        self._now = now
        self._min_interval = min_interval
        self._min_bytes = min_bytes
        self._download = None
        self._terminal = _is_terminal(stream)
        self._live = None

    def _settle(self):
        """End the in-place line, once, before anything else claims the cursor.

        Every other milestone owns a line of its own, so an update that is
        still being redrawn has to become a finished line first - otherwise
        the next milestone would be written over what it is meant to follow.
        """
        if self._live is None:
            return
        self._live = None
        self._stream.write("\n")

    def _write(self, ctf, message):
        self._settle()
        self._stream.write(f"[{display_text(ctf, 60)}] {message}\n")
        self._stream.flush()

    def _update(self, ctf, message):
        """Redraw the in-place line a terminal keeps for the current download.

        A carriage return is the whole vocabulary: it returns to the start of
        the line we already own, so nothing here can move the cursor off it.
        An update that is shorter than the one it replaces would otherwise
        leave the tail of the old text standing, so the difference is written
        over with spaces rather than erased with a cursor control sequence.
        """
        line = f"[{display_text(ctf, 60)}] {message}"
        if self._live is None:
            self._stream.write(line)
        else:
            self._stream.write(f"\r{line}{' ' * max(0, self._live - len(line))}")
        self._stream.flush()
        self._live = len(line)

    @staticmethod
    def _path(event):
        return display_path(event["local_path"], 100)

    def _reading(self, state):
        """The current clock reading, with the baseline rebased if it moved back.

        The clock is supplied by the caller, so a reading earlier than the
        baseline means the clock was replaced, not that time ran backwards.
        The old baseline then describes nothing, and keeping it would print a
        negative duration or rate, so the download is measured from here on.
        """
        now = self._now()
        if now < state["started"]:
            state["started"] = now
        if now < state["last_emit"]:
            state["last_emit"] = now
        return now

    def __call__(self, event):
        handler = getattr(self, f"_on_{event.get('event')}", None)
        if handler is None:
            return
        handler(event)

    def _on_ctf_start(self, event):
        self._write(
            event["ctf"],
            f"({event['index']}/{event['total']}) starting",
        )

    def _on_listing_start(self, event):
        self._write(
            event["ctf"],
            f"listing challenges ({display_text(event['platform'], 20)})",
        )

    def _on_listing_done(self, event):
        self._write(event["ctf"], f"{event['count']} challenges to process")

    def _on_challenge(self, event):
        self._write(
            event["ctf"],
            f"({event['index']}/{event['total']}) "
            f"{display_name(event['category'], 40)} / "
            f"{display_name(event['name'], 60)}",
        )

    def _on_ctf_done(self, event):
        if event["status"] == "partial":
            self._write(event["ctf"], f"partial ({event['failures']} failures)")
        else:
            self._write(event["ctf"], "complete")

    def _on_ctf_failed(self, event):
        self._write(event["ctf"], f"failed ({display_text(event['code'], 40)})")

    def _on_attachment_start(self, event):
        started = self._now()
        self._download = {
            "started": started,
            "last_emit": started,
            "last_bytes": 0,
        }
        declared = event.get("declared")
        size = "size unknown" if declared is None else format_bytes(declared)
        self._write(event["ctf"], f"downloading {self._path(event)} ({size})")

    def _on_attachment_progress(self, event):
        state = self._download
        if state is None:
            return
        now = self._reading(state)
        received = event["received"]
        if (
            now - state["last_emit"] < self._min_interval
            and received - state["last_bytes"] < self._min_bytes
        ):
            return
        state["last_emit"] = now
        state["last_bytes"] = received

        declared = event.get("declared")
        transferred = format_bytes(received)
        if declared:
            transferred += (
                f"/{format_bytes(declared)} ({received * 100 // declared}%)"
            )
        elapsed = now - state["started"]
        if elapsed > 0:
            transferred += f" {format_bytes(received / elapsed)}/s"
        emit = self._update if self._terminal else self._write
        emit(event["ctf"], f"{self._path(event)} {transferred}")

    def _on_attachment_done(self, event):
        state = self._download
        self._download = None
        size = format_bytes(event["size"])
        if event.get("status") == "verified":
            self._write(event["ctf"], f"verified {self._path(event)} ({size})")
            return
        elapsed = self._reading(state) - state["started"] if state else 0.0
        self._write(
            event["ctf"],
            f"saved {self._path(event)} ({size} in {elapsed:.1f}s)",
        )

    def _on_attachment_failed(self, event):
        self._download = None
        self._write(
            event["ctf"],
            f"failed {self._path(event)} ({display_text(event['code'], 40)})",
        )
