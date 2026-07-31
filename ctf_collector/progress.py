"""Human-facing progress for long collections.

Everything written here is as public as any other terminal output, so the
reporter prints only values the collector has already redacted, and scrubs
them again for control sequences before they reach the stream.
"""

import os
import time
import unicodedata

from .safety import display_name, display_path, display_text


MEBIBYTE = 1024 * 1024
BYTE_UNITS = (
    ("GiB", 1024 ** 3),
    ("MiB", 1024 ** 2),
    ("KiB", 1024),
)
# The width assumed for a terminal that will not say how wide it is. Eighty is
# the narrowest width still in common use, so a line composed for it also fits
# the terminals we could not measure.
DEFAULT_COLUMNS = 80
ELLIPSIS = "..."
WIDE_WIDTHS = frozenset(("W", "F"))
# The columns the gauge spends between its brackets when the line can afford
# it. Twenty divides the percentage into steps the eye can follow and still
# leaves an eighty column terminal room for the figures beside it.
BAR_CELLS = 20


def format_bytes(count):
    count = int(count)
    for suffix, scale in BYTE_UNITS:
        if count >= scale:
            return f"{count / scale:.1f} {suffix}"
    return f"{count} B"


def format_bar(percent, cells=BAR_CELLS):
    """A gauge of `cells` columns, filled to `percent`.

    The gauge occupies the same columns at every percentage, so the figures
    beside it keep their place on the line instead of sliding along it as the
    download runs. What has not arrived is spaces rather than a second
    character: the line is redrawn where it stands, and only the part that
    changed should look like it changed. The head of the fill is an arrow
    while anything is still to come, and a finished download is solid, since
    an arrow at the end would point past the end of the file.
    """
    filled = min(int(percent), 100) * cells // 100
    if filled >= cells:
        return "=" * cells
    return "=" * filled + ">" + " " * (cells - filled - 1)


def cell_width(text):
    """The columns a terminal advances for `text`.

    The reporter reclaims its line by returning to the start of it, which only
    works while the line is narrower than the terminal, and a terminal counts
    columns rather than characters: an East Asian wide or fullwidth character
    takes two of them and a combining mark takes none.
    """
    width = 0
    for character in text:
        if unicodedata.combining(character):
            continue
        # Width tables differ across terminal emulators.  Treating every
        # non-ASCII printable code point as two cells can leave spare room but
        # cannot underestimate it and wrap the live line.
        width += 1 if ord(character) < 128 else 2
    return width


def clip(text, columns):
    """`text` cut down to `columns` columns, marked where it was cut.

    The cut falls between characters, because half of a wide character is not
    a character a terminal can draw and a mark severed from what it modifies
    is not the text we measured. Below the width of the marker itself there is
    nothing left that could be said truthfully, so nothing is said.
    """
    if cell_width(text) <= columns:
        return text
    budget = columns - cell_width(ELLIPSIS)
    if budget < 0:
        return ""
    kept = []
    used = 0
    for character in text:
        width = cell_width(character)
        if used + width > budget:
            break
        kept.append(character)
        used += width
    return "".join(kept) + ELLIPSIS


def terminal_columns(stream, fallback=DEFAULT_COLUMNS):
    """How wide the terminal is now.

    A window is resized while a long download is in flight, and the line we
    are about to redraw has to fit the window as it is at that moment, so the
    width is asked for again rather than remembered. A stream that cannot
    answer - one that is not a file, or a terminal that reports no size at
    all - is treated as the default terminal, since guessing wide would wrap
    the line on exactly the terminals we could not check.
    """
    try:
        columns = os.get_terminal_size(stream.fileno()).columns
    except Exception:
        return fallback
    return columns if columns > 0 else fallback


def _is_terminal(stream):
    """Whether the stream says it is a terminal.

    Only a terminal is redrawn in place, because a rewritten line is a line a
    log or a pipe never keeps, and only a terminal is shown a download in
    flight at all. A stream that cannot answer - one that is closed, or that
    is not a file at all - has not said yes, so it is treated as a log.
    """
    try:
        return bool(stream.isatty())
    except Exception:
        return False


class ProgressReporter:
    """Writes one self-contained line per milestone.

    A download that takes minutes still has to look alive, but a line per
    chunk would bury everything else, so in-flight updates are released by
    elapsed time or transferred bytes while start and end are unconditional.
    A terminal draws those updates over one line it can reclaim; anywhere
    else they are dropped, because a log keeps every line it is given and
    nothing an update says outlives the result that follows it.
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

    def _update(self, line, columns):
        """Redraw the in-place line a terminal keeps for the current download.

        A carriage return is the whole vocabulary: it returns to the start of
        the line we already own, so nothing here can move the cursor off it.
        An update that is shorter than the one it replaces would otherwise
        leave the tail of the old text standing, so the difference is written
        over with spaces rather than erased with a cursor control sequence.
        The erasing stops at the last column as well: a window that has just
        been narrowed cannot be cleaned past its own edge, and spaces written
        past it would wrap and cost us the line we are reclaiming.
        """
        width = cell_width(line)
        # A resize may have reflowed the old live line before this redraw.  In
        # that case a carriage return reaches only its final screen row, so
        # settle it once and begin a fresh width-safe line.
        if self._live is not None and self._live > columns:
            self._settle()
        if self._live is None:
            self._stream.write(line)
        else:
            erased = max(0, min(self._live, columns) - width)
            self._stream.write(f"\r{line}{' ' * erased}")
        self._stream.flush()
        self._live = width

    @staticmethod
    def _fit(candidates, columns):
        """The first candidate that fits `columns` columns, cut down if none do.

        A line wider than the terminal is a line the carriage return can no
        longer reclaim: the terminal wraps it, the return only reaches the
        start of its last screen row, and every update after that is appended
        to the wreckage of the one before instead of replacing it. The
        candidates are therefore offered widest first and the first one the
        terminal can hold is drawn. A terminal too narrow for even the last of
        them gets that one cut to the width, which is the only remaining way
        to stay on one row.
        """
        line = ""
        for line in candidates:
            if cell_width(line) <= columns:
                return line
        if columns > 0 and "%" in line:
            # The numeric share cannot fit in one or two columns; preserving
            # the percent marker is still better than silence or an ellipsis.
            return "%"
        return clip(line, columns)

    @staticmethod
    def _measured_lines(head, percent, sized, rate):
        """Every form of an update with a declared size, widest first.

        What a narrow line cannot afford it gives up in the order the reader
        misses least. The rate goes first: it describes how the transfer is
        going rather than how far it has got. The name of the CTF goes next,
        because one CTF is collected at a time and its name is already on the
        line above. The byte counts follow, since the gauge and the share say
        the same thing in fewer columns. Then the gauge itself narrows, cell
        by cell, down to a single one. The share is the last thing standing:
        an update that no longer says how far along it is has stopped being
        progress at all, so on a terminal too narrow for anything else it is
        spelled without the padding that keeps it aligned.
        """
        share = f"{percent:3d}%"
        gauge = f"[{format_bar(percent)}]"
        yield f"{head}{gauge} {share} {sized}{rate}"
        yield f"{head}{gauge} {share} {sized}"
        yield f"{gauge} {share} {sized}"
        yield f"{gauge} {share}"
        for cells in range(BAR_CELLS - 1, 0, -1):
            yield f"[{format_bar(percent, cells)}] {share}"
        yield f"{percent}%"

    @staticmethod
    def _unmeasured_lines(head, transferred, rate):
        """Every form of an update without a declared size, widest first.

        Nothing here knows the distance to the end, so there is no gauge to
        draw and no share to spell: a bar filled from a size the server never
        declared would be an invention, and the one number this update has is
        the count of what has arrived. It gives up the rate and then the name
        of the CTF, in that order, and below that there is only the count to
        cut into.
        """
        yield f"{head}{transferred}{rate}"
        yield f"{head}{transferred}"
        yield transferred

    def _live_line(self, ctf, received, declared, rate, columns):
        """The update the terminal is shown, composed for the width it has now.

        The path is not repeated here. It is on the line that announced the
        download, it does not change between redraws, and spending the width
        on it again would push out the gauge and the figures that do change.
        """
        head = f"[{display_text(ctf, 60)}] "
        transferred = format_bytes(received)
        if declared:
            candidates = self._measured_lines(
                head,
                received * 100 // declared,
                f"{transferred}/{format_bytes(declared)}",
                rate,
            )
        else:
            candidates = self._unmeasured_lines(head, transferred, rate)
        return self._fit(candidates, columns)

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
        """Show the download moving, on the one stream that can take it back.

        The clock reading and the pacing are kept off a terminal too: the
        callback is the only place the reporter observes the clock, and the
        duration the result reports is measured from what it observed there.
        Only the line is withheld.
        """
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
        if not self._terminal:
            return

        elapsed = now - state["started"]
        rate = f" {format_bytes(received / elapsed)}/s" if elapsed > 0 else ""
        columns = terminal_columns(self._stream)
        self._update(
            self._live_line(
                event["ctf"],
                received,
                event.get("declared"),
                rate,
                columns,
            ),
            columns,
        )

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
