"""Inert offline HTML and media-source handling.

The collector deliberately does not render Markdown or server-supplied HTML.
Source documents are escaped into ``pre`` elements, while every active media
element is assembled from a verified local path chosen by the collector.
"""

from html import escape, unescape
from html.parser import HTMLParser
import json
from pathlib import PurePosixPath
import re
import unicodedata
from urllib.parse import unquote, urlsplit

from .safety import _sensitive_key, normalize_unicode_text


MAX_MEDIA_SOURCES = 64
MAX_FTYP_BOX_BYTES = 512
# The complete bounded `ftyp` box must come from the same read as the cached
# digest. Keeping this equal to the accepted box bound makes that possible.
MEDIA_SIGNATURE_PREFIX_BYTES = MAX_FTYP_BOX_BYTES
SUPPORTED_MEDIA_TYPES = {
    "audio/flac",
    "audio/mpeg",
    "audio/mp4",
    "audio/ogg",
    "audio/wav",
    "audio/webm",
    "audio/x-wav",
    "image/bmp",
    "image/gif",
    "image/jpeg",
    "image/png",
    "image/webp",
    "video/mp4",
    "video/ogg",
    "video/quicktime",
    "video/webm",
}

# Suffixes a browser opens as a document rather than as data. Archived media is
# named by the server, so a `.svg` or `.html` that arrived with a passive
# Content-Type would still be a live document the moment it is opened from the
# archive directory. Appending a passive suffix settles what the name claims.
ACTIVE_DOCUMENT_SUFFIXES = frozenset(
    {".htm", ".html", ".js", ".mjs", ".svg", ".xhtml", ".xml"}
)
PASSIVE_SUFFIX = ".bin"

# Formats whose signature is an ISO base media `ftyp` box. `image/avif` is not
# an accepted media type, but the rule that recognizes an `ftyp` box belongs
# with the box rather than with the list of types we happen to accept today.
FTYP_MEDIA_TYPES = frozenset(
    {"audio/mp4", "image/avif", "video/mp4", "video/quicktime"}
)
# An `ftyp` box holds a header, a brand and a minor version at least, and real
# files keep it small; both bounds are what makes the marker a header.
MIN_FTYP_BOX_BYTES = 16
FTYP_BRANDS_BY_MEDIA_TYPE = {
    "audio/mp4": frozenset(
        {b"isom", b"iso2", b"iso5", b"iso6", b"mp41", b"mp42", b"M4A ", b"M4B "}
    ),
    "image/avif": frozenset({b"avif", b"avis"}),
    "video/mp4": frozenset(
        {b"isom", b"iso2", b"iso5", b"iso6", b"avc1", b"mp41", b"mp42", b"M4V "}
    ),
    "video/quicktime": frozenset({b"qt  "}),
}
BMP_DIB_HEADER_SIZES = frozenset({12, 16, 40, 52, 56, 64, 108, 124})

MARKDOWN_IMAGE_RE = re.compile(
    r"!\[[^\]\r\n]*\]\(\s*(?:<([^>\r\n]+)>|([^\s)\r\n]+))"
    r"(?:\s+(?:\"[^\"]*\"|'[^']*'))?\s*\)",
)
MARKDOWN_IMAGE_REFERENCE_RE = re.compile(
    r"!\[([^\]\r\n]*)\]\[([^\]\r\n]*)\]",
)
MARKDOWN_REFERENCE_DEFINITION_RE = re.compile(
    r"(?m)^[ \t]{0,3}\[([^\]\r\n]+)\]:[ \t]*"
    r"(?:<([^>\r\n]+)>|([^\s\r\n]+))",
)
MARKDOWN_LINK_RE = re.compile(r"!?\[([^\]]*)\]\([^)]+\)")
MARKDOWN_HEADING_RE = re.compile(r"(?m)^[ \t]{0,3}#{1,6}[ \t]+")
BLOCK_TAGS = {
    "address",
    "article",
    "aside",
    "blockquote",
    "br",
    "dd",
    "div",
    "dl",
    "dt",
    "figcaption",
    "figure",
    "footer",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hr",
    "li",
    "main",
    "nav",
    "ol",
    "p",
    "pre",
    "section",
    "table",
    "tr",
    "ul",
}
SKIPPED_TEXT_TAGS = {"script", "style", "template"}
# What an authenticated page carries besides its prose. A rules page is fetched
# with our credentials, so its scripts hold the page's own session state (a CSRF
# nonce, the signed-in identity) and its chrome names the operator. None of that
# is the rules, so the element and everything inside it is dropped before the
# source is archived. Ordinary comments are not in this set: a flag left in one
# is content, and escaping already makes it inert.
SESSION_CONTAINER_TAGS = {"footer", "header", "nav", "script"}
SESSION_VOID_TAGS = {"input", "meta"}
RULES_EMAIL_RE = re.compile(
    r"(?<![\w.!#$%&'*+/=?^`{|}~-])"
    r"[\w.!#$%&'*+/=?^`{|}~-]+@"
    r"[\w-]+(?:\.[\w-]+)*",
    re.IGNORECASE,
)
RULES_NAMED_VALUE_RE = re.compile(
    r"(?P<prefix>(?P<quote>[\"']?)(?P<name>[A-Za-z_][\w:.-]*)"
    r"(?P=quote)\s*[:=]\s*)"
    r"(?P<value>\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;<>\r\n]+)",
)
RULES_REDACTED = "[REDACTED]"
CSP = (
    "default-src 'none'; img-src 'self'; media-src 'self'; "
    "style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; "
    "frame-ancestors 'none'"
)


class _MediaSourceParser(HTMLParser):
    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self._line_offsets = [0]
        for match in re.finditer("\n", source):
            self._line_offsets.append(match.end())
        self.sources = []
        self._media_parents = []

    def _offset(self):
        line, column = self.getpos()
        return self._line_offsets[min(line - 1, len(self._line_offsets) - 1)] + column

    def handle_starttag(self, tag, attrs):
        tag = tag.casefold()
        attributes = {
            str(key).casefold(): value
            for key, value in attrs
            if key is not None
        }
        source = attributes.get("src")
        if tag in {"img", "audio", "video", "source"} and source is not None:
            if tag == "img":
                kind = "image"
            elif tag in {"audio", "video"}:
                kind = tag
            elif self._media_parents:
                kind = self._media_parents[-1]
            else:
                kind = "video"
            self.sources.append((self._offset(), kind, source))
        if tag in {"audio", "video"}:
            self._media_parents.append(tag)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag.casefold() in {"audio", "video"}:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        tag = tag.casefold()
        if tag not in {"audio", "video"}:
            return
        for index in range(len(self._media_parents) - 1, -1, -1):
            if self._media_parents[index] == tag:
                del self._media_parents[index:]
                break


class _ReadableTextParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self._skipped_depth = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.casefold()
        if tag in SKIPPED_TEXT_TAGS:
            self._skipped_depth += 1
        elif self._skipped_depth == 0 and tag in BLOCK_TAGS:
            self.parts.append("\n")

    def handle_startendtag(self, tag, attrs):
        if self._skipped_depth == 0 and tag.casefold() in BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        tag = tag.casefold()
        if tag in SKIPPED_TEXT_TAGS:
            if self._skipped_depth:
                self._skipped_depth -= 1
        elif self._skipped_depth == 0 and tag in BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data):
        if self._skipped_depth == 0:
            self.parts.append(data)


class _SessionMarkupParser(HTMLParser):
    """Every construct of a document, in order, with where it starts.

    HTMLParser consumes its input contiguously, so the offset of one event is
    the end of the one before it. Recording only the offsets lets the source be
    rebuilt from its own bytes, which keeps the parts we archive spelled the
    way the server spelled them instead of the way a re-serializer would.
    """

    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self._line_offsets = [0]
        for match in re.finditer("\n", source):
            self._line_offsets.append(match.end())
        self.events = []

    def _offset(self):
        line, column = self.getpos()
        return self._line_offsets[min(line - 1, len(self._line_offsets) - 1)] + column

    def _record(self, kind, tag=None):
        self.events.append((self._offset(), kind, tag))

    def handle_starttag(self, tag, attrs):
        self._record("start", tag.casefold())

    def handle_startendtag(self, tag, attrs):
        self._record("startend", tag.casefold())

    def handle_endtag(self, tag):
        self._record("end", tag.casefold())

    def handle_data(self, data):
        self._record("data")

    def handle_comment(self, data):
        self._record("other")

    def handle_decl(self, decl):
        self._record("other")

    def handle_pi(self, data):
        self._record("other")

    def unknown_decl(self, data):
        self._record("other")


def strip_session_markup(source):
    """The source without the elements that carry page session state.

    Returns ``None`` when the document cannot be walked, because a source we
    could not inspect is one we cannot say is free of a nonce or an operator's
    address. An element we drop takes its content with it, and an element that
    is never closed takes the rest of the document: closing over too much is a
    smaller loss than archiving a credential.
    """
    text = str(source)
    parser = _SessionMarkupParser(text)
    try:
        parser.feed(text)
        parser.close()
    except (ValueError, TypeError):
        return None
    events = parser.events
    kept = []
    index = 0
    while index < len(events):
        offset, kind, tag = events[index]
        end = events[index + 1][0] if index + 1 < len(events) else len(text)
        if kind in {"start", "startend"} and tag in SESSION_VOID_TAGS:
            index += 1
            continue
        if kind == "startend" and tag in SESSION_CONTAINER_TAGS:
            # HTML does not make these elements void: a slash on `<script/>`
            # is ambiguous to consumers that apply HTML parsing rules. Treat
            # it like an unclosed removed container and discard the remainder.
            break
        if kind == "start" and tag in SESSION_CONTAINER_TAGS:
            depth = 1
            index += 1
            while index < len(events) and depth:
                _offset, nested_kind, nested_tag = events[index]
                if nested_tag == tag:
                    if nested_kind == "start":
                        depth += 1
                    elif nested_kind == "end":
                        depth -= 1
                index += 1
            continue
        kept.append(text[offset:end])
        index += 1
    return "".join(kept)


def _rules_sensitive_name(name):
    return _sensitive_key(name)


def redact_rules_values(source):
    """Withhold identity and session fields from otherwise useful rules prose."""

    def replace_named_value(match):
        if not _rules_sensitive_name(match.group("name")):
            return match.group(0)
        value = match.group("value")
        quote = value[0] if value[:1] in {"\"", "'"} else ""
        replacement = f"{quote}{RULES_REDACTED}{quote}" if quote else RULES_REDACTED
        return match.group("prefix") + replacement

    canonical = unicodedata.normalize("NFC", unescape(str(source)))
    redacted = RULES_NAMED_VALUE_RE.sub(replace_named_value, canonical)
    return RULES_EMAIL_RE.sub(RULES_REDACTED, redacted)


def extract_media_sources(description):
    """Return at most 64 unique media sources in document order."""
    source = str(description or "")
    positioned = [
        (match.start(), "image", match.group(1) or match.group(2))
        for match in MARKDOWN_IMAGE_RE.finditer(source)
    ]
    definitions = {
        " ".join(match.group(1).split()).casefold(): (
            match.group(2) or match.group(3)
        )
        for match in MARKDOWN_REFERENCE_DEFINITION_RE.finditer(source)
    }
    for match in MARKDOWN_IMAGE_REFERENCE_RE.finditer(source):
        label = match.group(2) or match.group(1)
        destination = definitions.get(" ".join(label.split()).casefold())
        if destination is not None:
            positioned.append((match.start(), "image", destination))
    parser = _MediaSourceParser(source)
    try:
        parser.feed(source)
        parser.close()
    except (ValueError, TypeError):
        # HTMLParser is deliberately tolerant, but a malformed character
        # reference should not prevent Markdown media or the archive itself.
        pass
    positioned.extend(parser.sources)
    positioned.sort(key=lambda item: item[0])
    result = []
    seen = set()
    for _position, kind, value in positioned:
        key = str(value)
        if key in seen:
            continue
        seen.add(key)
        result.append((kind, value))
        if len(result) == MAX_MEDIA_SOURCES:
            break
    return result


def passive_media_name(name):
    """A media file name that no browser will open as a document.

    The suffix is appended rather than replaced, so the name still says what
    the server called it. Applying this to its own result changes nothing,
    which is what lets a second run recognize the file the first run wrote.
    """
    text = str(name)
    _stem, _dot, suffix = text.rpartition(".")
    if _dot and f".{suffix}".casefold() in ACTIVE_DOCUMENT_SUFFIXES:
        return f"{text}{PASSIVE_SUFFIX}"
    return text


def is_supported_media_type(content_type):
    return str(content_type).casefold() in SUPPORTED_MEDIA_TYPES


def _matches_ftyp(content_type, payload, total_size):
    """Whether the prefix opens with a real ISO base media `ftyp` box.

    `ftyp` four bytes in is a marker, not a format: `<!--ftyp-->` carries it as
    readily as an MP4 does. What separates them is the box length in front of
    it, which an ISO file states as a small multiple of four, and the brand
    behind it, which is printable ASCII.
    """
    if len(payload) < MIN_FTYP_BOX_BYTES or payload[4:8] != b"ftyp":
        return False
    box_size = int.from_bytes(payload[:4], "big")
    if box_size < MIN_FTYP_BOX_BYTES or box_size > MAX_FTYP_BOX_BYTES:
        return False
    if box_size % 4:
        return False
    if box_size > total_size or box_size > len(payload):
        return False
    brands = {payload[8:12]}
    brands.update(
        payload[offset : offset + 4]
        for offset in range(16, box_size, 4)
    )
    return bool(brands.intersection(FTYP_BRANDS_BY_MEDIA_TYPE[content_type]))


def _matches_bmp(payload):
    """Whether the prefix carries a BMP file header and a real DIB header.

    `BM` alone is two bytes of any document that happens to start with them,
    so the device-independent bitmap header behind it is checked too: its size
    is one of a fixed set, and the pixel data cannot begin before it ends.
    """
    if len(payload) < 18 or payload[:2] != b"BM":
        return False
    header_size = int.from_bytes(payload[14:18], "little")
    if header_size not in BMP_DIB_HEADER_SIZES:
        return False
    pixel_offset = int.from_bytes(payload[10:14], "little")
    return pixel_offset >= 14 + header_size


def _matches_mpeg_audio(payload, total_size):
    """Whether the prefix is an ID3 tag or a plausible MPEG frame header.

    Eleven set sync bits are cheap to spell by accident, so the fields behind
    them are read: a reserved version, a reserved layer, the reserved sampling
    rate and the invalid bitrate index all mean this is not an MPEG frame.
    """
    if payload.startswith(b"ID3"):
        if len(payload) < 10:
            return False
        if payload[3] not in {2, 3, 4} or payload[4] == 0xFF:
            return False
        if any(byte & 0x80 for byte in payload[6:10]):
            return False
        tag_size = 0
        for byte in payload[6:10]:
            tag_size = (tag_size << 7) | byte
        return 10 + tag_size <= total_size
    if len(payload) < 4 or payload[0] != 0xFF or payload[1] & 0xE0 != 0xE0:
        return False
    version = (payload[1] >> 3) & 0b11
    layer = (payload[1] >> 1) & 0b11
    bitrate = (payload[2] >> 4) & 0b1111
    sampling = (payload[2] >> 2) & 0b11
    emphasis = payload[3] & 0b11
    return (
        version != 1
        and layer != 0
        and bitrate not in {0, 0b1111}
        and sampling != 3
        and emphasis != 2
    )


def media_signature_matches(content_type, payload, *, total_size=None):
    """Return whether a bounded prefix matches an allowed passive media type."""
    content_type = str(content_type).casefold()
    payload = bytes(payload)
    if total_size is None:
        total_size = len(payload)
    if (
        isinstance(total_size, bool)
        or not isinstance(total_size, int)
        or total_size < len(payload)
    ):
        return False
    if content_type == "image/png":
        return payload.startswith(b"\x89PNG\r\n\x1a\n")
    if content_type == "image/jpeg":
        return payload.startswith(b"\xff\xd8\xff")
    if content_type == "image/gif":
        return payload.startswith((b"GIF87a", b"GIF89a"))
    if content_type == "image/webp":
        return len(payload) >= 12 and payload[:4] == b"RIFF" and payload[8:12] == b"WEBP"
    if content_type == "image/bmp":
        return _matches_bmp(payload)
    if content_type == "audio/mpeg":
        return _matches_mpeg_audio(payload, total_size)
    if content_type in {"audio/wav", "audio/x-wav"}:
        return len(payload) >= 12 and payload[:4] == b"RIFF" and payload[8:12] == b"WAVE"
    if content_type == "audio/flac":
        return payload.startswith(b"fLaC")
    if content_type in {"audio/ogg", "video/ogg"}:
        return payload.startswith(b"OggS")
    if content_type in {"audio/webm", "video/webm"}:
        return payload.startswith(b"\x1aE\xdf\xa3")
    if content_type in FTYP_MEDIA_TYPES:
        return _matches_ftyp(content_type, payload, total_size)
    return False


def safe_local_reference(value):
    """Return a passive relative archive path, or ``None`` when unsafe."""
    if not isinstance(value, str) or not value:
        return None
    value = normalize_unicode_text(value)
    if "\\" in value or any(ord(character) < 32 for character in value):
        return None
    try:
        parsed = urlsplit(value)
    except ValueError:
        # A reference we cannot parse is one we cannot vouch for.
        return None
    if (
        parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or parsed.path.startswith("/")
    ):
        return None
    decoded = unquote(parsed.path)
    parts = PurePosixPath(decoded).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        return None
    return parsed.path


def _file_html_path(item):
    explicit = safe_local_reference(item.get("html_path"))
    if explicit is not None:
        return explicit
    local_path = item.get("local_path")
    if not isinstance(local_path, str):
        return None
    parts = PurePosixPath(local_path).parts
    try:
        files_index = len(parts) - 1 - tuple(reversed(parts)).index("files")
    except ValueError:
        return None
    return safe_local_reference("/".join(parts[files_index:]))


def readable_source_text(source):
    """Best-effort readable text for a Markdown/HTML source document."""
    source = normalize_unicode_text(source)
    parser = _ReadableTextParser()
    try:
        parser.feed(source)
        parser.close()
        text = "".join(parser.parts)
    except (ValueError, TypeError):
        text = source
    text = MARKDOWN_LINK_RE.sub(lambda match: match.group(1), text)
    text = MARKDOWN_HEADING_RE.sub("", text)
    lines = [line.strip() for line in text.splitlines()]
    compact = []
    for line in lines:
        if line or (compact and compact[-1]):
            compact.append(line)
    return "\n".join(compact).strip()


def _document(title, body):
    csp = escape(CSP, quote=True)
    title = normalize_unicode_text(title)
    body = normalize_unicode_text(body)
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">\n'
        f'<meta http-equiv="Content-Security-Policy" content="{csp}">\n'
        f"<title>{escape(title)}</title>\n"
        "<style>"
        "body{max-width:70rem;margin:2rem auto;padding:0 1rem;"
        "font:16px/1.5 sans-serif;color:#171717;background:#fff}"
        "dt{font-weight:bold;margin-top:.6rem}dd{margin-left:1.5rem}"
        "pre{white-space: pre-wrap;overflow-wrap:anywhere;padding:1rem;"
        "background:#f4f4f4;border:1px solid #ddd}"
        "img,video{max-width:100%;height:auto}audio{max-width:100%}"
        "code{overflow-wrap:anywhere}</style></head><body>\n"
        f"{body}\n</body></html>\n"
    )


def _value_text(value):
    if value is None or value == "":
        return "Unavailable"
    if isinstance(value, (dict, list)):
        return normalize_unicode_text(
            json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
        )
    return normalize_unicode_text(value)


def render_challenge_html(challenge, files, media):
    """Build a challenge page using only collector-controlled active markup."""
    name = escape(_value_text(challenge.get("name")))
    fields = (
        ("Category", challenge.get("category")),
        ("ID", challenge.get("id")),
        ("Value", challenge.get("value")),
        ("Points", challenge.get("points")),
        ("Hints", challenge.get("hints")),
        ("Connection info", challenge.get("connection_info")),
    )
    definitions = "".join(
        f"<dt>{escape(label)}</dt><dd><pre>{escape(_value_text(value))}</pre></dd>"
        for label, value in fields
    )
    file_items = []
    for item in files:
        label = escape(normalize_unicode_text(item.get("local_path", "Unavailable")))
        status = escape(normalize_unicode_text(item.get("status", "unknown")))
        html_path = (
            _file_html_path(item)
            if item.get("status") in {"downloaded", "verified"}
            else None
        )
        if html_path is None:
            file_items.append(f"<li><code>{label}</code> — {status}</li>")
        else:
            href = escape(html_path, quote=True)
            # An attachment is server-supplied bytes under a server-supplied
            # name, so a click must save it rather than open it: `.html` and
            # `.svg` are documents the browser would otherwise run beside the
            # archive. `rel` closes the window handle either way.
            file_items.append(
                f'<li><a href="{href}" download rel="noopener noreferrer">'
                f"<code>{label}</code></a> — {status}</li>"
            )
    file_items = "".join(file_items)
    if not file_items:
        file_items = "<li>None</li>"

    media_items = []
    for item in media:
        if item.get("status") not in {"downloaded", "verified"}:
            continue
        safe_path = safe_local_reference(item.get("html_path"))
        if safe_path is None:
            continue
        local_path = escape(safe_path, quote=True)
        kind = item.get("media_kind")
        if kind == "image":
            element = f'<img src="{local_path}" alt="Archived challenge media">'
        elif kind == "audio":
            element = f'<audio controls src="{local_path}"></audio>'
        else:
            element = f'<video controls src="{local_path}"></video>'
        media_items.append(f"<li>{element}</li>")
    media_list = "".join(media_items) if media_items else "<li>None</li>"

    description = escape(_value_text(challenge.get("description")))
    body = (
        f"<h1>{name}</h1>\n"
        f"<dl>{definitions}</dl>\n"
        f"<h2>Files</h2><ul>{file_items}</ul>\n"
        f"<h2>Archived media</h2><ul>{media_list}</ul>\n"
        f"<h2>Original description source</h2><pre>{description}</pre>"
    )
    return _document(challenge.get("name", "Challenge"), body)


def render_rules_html(source):
    source = normalize_unicode_text(source)
    readable = escape(readable_source_text(source))
    escaped_source = escape(source)
    body = (
        "<h1>Event rules / home content</h1>\n"
        "<p>Scripts, navigation chrome and form state were removed before "
        "archiving; the source below is inert escaped text.</p>\n"
        f"<h2>Readable text</h2><pre>{readable}</pre>\n"
        f"<h2>Original source</h2><pre>{escaped_source}</pre>"
    )
    return _document("Event rules", body)
