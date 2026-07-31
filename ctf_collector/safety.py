import errno
from html import unescape
import hashlib
import json
import math
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
    "auth",
    "authentication",
    "authorization",
    "cookie",
    "csrf",
    "email",
    "nonce",
    "password",
    "secret",
    "session",
    "token",
    "user",
}
SENSITIVE_COMPOUND_KEY_RE = re.compile(
    r"(?:"
    r"access(?:token)"
    r"|api(?:key)"
    r"|(?:auth|authentication|authorization|cookie|csrf|email|nonce|password|secret|session|token|user)"
    r"(?:address|data|hash|id|key|name|token|value)"
    r")\Z"
)
WITHHELD = "[REDACTED]"
SAFE_COMPONENT = "redacted"
# The first spelling is the established public marker. The later spellings
# are fixed alternatives rather than transformations of a credential; an
# empty final candidate is a finite fail-safe because no configured token is
# empty. This lets a token literally equal to (or contained by) one marker be
# removed without replacing it with itself.
REDACTION_MARKERS = (
    WITHHELD,
    "[WITHHELD]",
    "[FILTERED]",
    "[HIDDEN]",
    "\ufffd",
    "",
)
DISPLAY_PUNCTUATION = frozenset(" !\"&'(),-.:;+@_")
SOURCE_URL_RE = re.compile(
    r"(?:"
    # A scheme-relative authority may immediately follow prose (`x//...`).
    # Requiring userinfo keeps that exception narrow while ensuring its
    # credential cannot hide behind the usual word-boundary guard.
    r"[\\/]{2,}[^\s<>\"']*?@[^\s<>\"']+"
    r"|(?<![A-Za-z0-9_])(?:"
    # WHATWG treats slashes and backslashes after an HTTP scheme as authority
    # separators, including when there are zero, one, or too many of them.
    r"(?:https?:[\\/]*|[A-Za-z][A-Za-z0-9+.-]*://|//|\.\.?/|/)"
    r"[^\s<>\"']+"
    r"|(?:[A-Za-z0-9._~%-]+/)+[A-Za-z0-9._~%/-]+[?#][^\s<>\"']+"
    r"|[A-Za-z0-9_~%-]+\.[A-Za-z0-9._~%-]+[?#][^\s<>\"']+"
    # A destination needs neither a slash nor a dot to carry a credential:
    # `download?credential=...` is one word and a query. This alternative is
    # last so the longer, more specific spellings above still win, and it asks
    # for an assignment behind the separator, because that is what carried
    # state looks like and a flag is not it: `flag{a#b}` and `issue#42` are
    # content, and trimming them would lose the very thing we archive.
    r"|\w[\w.~%-]*[?#][^\s<>\"']+"
    r"))",
    re.IGNORECASE,
)
# WHATWG URL parsing ignores ASCII tab, newline and carriage return anywhere
# in a URL. Embedded source still owns its ordinary line breaks, so only the
# authority prefix through a syntactic userinfo separator is canonicalized
# before the ordinary URL-token scanner runs.
URL_USERINFO_PREFIX_RE = re.compile(
    r"(?:"
    r"[\\/]{2,}"
    r"|(?<![A-Za-z0-9_])(?:"
    r"https?:[\\/]*|[A-Za-z][A-Za-z0-9+.-]*://|//"
    r")"
    r")"
    r"(?=[^\\/?#\x20\f\v<>\"']*@)"
    r"[^\\/?#\x20\f\v<>\"']*@",
    re.IGNORECASE,
)
FLAG_PAYLOAD_RE = re.compile(r"\bflag\{[^{}\r\n]*\}", re.IGNORECASE)
MARKDOWN_DESTINATION_RE = re.compile(
    r"(\]\(\s*<?)([^)\s>]+)(>?)",
)
HTML_QUOTED_URL_ATTRIBUTE_RE = re.compile(
    r"(\b(?:src|href|poster|action|data)\s*=\s*)([\"'])(.*?)(\2)",
    re.IGNORECASE | re.DOTALL,
)
HTML_UNQUOTED_URL_ATTRIBUTE_RE = re.compile(
    r"(\b(?:src|href|poster|action|data)\s*=\s*)([^\s>\"']+)",
    re.IGNORECASE,
)
# How many collision suffixes one candidate name may be asked for before the
# next candidate is tried instead. A secret that survives every suffix of one
# name is a name we should stop spelling, not one to keep counting on.
SAFE_NAME_ATTEMPTS = 8
# Keep sanitized metadata comfortably inside the recursion budgets of both
# Python and downstream JSON/HTML rendering. The count is containers, not
# scalar leaves: a scalar below 64 dict/list containers remains valid.
MAX_METADATA_NESTING = 64
WHATWG_IGNORED_URL_CHARACTERS = "\t\n\r"


def normalize_unicode_text(value):
    """Return text containing Unicode scalar values only.

    JSON can decode an isolated UTF-16 surrogate even though UTF-8 cannot
    encode it. Replacing those code points at the first text boundary keeps
    metadata, paths, rendering and final writes on the same deterministic
    spelling instead of exposing a raw ``UnicodeEncodeError``.
    """
    text = str(value)
    if not any(0xD800 <= ord(character) <= 0xDFFF for character in text):
        return text
    return "".join(
        "\ufffd" if 0xD800 <= ord(character) <= 0xDFFF else character
        for character in text
    )


def _secret_spellings(secrets):
    """Configured secrets and the compatibility spellings they normalize to."""
    result = []
    seen = set()
    for secret in secrets:
        if not secret:
            continue
        original = normalize_unicode_text(secret)
        for spelling in (original, unicodedata.normalize("NFKC", original)):
            if spelling and spelling not in seen:
                seen.add(spelling)
                result.append(spelling)
    return tuple(result)


def redaction_marker(secrets=()):
    """Choose a fixed marker that cannot itself disclose any given secret."""
    spellings = _secret_spellings(secrets)
    for candidate in REDACTION_MARKERS:
        normalized = unicodedata.normalize("NFKC", candidate)
        if not any(
            spelling in candidate or spelling in normalized
            for spelling in spellings
        ):
            return candidate
    # REDACTION_MARKERS ends in the empty string, which is conflict-free for
    # every non-empty secret. Keep this guard explicit if the catalog changes.
    return ""


def _remove_whatwg_url_controls(value):
    return normalize_unicode_text(value).translate(
        {ord(character): None for character in WHATWG_IGNORED_URL_CHARACTERS}
    )


def sanitize_component(value, fallback="unnamed", max_length=120):
    value = unicodedata.normalize("NFKC", normalize_unicode_text(value))
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
    value = unicodedata.normalize("NFKC", normalize_unicode_text(value))
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
    text = unicodedata.normalize("NFKC", normalize_unicode_text(value))
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
    text = normalize_unicode_text(value)
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
    return f".{normalize_unicode_text(name)}.part"


class UniqueNameAllocator:
    """Amortized-linear allocation for one output directory.

    Reservations include both committed targets and every temporary sibling a
    target will use. That makes the collision rule bidirectional: choosing
    ``X`` reserves ``X.part``, while choosing ``X.part`` first prevents a later
    ``X`` from using that committed file as its temporary output.
    """

    def __init__(self, used=()):
        self._targets = {normalize_unicode_text(name).casefold() for name in used}
        self._reserved = set(self._targets)
        self._initialized_sibling_sets = set()
        self._next_suffixes = {}
        self.probe_count = 0

    @staticmethod
    def _spellings(name, siblings):
        return (name, *(f"{name}{suffix}" for suffix in siblings))

    def reserve_existing_siblings(self, siblings):
        siblings = tuple(normalize_unicode_text(suffix) for suffix in siblings)
        key = tuple(suffix.casefold() for suffix in siblings)
        if key in self._initialized_sibling_sets:
            return
        self._initialized_sibling_sets.add(key)
        for name in self._targets:
            self._reserved.update(
                spelling.casefold()
                for spelling in self._spellings(name, siblings)
            )

    def allocate(self, name, *, keep_extension=True, siblings=()):
        name = normalize_unicode_text(name)
        siblings = tuple(normalize_unicode_text(suffix) for suffix in siblings)
        stem, suffix = os.path.splitext(name) if keep_extension else (name, "")
        key = (name.casefold(), keep_extension, tuple(item.casefold() for item in siblings))
        counter = self._next_suffixes.get(key, 1)
        while True:
            candidate = name if counter == 1 else f"{stem}__{counter}{suffix}"
            counter += 1
            self._next_suffixes[key] = counter
            self.probe_count += 1
            spellings = self._spellings(candidate, siblings)
            folded = tuple(spelling.casefold() for spelling in spellings)
            if any(spelling in self._reserved for spelling in folded):
                continue
            self._targets.add(folded[0])
            self._reserved.update(folded)
            return candidate


def unique_name(name, used, *, keep_extension=True):
    """The first spelling of `name` that this directory has not used yet.

    An attachment keeps its extension, so the suffix goes before it rather
    than changing what the file claims to be. A directory has no extension to
    keep, so the suffix goes at the end of it.
    """
    name = normalize_unicode_text(name)
    candidate = name
    stem, suffix = os.path.splitext(name) if keep_extension else (name, "")
    counter = 2
    while candidate.casefold() in used:
        candidate = f"{stem}__{counter}{suffix}"
        counter += 1
    used.add(candidate.casefold())
    return candidate


def filename_from_url(url):
    try:
        path = unquote(urlsplit(url).path)
    except ValueError:
        return "attachment"
    return path.rsplit("/", 1)[-1] or "attachment"


def redact_url(url, *, force=False):
    """A URL without its query or fragment, or nothing at all.

    A value that cannot be parsed cannot be trimmed, and a URL we cannot trim
    is one whose query we would otherwise persist whole: `http://[broken/?x`
    is not a URL to any parser, but it is a perfectly good place to hide a
    token. So an unparsable value is withheld rather than returned.
    """
    text = _remove_whatwg_url_controls(unescape(str(url)))
    canonical = text

    # Browsers parse these spellings as network authorities even though
    # urllib.parse leaves the would-be authority in the path. Normalize only
    # when that first component contains userinfo; ordinary relative paths
    # and prose retain their spelling.
    special = re.match(r"(?i)^(https?):[\\/]*(.*)$", canonical, re.DOTALL)
    if special:
        rest = special.group(2)
        authority = re.split(r"[\\/?#]", rest, maxsplit=1)[0]
        if "@" in authority:
            canonical = f"{special.group(1)}://{rest.replace(chr(92), '/')}"
    else:
        relative = re.match(r"^[\\/]{2,}(.*)$", canonical, re.DOTALL)
        if relative:
            rest = relative.group(1)
            authority = re.split(r"[\\/?#]", rest, maxsplit=1)[0]
            if "@" in authority:
                canonical = f"//{rest.replace(chr(92), '/')}"

    try:
        parsed = urlsplit(canonical)
    except ValueError:
        return WITHHELD
    if parsed.netloc:
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
    if (force or canonical.startswith("/") or canonical.startswith("./")) and (
        parsed.query or parsed.fragment
    ):
        return urlunsplit(("", "", parsed.path, "", ""))
    return canonical


def redact_urls_in_text(value):
    """Drop URL queries/fragments without rewriting the surrounding source.

    Challenge descriptions and rules are source documents rather than URL
    fields, so treating the whole string as one URL would either lose the
    document or retain signed links embedded inside it.  This scanner only
    touches recognizable absolute or path-relative URL tokens.  Closing source
    punctuation is detached before parsing and restored afterwards.
    """

    def clean(url):
        if FLAG_PAYLOAD_RE.fullmatch(url):
            return url
        return redact_url(unescape(url), force=True)

    def replace_url_token(match):
        url = match.group(0)
        trailing = ""
        while url and url[-1] in ")]},.;":
            trailing = url[-1] + trailing
            url = url[:-1]
        if any(
            start <= match.start() and match.start() + len(url) <= end
            for start, end in flag_ranges
        ):
            return match.group(0)
        # `issue#42` is ordinary prose rather than a carried fragment. A bare
        # opaque word or named query is withheld, while a numeric issue label
        # keeps the established source spelling.
        if re.fullmatch(r"[\w~%-]+#[0-9]+", url):
            return url + trailing
        return clean(url) + trailing

    def replace_markdown(match):
        return match.group(1) + clean(match.group(2)) + match.group(3)

    def replace_quoted_attribute(match):
        return (
            match.group(1)
            + match.group(2)
            + clean(match.group(3))
            + match.group(4)
        )

    def replace_unquoted_attribute(match):
        return match.group(1) + clean(match.group(2))

    # Character references can spell every structural part of a URL. Decode
    # them before looking for URL-shaped text so `&sol;&sol;user:pass@host`
    # cannot hide its authority from the scheme-relative scanner.
    canonical = unescape(normalize_unicode_text(value))
    canonical = URL_USERINFO_PREFIX_RE.sub(
        lambda match: _remove_whatwg_url_controls(match.group(0)),
        canonical,
    )
    result = MARKDOWN_DESTINATION_RE.sub(replace_markdown, canonical)
    result = HTML_QUOTED_URL_ATTRIBUTE_RE.sub(replace_quoted_attribute, result)
    result = HTML_UNQUOTED_URL_ATTRIBUTE_RE.sub(
        replace_unquoted_attribute,
        result,
    )
    flag_ranges = [match.span() for match in FLAG_PAYLOAD_RE.finditer(result)]
    return SOURCE_URL_RE.sub(replace_url_token, result)


def redact_secrets(value, secrets=()):
    """Remove every secret, including the spellings that only look different.

    Names travel on to `sanitize_component` and to the display, and both
    normalize first, so a token written in a compatibility form is the token:
    it is redacted here rather than reconstituted downstream. Text that holds
    no secret keeps its own spelling, because normalizing it would rewrite a
    value we were only asked to inspect.
    """
    result = normalize_unicode_text(value)
    spellings = _secret_spellings(secrets)
    marker = redaction_marker(spellings)
    for spelling in spellings:
        result = result.replace(spelling, marker)
    normalized = unicodedata.normalize("NFKC", result)
    if any(spelling in normalized for spelling in spellings):
        result = normalized
        for spelling in spellings:
            result = result.replace(spelling, marker)
    return result


def _spells_secret(component, secrets):
    """Whether an already sanitized component spells a secret.

    `sanitize_component` normalized it, so the component's own spelling is the
    last one left to check.
    """
    component = normalize_unicode_text(component)
    normalized = unicodedata.normalize("NFKC", component)
    return any(
        spelling in component or spelling in normalized
        for spelling in _secret_spellings(secrets)
    )


def _credential_safe_literal(preferred, secrets, alternatives, max_length):
    """Choose bounded public text that contains no configured credential."""
    for candidate in (preferred, *alternatives, ""):
        candidate = normalize_unicode_text(candidate)[:max_length]
        if not _spells_secret(candidate, secrets):
            return candidate
    # The final candidate above is empty and no configured credential is, so
    # this is only a defensive return if that invariant changes.
    return ""


def credential_safe_error(code, message, secrets=(), *, status=None):
    """Build an error whose bounded public fields cannot quote a credential.

    Ordinary credentials retain the established code and useful message.
    Very short or collectively exhaustive credentials select from fixed text
    that is independent of the credential, with the empty string as the
    finite last resort.
    """
    safe_code = _credential_safe_literal(
        code,
        secrets,
        ("blocked", "refused", "x", "q", "z", "0"),
        64,
    )
    safe_message = _credential_safe_literal(
        message,
        secrets,
        ("output blocked", "request refused", "x", "q", "z", "0"),
        120,
    )
    return CollectorError(safe_code, safe_message, status=status)


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
    joined = "/".join(normalize_unicode_text(part) for part in parts)
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
    preferred = normalize_unicode_text(preferred)
    fallback = normalize_unicode_text(fallback)
    digest = hashlib.sha256(normalize_unicode_text(seed).encode("utf-8")).hexdigest()[:16]
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
    persistent_allocator = isinstance(used, UniqueNameAllocator)
    allocator = used if persistent_allocator else UniqueNameAllocator(used)
    allocator.reserve_existing_siblings(siblings)
    for candidate in _name_candidates(preferred, seed, fallback, max_length):
        for _attempt in range(SAFE_NAME_ATTEMPTS):
            name = allocator.allocate(
                candidate,
                keep_extension=keep_extension,
                siblings=siblings,
            )
            paths = [(*parent_parts, name)]
            paths.extend((*parent_parts, name, *child) for child in children)
            paths.extend(
                (*parent_parts, f"{name}{suffix}") for suffix in siblings
            )
            if not any(path_spells_secret(path, secrets) for path in paths):
                if not persistent_allocator:
                    used.add(name.casefold())
                return name
    raise CollectorError(
        "unsafe_name",
        "cannot name an output path without disclosing a token",
    )


def _normalized_key_parts(key):
    value = normalize_unicode_text(key)
    value = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", value)
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return tuple(
        part for part in re.split(r"[^a-z0-9]+", value.casefold()) if part
    )


def _sensitive_key(key):
    parts = _normalized_key_parts(key)
    return bool(
        SENSITIVE_KEY_PARTS.intersection(parts)
        or any(SENSITIVE_COMPOUND_KEY_RE.fullmatch(part) for part in parts)
        or any(
            parts[index : index + 2] == ("api", "key")
            for index in range(max(0, len(parts) - 1))
        )
    )


def _metadata_key_available(candidate, result, secrets):
    """Whether a finished metadata key is both unused and secret-free."""
    return candidate not in result and redact_secrets(candidate, secrets) == candidate


def _next_private_scalar(value):
    """The next deterministic private-use scalar, or ``None`` at exhaustion."""
    if value < 0xE000:
        return 0xE000
    if value < 0xF8FF:
        return value + 1
    if value < 0xF0000:
        return 0xF0000
    if value < 0xFFFFD:
        return value + 1
    if value < 0x100000:
        return 0x100000
    if value < 0x10FFFD:
        return value + 1
    return None


def _unique_metadata_key(safe_key, result, secrets, next_suffixes):
    if _metadata_key_available(safe_key, result, secrets):
        return safe_key

    counter_key = ("numeric", safe_key)
    counter = next_suffixes.get(counter_key, 2)
    suffix_stem = f"{safe_key}__"
    suffix_stem = redact_secrets(suffix_stem, secrets)
    # Preserve the established readable suffix when it is safe, but do not
    # count forever when a configured secret conflicts with every digit.
    for _attempt in range(32):
        candidate = f"{suffix_stem}{counter}"
        counter += 1
        next_suffixes[counter_key] = counter
        if _metadata_key_available(candidate, result, secrets):
            return candidate

    # Private-use scalars are stable under NFKC and do not derive any plaintext
    # from the secret. The finite scalar space gives this path a hard stop while
    # providing far more unique keys than bounded metadata can contain.
    private_key = ("private", safe_key)
    codepoint = next_suffixes.get(private_key, 0xDFFF)
    marker = redaction_marker(secrets)
    while True:
        codepoint = _next_private_scalar(codepoint)
        if codepoint is None:
            raise CollectorError(
                "invalid_api_data",
                "metadata keys cannot be represented safely",
            )
        next_suffixes[private_key] = codepoint
        candidate = f"{marker}{chr(codepoint)}"
        if _metadata_key_available(candidate, result, secrets):
            return candidate


def safe_metadata(value, key="", secrets=()):
    return _safe_metadata(value, key, secrets, 0)


def _safe_metadata(value, key, secrets, depth):
    if isinstance(value, float) and not math.isfinite(value):
        raise CollectorError(
            "invalid_api_data",
            "metadata contains a non-finite number",
        )
    if key and _sensitive_key(key):
        return redaction_marker(secrets)
    if isinstance(value, (dict, list)) and depth >= MAX_METADATA_NESTING:
        raise CollectorError(
            "metadata_too_deep",
            "metadata nesting exceeds the supported limit",
        )
    if isinstance(value, dict):
        result = {}
        next_suffixes = {}
        for item_key, item_value in value.items():
            original_key = normalize_unicode_text(item_key)
            safe_key = redact_urls_in_text(
                redact_secrets(original_key, secrets)
            )
            candidate = _unique_metadata_key(
                safe_key,
                result,
                secrets,
                next_suffixes,
            )
            # Classification follows the completed key that will actually be
            # stored, after entity decoding, redaction, and collision suffixing.
            if _sensitive_key(candidate):
                result[candidate] = redaction_marker(secrets)
            else:
                result[candidate] = _safe_metadata(
                    item_value,
                    candidate,
                    secrets,
                    depth + 1,
                )
        return result
    if isinstance(value, list):
        return [
            _safe_metadata(item, key, secrets, depth + 1)
            for item in value
        ]
    if isinstance(value, str):
        lowered_key = normalize_unicode_text(key).lower()
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
        redacted = redact_secrets(value, secrets)
        if url_value:
            # URL-valued metadata is a URL, not surrounding prose. Settle its
            # outer whitespace before classification so a leading space
            # cannot bypass the scheme-relative authority check.
            canonical = _remove_whatwg_url_controls(unescape(redacted)).strip()
            return redact_secrets(redact_url(canonical, force=True), secrets)
        return redact_secrets(redact_urls_in_text(redacted), secrets)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        text = str(value)
        if redact_secrets(text, secrets) != text:
            return redaction_marker(secrets)
    return value


def safe_json_text(value, secrets=(), *, normalize_surrogates=False):
    """Serialize JSON without changing trusted decoded keys or values.

    API metadata is redacted before it reaches this boundary.  A configured
    token can nevertheless equal a collector-owned JSON key or enum value;
    changing that decoded value would corrupt the output contract.  JSON's
    Unicode escapes let the on-disk spelling omit those coincidental bytes
    while ``json.loads`` still sees the collector-owned schema.

    Only text inside JSON strings is escaped.  If a credential collides with
    unavoidable JSON grammar, the document cannot be represented safely and
    the caller gets a bounded, credential-free refusal.
    """
    spellings = tuple(
        sorted(
            _secret_spellings(secrets),
            key=lambda item: (-len(item), item),
        )
    )
    used_characters = set(spellings)

    def collect_characters(item):
        if isinstance(item, dict):
            for item_key, item_value in item.items():
                if isinstance(item_key, str):
                    used_characters.update(item_key)
                collect_characters(item_value)
        elif isinstance(item, (list, tuple)):
            for child in item:
                collect_characters(child)
        elif isinstance(item, str):
            used_characters.update(item)

    collect_characters(value)
    placeholder_expansions = {}
    expansion_placeholders = {}
    next_placeholder = 0xDFFF

    def placeholder(expansion):
        nonlocal next_placeholder
        existing = expansion_placeholders.get(expansion)
        if existing is not None:
            return existing
        while True:
            next_placeholder = _next_private_scalar(next_placeholder)
            if next_placeholder is None:
                raise credential_safe_error(
                    "unsafe_credential",
                    "required JSON cannot be encoded without disclosing a credential",
                    secrets,
                )
            candidate = chr(next_placeholder)
            if candidate not in used_characters:
                break
        used_characters.add(candidate)
        placeholder_expansions[candidate] = expansion
        expansion_placeholders[expansion] = candidate
        return candidate

    def code_unit_escapes(code_unit):
        digits = f"{code_unit:04X}"
        candidates = [""]
        for digit in digits:
            choices = (digit.lower(), digit.upper()) if digit in "ABCDEF" else (digit,)
            candidates = [prefix + choice for prefix in candidates for choice in choices]
        return tuple(f"\\u{digits_variant}" for digits_variant in candidates)

    def scalar_escape(character):
        codepoint = ord(character)
        if codepoint <= 0xFFFF:
            candidates = code_unit_escapes(codepoint)
        else:
            scalar = codepoint - 0x10000
            high = 0xD800 + (scalar >> 10)
            low = 0xDC00 + (scalar & 0x3FF)
            candidates = tuple(
                first + second
                for first in code_unit_escapes(high)
                for second in code_unit_escapes(low)
            )
        short_escape = {
            '"': '\\"',
            "\\": "\\\\",
            "\b": "\\b",
            "\f": "\\f",
            "\n": "\\n",
            "\r": "\\r",
            "\t": "\\t",
        }.get(character)
        if short_escape is not None:
            candidates = (*candidates, short_escape)
        for candidate in candidates:
            if not _spells_secret(candidate, spellings):
                return candidate
        return candidates[0]

    def transform_text(text):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in text):
            if normalize_surrogates:
                text = normalize_unicode_text(text)
            else:
                raise credential_safe_error(
                    "invalid_output",
                    "JSON text contains an isolated Unicode surrogate",
                    secrets,
                )
        result = []
        index = 0
        while index < len(text):
            spelling = next(
                (item for item in spellings if text.startswith(item, index)),
                None,
            )
            if spelling is not None:
                expansion = "".join(scalar_escape(character) for character in spelling)
                result.append(placeholder(expansion))
                index += len(spelling)
                continue
            character = text[index]
            # Prevent json.dumps from creating short escapes behind our back.
            # Quotes, reverse solidi and controls are represented with the
            # same semantic Unicode escapes used for credential occurrences.
            if character in {'"', "\\"} or ord(character) < 0x20:
                result.append(placeholder(scalar_escape(character)))
            else:
                result.append(character)
            index += 1
        return "".join(result)

    def transform(item):
        if isinstance(item, dict):
            return {
                transform_text(item_key) if isinstance(item_key, str) else item_key:
                transform(item_value)
                for item_key, item_value in item.items()
            }
        if isinstance(item, list):
            return [transform(child) for child in item]
        if isinstance(item, tuple):
            return tuple(transform(child) for child in item)
        if isinstance(item, str):
            return transform_text(item)
        return item

    payload = (
        json.dumps(
            transform(value),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
            allow_nan=False,
        )
        + "\n"
    )
    for marker, expansion in placeholder_expansions.items():
        payload = payload.replace(marker, expansion)
    if any(spelling in payload for spelling in spellings):
        raise credential_safe_error(
            "unsafe_credential",
            "required JSON cannot be encoded without disclosing a credential",
            secrets,
        )
    return payload


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
        checked = tuple(normalize_unicode_text(part) for part in parts)
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

    def read_bytes(self, parts, maximum=None):
        parts = self._parts(parts)
        if maximum is not None and (
            isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 0
        ):
            raise CollectorError("invalid_limit", "read limit must be a non-negative integer")
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
                    return stream.read() if maximum is None else stream.read(maximum)
            finally:
                if descriptor is not None:
                    os.close(descriptor)
        finally:
            os.close(directory)

    def hash_file(self, parts, maximum, *, prefix_bytes=0):
        if (
            isinstance(prefix_bytes, bool)
            or not isinstance(prefix_bytes, int)
            or prefix_bytes < 0
        ):
            raise CollectorError(
                "invalid_limit",
                "prefix size must be a non-negative integer",
            )
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
            prefix = bytearray()
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
                        if len(prefix) < prefix_bytes:
                            remaining = prefix_bytes - len(prefix)
                            prefix.extend(chunk[:remaining])
                        digest.update(chunk)
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            result = (size, digest.hexdigest())
            if prefix_bytes:
                return (*result, bytes(prefix))
            return result
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

    def atomic_bytes(self, parts, payload):
        parts = self._parts(parts)
        if not isinstance(payload, bytes):
            raise TypeError("atomic_bytes payload must be bytes")
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

    def atomic_text(self, parts, value):
        if not isinstance(value, str):
            raise TypeError("atomic_text value must be str")
        self.atomic_bytes(parts, normalize_unicode_text(value).encode("utf-8"))

    def atomic_json(self, parts, value, *, secrets=()):
        payload = safe_json_text(value, secrets, normalize_surrogates=True)
        self.atomic_text(parts, payload)
