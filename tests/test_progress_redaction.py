"""What a value chosen by the API is allowed to put on the operator's terminal.

The progress display is as public as any other terminal output, so a name or
a category from a challenge server has to pass a boundary that is closed by
default. A failure here never quotes the value under test: echoing the match
into the test log would disclose exactly what the boundary exists to withhold.
"""

from io import StringIO
import json
from pathlib import Path
import tempfile
import unicodedata
import unittest
from unittest.mock import patch
from urllib.parse import unquote, urlsplit

from ctf_collector.collector import collect_ctf
from ctf_collector.errors import CollectorError
from ctf_collector.progress import ProgressReporter
from ctf_collector.safety import (
    ctf_directory_name,
    redact_secrets,
    safe_unique_component,
    sanitize_component_without_secrets,
)

from .support import FakeOpener, make_config


ATTACHMENT_BODY = b"attachment payload"
# make_config writes "<platform>-secret" into the token file.
TOKEN = "ctfd-secret"
# NFKC turns the full width letters back into the token itself.
COMPATIBILITY_TOKEN = "ｃｔｆｄ-secret"
# A token whose separator is the one sanitizing folds a run of.
FOLDING_TOKEN = "abc_def"


def challenge_responder(challenges):
    """A listing and one detail route per challenge, plus the attachment."""
    details = {str(item["id"]): item for item in challenges}
    summaries = [
        {key: value for key, value in item.items() if key != "files"}
        for item in challenges
    ]

    def respond(request):
        path = urlsplit(request["url"]).path
        if path == "/api/v1/challenges":
            return 200, {}, {
                "data": summaries,
                "meta": {"pagination": {"page": 1, "pages": 1, "next": None}},
            }
        prefix = "/api/v1/challenges/"
        if path.startswith(prefix):
            detail = details.get(unquote(path[len(prefix):]))
            if detail is not None:
                return 200, {}, {"data": detail}
        if path == "/files/a.bin":
            return 200, {"Content-Length": len(ATTACHMENT_BODY)}, ATTACHMENT_BODY
        return 404, {}, b"missing"

    return respond


def responder(*, name="First", category="Web", files=()):
    return challenge_responder(
        [{"id": 1, "name": name, "category": category, "files": list(files)}]
    )


class Transcript:
    """Records events and renders them exactly as `ctf-collect sync` does."""

    def __init__(self):
        self.stream = StringIO()
        self.events = []
        self._reporter = ProgressReporter(self.stream)

    def __call__(self, event):
        self.events.append(event)
        self._reporter(event)

    def text(self):
        return self.stream.getvalue()

    def discloses(self, markers):
        """Whether a marker survives in the events or in the rendered lines.

        Both surfaces count: the rendered line is what an operator reads, and
        the event is what any other reporter would be handed.
        """
        surfaces = (self.stream.getvalue(), "\n".join(repr(e) for e in self.events))
        return any(marker in surface for surface in surfaces for marker in markers)


HOSTILE_VALUES = (
    (
        "authorization header of a mapping value",
        {"authorization": "Bearer AUTHSECRET"},
        ("AUTHSECRET", "Bearer"),
    ),
    (
        "cookie of a mapping value",
        {"cookie": "COOKIESECRET"},
        ("COOKIESECRET",),
    ),
    (
        "flag candidate of a mapping value",
        {"flag": "flag{candidate-secret}"},
        ("candidate-secret", "flag{"),
    ),
    (
        "source URL of a mapping value",
        {"url": "https://source/?q=QUERYSECRET#FRAGMENTSECRET"},
        ("QUERYSECRET", "FRAGMENTSECRET", "://", "source"),
    ),
    (
        "query and fragment of a signed path",
        "signed/file.bin?signature=QUERYSECRET#FRAGMENTSECRET",
        ("QUERYSECRET", "FRAGMENTSECRET", "signature"),
    ),
    (
        "flag candidate",
        "flag{candidate-secret}",
        ("candidate-secret", "flag{"),
    ),
)


def run_collection(config_name=None, **response):
    transcript = Transcript()
    with tempfile.TemporaryDirectory() as tmp:
        config = make_config(tmp)
        if config_name is not None:
            config["name"] = config_name
        fake = FakeOpener(responder(**response))
        with patch("ctf_collector.http.build_opener", return_value=fake):
            manifest = collect_ctf(config, progress=transcript)
    return transcript, manifest


class TreeTranscript(Transcript):
    """A transcript that also records the tree as it stood at each event.

    A temporary file exists only while the body it holds is still arriving, so
    the paths that reach the filesystem are read back from inside the download
    rather than from the tree that survives it.
    """

    def __init__(self, root):
        super().__init__()
        self.root = Path(root)
        self.observed = set()

    def __call__(self, event):
        self.observe()
        super().__call__(event)

    def observe(self):
        if not self.root.exists():
            return
        for path in self.root.rglob("*"):
            self.observed.add(str(path.relative_to(self.root)))


class Collection:
    """What a run left behind: the tree, both manifests and the transcript.

    The returned manifest and the stored one are kept apart because only the
    stored one is what a later run reads back, and a path that resolves in one
    but not the other is a manifest that no longer names the file it describes.
    """

    def __init__(self, transcript, manifest, persisted, written, files, observed=()):
        self.transcript = transcript
        self.manifest = manifest
        self.persisted = persisted
        self.written = written
        self.files = files
        self.observed = observed

    def manifests(self):
        return (("returned", self.manifest), ("stored", self.persisted))


def run_collection_with_token(token, respond=None, *, observe=False, **response):
    """A collection whose API token is the value the tree must never spell.

    The output tree is read back before it is removed, because the path that
    reaches the filesystem is the one the manifest and the display promise to
    withhold. `observe` reads it back from inside the run as well, for a path
    that no longer exists once the run is over.
    """
    with tempfile.TemporaryDirectory() as tmp:
        config = make_config(tmp)
        transcript = (
            TreeTranscript(config["output_root"]) if observe else Transcript()
        )
        token_file = Path(tmp) / "chosen.token"
        token_file.write_text(f"{token}\n", encoding="utf-8")
        config["token_file"] = token_file
        fake = FakeOpener(respond if respond is not None else responder(**response))
        with patch("ctf_collector.http.build_opener", return_value=fake):
            manifest = collect_ctf(config, progress=transcript)
        observed = ()
        if observe:
            transcript.observe()
            observed = transcript.observed
        ctf_directory = Path(config["output_root"]) / ctf_directory_name(
            config["name"]
        )
        entries = sorted(ctf_directory.rglob("*"))
        written = [str(path.relative_to(ctf_directory)) for path in entries]
        files = {
            str(path.relative_to(ctf_directory))
            for path in entries
            if path.is_file()
        }
        persisted = json.loads(
            (ctf_directory / "manifest.json").read_text(encoding="utf-8")
        )
    return Collection(transcript, manifest, persisted, written, files, observed)


def run_folding_collection(**response):
    """A collection whose token is one folded separator away from a name."""
    collection = run_collection_with_token(FOLDING_TOKEN, **response)
    return collection.transcript, collection.manifest, collection.written


class SeparatorFoldingTokenTests(unittest.TestCase):
    """A name that sanitizing folds back into the token is still the token.

    `sanitize_component` normalizes separators and collapses a run of them, so
    a value that matched no secret on the way in can spell one on the way out.
    """

    def assert_token_withheld(self, transcript, manifest, written):
        self.assertFalse(
            any(FOLDING_TOKEN in path for path in written),
            "an output path disclosed the API token",
        )
        entry = manifest["challenges"][0]["files"][0]
        self.assertFalse(
            FOLDING_TOKEN in entry["local_path"],
            "the manifest disclosed the API token",
        )
        self.assertIn(
            entry["local_path"],
            written,
            "the manifest names a file that was never written",
        )
        self.assertFalse(
            transcript.discloses((FOLDING_TOKEN,)),
            "progress disclosed the API token",
        )

    def test_a_folded_token_in_a_challenge_name_never_becomes_a_path(self):
        transcript, manifest, written = run_folding_collection(
            name="abc__def",
            files=({"url": "/files/a.bin"},),
        )

        self.assert_token_withheld(transcript, manifest, written)

    def test_a_folded_token_in_a_category_never_becomes_a_path(self):
        transcript, manifest, written = run_folding_collection(
            category="abc//def",
            files=({"url": "/files/a.bin"},),
        )

        self.assert_token_withheld(transcript, manifest, written)

    def test_a_folded_token_in_an_attachment_name_never_becomes_a_path(self):
        transcript, manifest, written = run_folding_collection(
            files=({"url": "/files/a.bin", "name": "abc__def.bin"},),
        )

        self.assert_token_withheld(transcript, manifest, written)


class TokenWithheldAssertions:
    """What every surface of a finished collection has to hold.

    The tree, the manifest a later run reads back and the display are checked
    together, because a token withheld from one of them and written to another
    is a token that was disclosed.
    """

    def assert_token_withheld(self, collection, token):
        self.assertFalse(
            any(token in path for path in collection.written),
            "an output path disclosed the API token",
        )
        self.assertFalse(
            any(token in path for path in collection.observed),
            "a path that existed during the run disclosed the API token",
        )
        self.assertFalse(
            collection.transcript.discloses((token,)),
            "progress disclosed the API token",
        )
        for label, manifest in collection.manifests():
            for challenge in manifest["challenges"]:
                self.assertFalse(
                    token in challenge["directory"],
                    f"the {label} manifest disclosed the API token",
                )
                for entry in challenge["files"]:
                    self.assertFalse(
                        token in entry["local_path"],
                        f"the {label} manifest disclosed the API token",
                    )
                    self.assertTrue(
                        entry["local_path"] in collection.files,
                        f"the {label} manifest names a file that was never written",
                    )

    def assert_attachments_were_stored(self, collection, count):
        stored = [
            entry
            for challenge in collection.manifest["challenges"]
            for entry in challenge["files"]
        ]
        self.assertEqual(len(stored), count)
        for entry in stored:
            self.assertEqual(entry["status"], "downloaded")


class CompletedPathTokenTests(TokenWithheldAssertions, unittest.TestCase):
    """A token that only the finished path spells.

    Every component below is safe on its own. What completes the token is the
    join - an id to a name, a category to a directory - or the suffix that
    resolves a collision, and the finished path is what reaches the filesystem,
    the manifest and the display alike.
    """

    def test_a_token_completed_by_the_id_and_name_join_is_never_a_path(self):
        token = "1-First"

        collection = run_collection_with_token(
            token,
            files=({"url": "/files/a.bin"},),
        )

        self.assert_token_withheld(collection, token)
        self.assert_attachments_were_stored(collection, 1)

    def test_a_token_completed_by_the_category_join_is_never_a_path(self):
        token = "Web/1-First"

        collection = run_collection_with_token(
            token,
            files=({"url": "/files/a.bin"},),
        )

        self.assert_token_withheld(collection, token)
        self.assert_attachments_were_stored(collection, 1)

    def test_a_token_completed_by_a_challenge_collision_suffix_is_never_a_path(self):
        token = "1-First__2"
        # Two ids that sanitizing spells the same way, so the second challenge
        # is the one the collision suffix renames.
        collection = run_collection_with_token(
            token,
            respond=challenge_responder(
                [
                    {
                        "id": identifier,
                        "name": "First",
                        "category": "Web",
                        "files": [{"url": "/files/a.bin"}],
                    }
                    for identifier in (1, "1.")
                ]
            ),
        )

        self.assert_token_withheld(collection, token)
        self.assert_attachments_were_stored(collection, 2)

    def test_a_token_completed_by_a_filename_collision_suffix_is_never_a_path(self):
        token = "a__2.bin"

        collection = run_collection_with_token(
            token,
            files=({"url": "/files/a.bin"}, {"url": "/files/a.bin"}),
        )

        self.assert_token_withheld(collection, token)
        self.assert_attachments_were_stored(collection, 2)


class DerivedPathTokenTests(TokenWithheldAssertions, unittest.TestCase):
    """A token that only a name we derive from a chosen name spells.

    Neither the temporary file a download writes beside its target nor the one
    an atomic write puts a document under is the chosen name itself, yet both
    are fixed derivations of it and both reach the disk. So the name has to be
    chosen for them too, and the name that is chosen is the one the tree, the
    manifest and the display all agree on.
    """

    def test_a_token_completed_by_a_download_temporary_name_is_never_a_path(self):
        token = "a.bin.part"

        collection = run_collection_with_token(
            token,
            files=({"url": "/files/a.bin"},),
            observe=True,
        )

        self.assert_token_withheld(collection, token)
        self.assert_attachments_were_stored(collection, 1)
        entry = collection.manifest["challenges"][0]["files"][0]
        self.assertFalse(
            entry["local_path"].endswith("/a.bin"),
            "the attachment kept the name its temporary file completed",
        )

    def test_a_token_completed_by_a_challenge_temporary_child_renames_the_directory(
        self,
    ):
        token = "1-First/.challenge.json.part"

        collection = run_collection_with_token(
            token,
            files=({"url": "/files/a.bin"},),
            observe=True,
        )

        self.assert_token_withheld(collection, token)
        self.assert_attachments_were_stored(collection, 1)
        directory = collection.manifest["challenges"][0]["directory"]
        self.assertFalse(
            directory.endswith("/1-First"),
            "the challenge kept the directory its temporary child completed",
        )


class FixedChildTokenTests(unittest.TestCase):
    """A token the CTF directory only spells once its own files hang under it.

    The manifest, and the name it is written under before it is the manifest,
    are the same on every run and always sit directly beneath the CTF
    directory. That directory is named from the configuration rather than from
    the API, so there is no later candidate to fall back to: a name that
    completes a token there is refused before an output tree exists.
    """

    def assert_refused_before_any_output(self, token):
        transcript = Transcript()
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            token_file = Path(tmp) / "chosen.token"
            token_file.write_text(f"{token}\n", encoding="utf-8")
            config["token_file"] = token_file
            fake = FakeOpener(responder(files=({"url": "/files/a.bin"},)))
            with patch("ctf_collector.http.build_opener", return_value=fake):
                with self.assertRaises(CollectorError) as caught:
                    collect_ctf(config, progress=transcript)
            self.assertIn(
                caught.exception.code,
                {"invalid_config", "unsafe_name"},
            )
            self.assertFalse(
                Path(config["output_root"]).exists(),
                "a refused collection left an output tree behind",
            )
        self.assertFalse(
            transcript.discloses((token,)),
            "progress disclosed the API token",
        )

    def test_a_token_completed_by_the_manifest_is_refused(self):
        self.assert_refused_before_any_output("fake-ctfd/manifest.json")

    def test_a_token_completed_by_the_manifest_temporary_name_is_refused(self):
        self.assert_refused_before_any_output("fake-ctfd/.manifest.json.part")


class CollectorProgressBoundaryTests(unittest.TestCase):
    def assert_withheld(self, transcript, markers, label):
        self.assertFalse(
            transcript.discloses(markers),
            f"progress disclosed the {label}",
        )

    def test_a_hostile_challenge_name_never_reaches_the_progress_display(self):
        for label, value, markers in HOSTILE_VALUES:
            with self.subTest(case=label):
                transcript, _manifest = run_collection(name=value)
                self.assert_withheld(transcript, markers, label)

    def test_a_hostile_category_never_reaches_the_progress_display(self):
        for label, value, markers in HOSTILE_VALUES:
            with self.subTest(case=label):
                transcript, _manifest = run_collection(category=value)
                self.assert_withheld(transcript, markers, label)

    def test_an_ordinary_name_and_category_stay_readable(self):
        transcript, _manifest = run_collection(
            name="Fox hunting on-site",
            category="Signal identification",
        )

        self.assertIn(
            "(1/1) Signal identification / Fox hunting on-site",
            transcript.text(),
        )


class CompatibilityTokenTests(unittest.TestCase):
    """A token spelled in a compatibility form is still the token."""

    def test_a_compatibility_token_in_a_name_is_redacted_before_display(self):
        transcript, _manifest = run_collection(name=COMPATIBILITY_TOKEN)

        self.assertFalse(
            transcript.discloses((TOKEN,)),
            "progress disclosed the API token",
        )

    def test_a_compatibility_token_in_a_category_is_redacted_before_display(self):
        transcript, _manifest = run_collection(category=COMPATIBILITY_TOKEN)

        self.assertFalse(
            transcript.discloses((TOKEN,)),
            "progress disclosed the API token",
        )

    def test_a_compatibility_token_never_becomes_an_attachment_path(self):
        transcript, manifest = run_collection(
            files=({"url": "/files/a.bin", "name": f"{COMPATIBILITY_TOKEN}.bin"},),
        )

        local_path = manifest["challenges"][0]["files"][0]["local_path"]
        self.assertFalse(
            TOKEN in local_path,
            "the stored attachment path disclosed the API token",
        )
        self.assertFalse(
            transcript.discloses((TOKEN,)),
            "progress disclosed the API token",
        )

    def test_a_compatibility_token_in_the_ctf_name_is_rejected(self):
        with self.assertRaises(CollectorError) as caught:
            run_collection(config_name=COMPATIBILITY_TOKEN)

        self.assertEqual(caught.exception.code, "invalid_config")


class SecretRedactionOrderTests(unittest.TestCase):
    def test_a_compatibility_spelling_of_a_secret_cannot_be_restored(self):
        redacted = redact_secrets(f"name {COMPATIBILITY_TOKEN}", (TOKEN,))

        self.assertFalse(
            TOKEN in unicodedata.normalize("NFKC", redacted),
            "normalizing the redacted value restored the secret",
        )

    def test_a_literal_secret_is_still_replaced(self):
        result = redact_secrets(f"a {TOKEN} b", (TOKEN,))

        self.assertTrue(result == "a [REDACTED] b", "the secret was not replaced")

    def test_text_without_a_secret_is_returned_unchanged(self):
        self.assertEqual(
            redact_secrets("Buffer Overflow Ａ", (TOKEN,)),
            "Buffer Overflow Ａ",
        )


class SanitizedComponentBoundaryTests(unittest.TestCase):
    """The second half of the path boundary: what sanitizing itself spells."""

    def sanitize(self, value, secrets, fallback="challenge"):
        return sanitize_component_without_secrets(value, secrets, fallback)

    def test_an_ordinary_name_keeps_the_component_it_always_had(self):
        self.assertEqual(
            self.sanitize("Buffer Overflow", (FOLDING_TOKEN,)),
            "Buffer_Overflow",
        )

    def test_a_folded_separator_cannot_restore_a_secret(self):
        self.assertEqual(self.sanitize("abc__def", (FOLDING_TOKEN,)), "challenge")

    def test_a_fallback_that_spells_a_secret_is_replaced_in_turn(self):
        self.assertEqual(
            self.sanitize("abc__def", (FOLDING_TOKEN, "challenge")),
            "redacted",
        )

    def test_a_component_with_no_safe_spelling_is_refused(self):
        with self.assertRaises(CollectorError) as caught:
            self.sanitize("abc__def", (FOLDING_TOKEN, "challenge", "redacted"))

        self.assertEqual(caught.exception.code, "unsafe_name")


class CompletedPathComponentTests(unittest.TestCase):
    """The third half of the boundary: what the finished path spells.

    A component is chosen for the path it completes, so the parent above it,
    the fixed children written beneath it and the suffix that resolves a
    collision all belong to the check.
    """

    def choose(self, secrets, preferred="1-First", used=None, **kwargs):
        return safe_unique_component(
            ("out", "Web"),
            preferred,
            set() if used is None else used,
            secrets,
            fallback="challenge",
            keep_extension=False,
            **kwargs,
        )

    def test_a_name_no_secret_completes_is_the_one_that_is_used(self):
        self.assertEqual(self.choose((FOLDING_TOKEN,)), "1-First")

    def test_a_name_the_parent_completes_is_replaced(self):
        chosen = self.choose(("Web/1-First",))

        self.assertFalse(
            "1-First" in chosen,
            "the replacement kept the name the parent completed",
        )
        self.assertFalse(
            "Web/1-First" in f"out/Web/{chosen}",
            "the replacement still completed the secret",
        )

    def test_a_replacement_is_the_same_name_on_every_run(self):
        secrets = ("Web/1-First",)

        self.assertEqual(self.choose(secrets), self.choose(secrets))

    def test_two_replaced_names_stay_apart(self):
        secrets = ("Web/1-First", "Web/2-Second")

        self.assertNotEqual(
            self.choose(secrets, seed="1-First"),
            self.choose(secrets, seed="2-Second"),
        )

    def test_a_collision_suffix_that_completes_a_secret_is_passed_over(self):
        chosen = self.choose(("1-First__2",), used={"1-first"})

        self.assertEqual(chosen, "1-First__3")

    def test_a_child_written_under_the_name_is_checked_as_well(self):
        chosen = self.choose(
            ("1-First/challenge.json",),
            children=(("challenge.json",),),
        )

        completed = f"out/Web/{chosen}/challenge.json"
        self.assertFalse(
            "1-First/challenge.json" in completed,
            "a name whose child completed the secret was used anyway",
        )

    def test_a_parent_that_spells_the_secret_alone_is_refused(self):
        with self.assertRaises(CollectorError) as caught:
            self.choose(("out/Web",))

        self.assertEqual(caught.exception.code, "unsafe_name")


class SiblingPathComponentTests(unittest.TestCase):
    """The name a download writes beside its target belongs to the check.

    An attachment is written under `<name>.part` until the whole body has
    arrived, so that name is as much a path we chose as the target itself.
    """

    def choose(self, secrets, preferred="a.bin", used=None):
        return safe_unique_component(
            ("out", "Web", "1-First", "files"),
            preferred,
            set() if used is None else used,
            secrets,
            fallback="attachment",
            siblings=(".part",),
        )

    def test_a_name_no_sibling_completes_is_the_one_that_is_used(self):
        self.assertEqual(self.choose(("b.bin.part",)), "a.bin")

    def test_a_name_whose_temporary_sibling_completes_a_secret_is_replaced(self):
        chosen = self.choose(("a.bin.part",))

        self.assertNotEqual(chosen, "a.bin")
        self.assertFalse(
            "a.bin.part" in f"out/Web/1-First/files/{chosen}.part",
            "the replacement still completed the secret",
        )

    def test_a_sibling_the_parent_alone_completes_is_refused(self):
        with self.assertRaises(CollectorError) as caught:
            self.choose(("out/Web/1-First/files",))

        self.assertEqual(caught.exception.code, "unsafe_name")


class ReporterBoundaryTests(unittest.TestCase):
    """The reporter is the last boundary before the terminal."""

    def render(self, event):
        stream = StringIO()
        ProgressReporter(stream)(event)
        return stream.getvalue()

    def challenge(self, **fields):
        return self.render(
            {
                "event": "challenge",
                "ctf": "x",
                "index": 1,
                "total": 1,
                "name": "One",
                "category": "web",
                **fields,
            }
        )

    def test_a_mapping_name_is_withheld_instead_of_being_stringified(self):
        text = self.challenge(name={"authorization": "Bearer AUTHSECRET"})

        self.assertFalse("AUTHSECRET" in text, "the reporter displayed a mapping")
        self.assertIn("[REDACTED]", text)

    def test_a_list_category_is_withheld_instead_of_being_stringified(self):
        text = self.challenge(category=["flag{candidate-secret}"])

        self.assertFalse(
            "candidate-secret" in text,
            "the reporter displayed a list category",
        )
        self.assertIn("[REDACTED]", text)

    def test_a_url_like_name_is_withheld(self):
        text = self.challenge(name="https://source/?q=QUERYSECRET")

        self.assertFalse("QUERYSECRET" in text, "the reporter displayed a query")
        self.assertFalse("://" in text, "the reporter displayed a source URL")

    def test_a_query_and_fragment_are_dropped_from_a_path(self):
        text = self.render(
            {
                "event": "attachment_start",
                "ctf": "x",
                "local_path": "web/1-One/files/a.bin?sig=QUERYSECRET#FRAGMENTSECRET",
                "declared": None,
            }
        )

        self.assertFalse(
            "QUERYSECRET" in text or "FRAGMENTSECRET" in text,
            "the reporter displayed a query or fragment",
        )
        self.assertIn("web/1-One/files/a.bin", text)

    def test_an_ordinary_challenge_line_is_unchanged(self):
        self.assertEqual(
            self.challenge(),
            "[x] (1/1) web / One\n",
        )


if __name__ == "__main__":
    unittest.main()
