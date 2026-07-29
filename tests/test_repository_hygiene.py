from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RepositoryHygieneTests(unittest.TestCase):
    def is_ignored(self, path):
        result = subprocess.run(
            ["git", "check-ignore", "--no-index", "--quiet", path],
            cwd=ROOT,
            check=False,
        )
        return result.returncode == 0

    def test_generated_and_sensitive_paths_are_ignored_but_example_is_retained(self):
        for path in (
            "collector.json",
            "collected/example",
            "output/example",
            "secrets/example.token",
            "credential.token",
            "download.part",
        ):
            with self.subTest(path=path):
                self.assertTrue(self.is_ignored(path), f"{path} should be ignored")

        self.assertFalse(
            self.is_ignored("config.example.json"),
            "the committed configuration example must remain visible",
        )

    def test_readme_documents_custom_outputs_and_stale_output_after_fatal_attempt(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        self.assertIn("custom `output_root`", readme)
        self.assertIn("`.gitignore`", readme)
        self.assertIn("stale", readme.lower())
        self.assertIn("fatal", readme.lower())


if __name__ == "__main__":
    unittest.main()
