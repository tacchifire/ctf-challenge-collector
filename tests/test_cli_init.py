import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "ctf-collect"


class InitCliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [str(LAUNCHER), *map(str, args)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_init_writes_safe_multi_ctf_template_without_token_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "collector.json"
            result = self.run_cli("init", "--config", config_path)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(config_path.exists())
            self.assertEqual(config_path.stat().st_mode & 0o777, 0o600)

            raw = config_path.read_text(encoding="utf-8")
            config = json.loads(raw)
            self.assertIsInstance(config["ctfs"], list)
            self.assertGreaterEqual(len(config["ctfs"]), 2)
            self.assertEqual(
                {item["platform"] for item in config["ctfs"]},
                {"ctfd", "rctf"},
            )
            self.assertTrue(all("token_file" in item for item in config["ctfs"]))
            self.assertNotIn('"token"', raw)
            self.assertNotIn('"authorization"', raw.lower())
            self.assertIn("Created", result.stdout)

    def test_init_refuses_to_overwrite_existing_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "collector.json"
            config_path.write_text('{"keep": true}\n', encoding="utf-8")

            result = self.run_cli("init", "--config", config_path)

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(
                config_path.read_text(encoding="utf-8"),
                '{"keep": true}\n',
            )
            self.assertIn("already exists", result.stderr)

    def test_launcher_is_executable(self):
        self.assertTrue(os.access(LAUNCHER, os.X_OK))


if __name__ == "__main__":
    unittest.main()
