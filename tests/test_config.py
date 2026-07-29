import json
from pathlib import Path
import tempfile
import unittest

from ctf_collector.config import load_config
from ctf_collector.errors import CollectorError


class ConfigTests(unittest.TestCase):
    def test_multiple_ctfs_and_relative_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "nested" / "config.json"
            config_path.parent.mkdir()
            config_path.write_text(
                json.dumps(
                    {
                        "ctfs": [
                            {
                                "name": "a",
                                "platform": "ctfd",
                                "base_url": "https://a.example",
                                "token_file": "../secrets/a.token",
                                "output_root": "../out",
                            },
                            {
                                "name": "b",
                                "platform": "rctf",
                                "base_url": "https://b.example",
                                "token_file": "../secrets/b.token",
                                "output_root": "../out",
                                "tls": {"verify": True, "ca_file": "../ca.pem"},
                                "unauthenticated_attachment_origins": [
                                    "https://cdn.example"
                                ],
                                "fail_on_partial": False,
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            configs = load_config(config_path)

            self.assertEqual([item["name"] for item in configs], ["a", "b"])
            self.assertEqual(
                configs[0]["token_file"],
                (Path(tmp) / "secrets" / "a.token").resolve(),
            )
            self.assertEqual(
                configs[1]["output_root"],
                (Path(tmp) / "out").resolve(),
            )
            self.assertFalse(configs[1]["fail_on_partial"])
            self.assertEqual(configs[0]["limits"]["page_size"], 100)

    def test_rejects_query_base_url_duplicate_name_and_unbounded_values(self):
        invalid_ctfs = [
            [
                {
                    "name": "a",
                    "platform": "ctfd",
                    "base_url": "https://a.example?token=no",
                    "token_file": "a.token",
                    "output_root": "out",
                }
            ],
            [
                {
                    "name": "same",
                    "platform": "ctfd",
                    "base_url": "https://a.example",
                    "token_file": "a.token",
                    "output_root": "out",
                },
                {
                    "name": "same",
                    "platform": "rctf",
                    "base_url": "https://b.example",
                    "token_file": "b.token",
                    "output_root": "out",
                },
            ],
            [
                {
                    "name": "a",
                    "platform": "ctfd",
                    "base_url": "https://a.example",
                    "token_file": "a.token",
                    "output_root": "out",
                    "limits": {"page_size": 101},
                }
            ],
        ]
        for ctfs in invalid_ctfs:
            with self.subTest(ctfs=ctfs), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "config.json"
                path.write_text(json.dumps({"ctfs": ctfs}), encoding="utf-8")
                with self.assertRaises(CollectorError):
                    load_config(path)

    def test_rejects_sanitized_casefolded_ctf_directory_collision_per_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            common = {
                "platform": "ctfd",
                "base_url": "https://ctf.example",
                "token_file": "token",
                "output_root": "out",
            }
            path.write_text(
                json.dumps(
                    {
                        "ctfs": [
                            {**common, "name": "Example CTF"},
                            {**common, "name": "example_ctf"},
                        ]
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaises(CollectorError) as caught:
                load_config(path)

            self.assertEqual(caught.exception.code, "invalid_config")
            self.assertIn("output directory", caught.exception.message)

    def test_sanitized_ctf_directory_collision_is_allowed_across_distinct_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            common = {
                "platform": "ctfd",
                "base_url": "https://ctf.example",
                "token_file": "token",
            }
            path.write_text(
                json.dumps(
                    {
                        "ctfs": [
                            {**common, "name": "Example CTF", "output_root": "one"},
                            {**common, "name": "example_ctf", "output_root": "two"},
                        ]
                    }
                ),
                encoding="utf-8",
            )

            configs = load_config(path)

            self.assertEqual(len(configs), 2)


if __name__ == "__main__":
    unittest.main()
