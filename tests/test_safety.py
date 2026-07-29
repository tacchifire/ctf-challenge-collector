import unittest

from ctf_collector.safety import safe_metadata, sanitize_component, unique_name


class SafetyTests(unittest.TestCase):
    def test_components_reject_traversal_separators_controls_and_devices(self):
        self.assertEqual(sanitize_component("../../CON"), "_CON")
        self.assertEqual(sanitize_component("/absolute\\path"), "absolute_path")
        self.assertEqual(sanitize_component("a\x00b\nc"), "a_b_c")
        self.assertEqual(sanitize_component(".."), "unnamed")
        self.assertEqual(sanitize_component("Lpt1.txt"), "_Lpt1.txt")

    def test_case_insensitive_collisions_are_deterministic(self):
        used = set()
        self.assertEqual(unique_name("Flag.txt", used), "Flag.txt")
        self.assertEqual(unique_name("flag.txt", used), "flag__2.txt")
        self.assertEqual(unique_name("FLAG.txt", used), "FLAG__3.txt")

    def test_long_unicode_component_has_a_deterministic_byte_bound(self):
        value = "問題" * 100
        first = sanitize_component(value)
        second = sanitize_component(value)
        self.assertEqual(first, second)
        self.assertLessEqual(len(first.encode("utf-8")), 120)
        self.assertRegex(first, r"__[0-9a-f]{10}$")

    def test_secret_keys_are_normalized_across_camel_snake_and_hyphen_forms(self):
        metadata = safe_metadata(
            {
                "accessToken": "camel",
                "access_token": "snake",
                "access-token": "hyphen",
                "apiKey": "api-camel",
                "api-key": "api-hyphen",
                "ordinary": "kept",
            }
        )

        self.assertEqual(metadata["ordinary"], "kept")
        for key in ("accessToken", "access_token", "access-token", "apiKey", "api-key"):
            with self.subTest(key=key):
                self.assertEqual(metadata[key], "[REDACTED]")

    def test_download_key_redacts_relative_url_query_and_fragment(self):
        metadata = safe_metadata(
            {
                "download": "signed/file.bin?token=secret#private",
                "caption": "question? and fragment# are prose",
            }
        )

        self.assertEqual(metadata["download"], "signed/file.bin")
        self.assertEqual(metadata["caption"], "question? and fragment# are prose")


if __name__ == "__main__":
    unittest.main()
