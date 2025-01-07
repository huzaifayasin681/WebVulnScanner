# tests/test_utils.py

import unittest
from scanner import utils

class TestUtils(unittest.TestCase):
    def test_is_valid_url(self):
        valid_urls = [
            "http://example.com",
            "https://www.example.com/path?query=param",
            "https://sub.domain.example.com:8080/",
        ]
        invalid_urls = [
            "ftp://example.com",
            "http//missing-colon.com",
            "justastring",
            "http://",
            "://missing-scheme.com",
        ]

        for url in valid_urls:
            self.assertTrue(utils.is_valid_url(url), f"Should be valid: {url}")

        for url in invalid_urls:
            self.assertFalse(utils.is_valid_url(url), f"Should be invalid: {url}")

    def test_format_results(self):
        scan_results = {
            'target_url': 'https://example.com',
            'scan_type': 'sqlxss',
            'depth': 2,
            'results': {
                'sqli': ["SQLi vulnerability found in parameter 'id'"],
                'xss': ["XSS vulnerability found in comment section"]
            }
        }

        formatted = utils.format_results(scan_results)
        self.assertIn("SQLi vulnerability found in parameter 'id'", formatted)
        self.assertIn("XSS vulnerability found in comment section", formatted)

if __name__ == '__main__':
    unittest.main()
