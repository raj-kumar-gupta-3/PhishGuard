import unittest
from phishguard import analyze_url


class TestPhishGuard(unittest.TestCase):

    def test_https_url(self):
        result = analyze_url("https://example.com")
        self.assertEqual(result["result"], "LOW RISK")

    def test_http_url(self):
        result = analyze_url("http://example.com")
        self.assertEqual(result["score"], 1)

    def test_ip_address(self):
        result = analyze_url("http://192.168.1.10/login")
        self.assertIn("URL uses an IP address", result["warnings"])

    def test_suspicious_keyword(self):
        result = analyze_url("http://example.com/login")
        self.assertIn(
            "Suspicious keyword found: login",
            result["warnings"]
        )

    def test_at_symbol(self):
        result = analyze_url("http://example.com@google.com")
        self.assertIn(
            "URL contains @ symbol",
            result["warnings"]
        )

    def test_invalid_url(self):
        result = analyze_url("example")
        self.assertEqual(result["result"], "INVALID")


if __name__ == "__main__":
    unittest.main()