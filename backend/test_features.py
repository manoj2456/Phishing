"""
PhishGuard - Python Unit & Integration Tests
Validates all 12 test cases specified in Section 11 of requirements.
"""

import unittest
from predict import predict_url
from feature_extractor import validate_and_normalize_url


class TestPhishGuardAnalyzer(unittest.TestCase):

    def test_01_normal_https_url(self):
        res = predict_url("https://example.com")
        self.assertTrue(res["success"])
        self.assertEqual(res["classification"], "SAFE")
        self.assertLessEqual(res["risk_score"], 30)
        self.assertGreaterEqual(res["risk_score"], 0)
        self.assertTrue(any("HTTPS is enabled" in p for p in res["positive_indicators"]))

    def test_02_http_url(self):
        res = predict_url("http://example.org")
        self.assertTrue(res["success"])
        # HTTP adds minor risk points (+15) but stays SAFE
        self.assertLessEqual(res["risk_score"], 35)
        self.assertTrue(any("insecure HTTP" in w for w in res["indicators"]))

    def test_03_very_long_url(self):
        long_url = "https://example.com/" + ("subpath/" * 12) + "payload"
        res = predict_url(long_url)
        self.assertTrue(res["success"])
        self.assertGreater(res["features"]["url_length"], 75)
        table_row = next(r for r in res["characteristics_table"] if r["feature"] == "URL Length")
        self.assertIn("Very Long", table_row["actualResult"])

    def test_04_multiple_subdomains(self):
        res = predict_url("https://a.b.c.d.example.com")
        self.assertTrue(res["success"])
        self.assertGreaterEqual(res["features"]["num_subdomains"], 3)
        table_row = next(r for r in res["characteristics_table"] if r["feature"] == "Subdomain Structure")
        self.assertEqual(table_row["actualResult"], "Unusual")

    def test_05_suspicious_keywords(self):
        res = predict_url("https://company-portal.com/login-verify-account")
        self.assertTrue(res["success"])
        self.assertGreaterEqual(res["features"]["suspicious_keyword_count"], 2)
        table_row = next(r for r in res["characteristics_table"] if r["feature"] == "Suspicious Keywords")
        self.assertIn("login", table_row["actualResult"])

    def test_06_ip_address_hostname(self):
        # RFC 1918 Private IP is internal network address, NOT proof of public phishing
        res = predict_url("http://192.168.1.104/secure-banking/verify.html")
        self.assertTrue(res["success"])
        self.assertEqual(res["features"]["is_ip_address"], 1)
        self.assertEqual(res["classification"], "SAFE")
        self.assertLessEqual(res["risk_score"], 30)

    def test_06b_public_ip_with_phishing_lure(self):
        # Public IP with active brand spoofing and lure keywords is PHISHING
        res = predict_url("http://198.51.100.22/paypal-login/verify.php")
        self.assertTrue(res["success"])
        self.assertEqual(res["features"]["is_ip_address"], 1)
        self.assertEqual(res["classification"], "PHISHING")
        self.assertGreaterEqual(res["risk_score"], 61)

    def test_07_contains_at_symbol(self):
        res = predict_url("http://mybank.com@attacker-site.xyz/login")
        self.assertTrue(res["success"])
        self.assertEqual(res["features"]["has_at_symbol"], 1)
        self.assertEqual(res["classification"], "PHISHING")

    def test_08_numerous_special_characters(self):
        res = predict_url("https://example.com/test?a=1&b=2&c=3&d=4;e=5!f=6")
        self.assertTrue(res["success"])
        self.assertGreater(res["features"]["num_special_chars"], 6)

    def test_09_invalid_url_protocol(self):
        res = predict_url("ftp://unsupported.example.com")
        self.assertFalse(res["success"])
        self.assertIn("error", res)

    def test_10_empty_input(self):
        res = predict_url("   ")
        self.assertFalse(res["success"])
        self.assertIn("error", res)

    def test_11_query_parameters(self):
        res = predict_url("https://example.com/search?q=cybersecurity&category=education")
        self.assertTrue(res["success"])
        self.assertGreaterEqual(res["features"]["num_question"], 1)
        self.assertGreaterEqual(res["features"]["num_equal"], 2)

    def test_12_misleading_subdomain(self):
        res = predict_url("http://paypal.com.account-update.xyz/login.php")
        self.assertTrue(res["success"])
        self.assertGreaterEqual(res["features"]["misleading_brand_count"], 1)
        self.assertEqual(res["classification"], "PHISHING")


if __name__ == "__main__":
    unittest.main()
