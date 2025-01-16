from dojo.models import Test
from dojo.tools.mozilla_observatory.parser import MozillaObservatoryParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestMozillaObservatoryParser(DojoTestCase):
    def test_parse_file_with_no_vuln_has_no_findings(self):
        with open(get_unit_tests_scans_path("mozilla_observatory") / "mozilla_no_vuln.json", encoding="utf-8") as testfile:
            parser = MozillaObservatoryParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(4, len(findings))
            # test that all findings are not active
            for finding in findings:
                self.assertFalse(finding.active)
                if finding.vuln_id_from_tool == "strict-transport-security":
                    with self.subTest(vuln_id_from_tool=finding.vuln_id_from_tool):
                        self.assertEqual("Preloaded via the HTTP Strict Transport Security (HSTS) preloading process", finding.title)
                        self.assertEqual("Info", finding.severity)
                        self.assertIn("Preloaded via the HTTP Strict Transport Security (HSTS) preloading process", finding.description)

    def test_parse_file_with_two_vuln_has_two_findings(self):
        with open(get_unit_tests_scans_path("mozilla_observatory") / "mozilla_gitlab_two_vuln.json", encoding="utf-8") as testfile:
            parser = MozillaObservatoryParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(2, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        with open(get_unit_tests_scans_path("mozilla_observatory") / "mozilla_google_many_vuln.json", encoding="utf-8") as testfile:
            parser = MozillaObservatoryParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(6, len(findings))

    def test_parse_file_cli_mozilla_org(self):
        """Test from the CLI"""
        with open(get_unit_tests_scans_path("mozilla_observatory") / "mozilla_org.json", encoding="utf-8") as testfile:
            parser = MozillaObservatoryParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(12, len(findings))
            for finding in findings:
                if finding.vuln_id_from_tool == "content-security-policy":
                    with self.subTest(vuln_id_from_tool=finding.vuln_id_from_tool):
                        self.assertTrue(finding.active)
                        self.assertEqual("Content Security Policy (CSP) implemented unsafely. This includes 'unsafe-inline' or data: inside script-src, overly broad sources such as https: inside object-src or script-src, or not restricting the sources for object-src or script-src.", finding.title)
                        self.assertEqual("Medium", finding.severity)
                        self.assertIn("Content Security Policy (CSP) implemented unsafely. This includes 'unsafe-inline' or data: inside script-src, overly broad sources such as https: inside object-src or script-src, or not restricting the sources for object-src or script-src.", finding.description)
                else:
                    with self.subTest(vuln_id_from_tool=finding.vuln_id_from_tool):
                        self.assertFalse(finding.active)

    def test_parse_file_cli_demo(self):
        """Test from the CLI"""
        with open(get_unit_tests_scans_path("mozilla_observatory") / "demo.json", encoding="utf-8") as testfile:
            parser = MozillaObservatoryParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(12, len(findings))
            for finding in findings:
                if finding.vuln_id_from_tool == "content-security-policy":
                    with self.subTest(vuln_id_from_tool="content-security-policy"):
                        self.assertTrue(finding.active)
                        self.assertEqual("Content Security Policy (CSP) header not implemented", finding.title)
                        self.assertEqual("Medium", finding.severity)
                        self.assertIn("Content Security Policy (CSP) header not implemented", finding.description)
                        self.assertEqual("content-security-policy", finding.vuln_id_from_tool)
                elif finding.vuln_id_from_tool == "cookies":
                    with self.subTest(vuln_id_from_tool="cookies"):
                        self.assertTrue(finding.active)
                        self.assertEqual("Cookies set without using the Secure flag or set over HTTP", finding.title)
                        self.assertEqual("Medium", finding.severity)
                        self.assertIn("Cookies set without using the Secure flag or set over HTTP", finding.description)
                elif finding.vuln_id_from_tool == "strict-transport-security":
                    with self.subTest(vuln_id_from_tool="strict-transport-security"):
                        self.assertTrue(finding.active)
                        self.assertEqual("HTTP Strict Transport Security (HSTS) header not implemented", finding.title)
                        self.assertEqual("Medium", finding.severity)
                        self.assertIn("HTTP Strict Transport Security (HSTS) header not implemented", finding.description)
                else:
                    with self.subTest(vuln_id_from_tool=finding.vuln_id_from_tool):
                        self.assertFalse(finding.active)

    def test_parse_file_cli_juicy(self):
        """Test from the CLI"""
        with open(get_unit_tests_scans_path("mozilla_observatory") / "juicy.json", encoding="utf-8") as testfile:
            parser = MozillaObservatoryParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(12, len(findings))
            for finding in findings:
                if finding.vuln_id_from_tool == "content-security-policy":
                    with self.subTest(vuln_id_from_tool=finding.vuln_id_from_tool):
                        self.assertTrue(finding.active)
                        self.assertEqual("Content Security Policy (CSP) header not implemented", finding.title)
                        self.assertEqual("Medium", finding.severity)
                        self.assertIn("Content Security Policy (CSP) header not implemented", finding.description)
                elif finding.vuln_id_from_tool == "strict-transport-security":
                    with self.subTest(vuln_id_from_tool=finding.vuln_id_from_tool):
                        self.assertTrue(finding.active)
                        self.assertEqual("HTTP Strict Transport Security (HSTS) header not implemented", finding.title)
                        self.assertEqual("Medium", finding.severity)
                        self.assertIn("HTTP Strict Transport Security (HSTS) header not implemented", finding.description)
                elif finding.vuln_id_from_tool == "x-xss-protection":
                    with self.subTest(vuln_id_from_tool=finding.vuln_id_from_tool):
                        self.assertTrue(finding.active)
                        self.assertEqual("X-XSS-Protection header not implemented", finding.title)
                        self.assertEqual("Low", finding.severity)
                        self.assertIn("X-XSS-Protection header not implemented", finding.description)
                elif finding.vuln_id_from_tool == "subresource-integrity":
                    with self.subTest(vuln_id_from_tool=finding.vuln_id_from_tool):
                        self.assertTrue(finding.active)
                        self.assertEqual('Subresource Integrity (SRI) not implemented, and external scripts are loaded over HTTP or use protocol-relative URLs via src="//..."', finding.title)
                        self.assertEqual("High", finding.severity)
                        self.assertIn("Subresource Integrity (SRI) not implemented", finding.description)
                elif finding.vuln_id_from_tool == "redirection":
                    with self.subTest(vuln_id_from_tool=finding.vuln_id_from_tool):
                        self.assertTrue(finding.active)
                        self.assertEqual("Does not redirect to an HTTPS site", finding.title)
                        self.assertEqual("Medium", finding.severity)
                        self.assertIn("Does not redirect to an HTTPS site", finding.description)
                else:
                    with self.subTest(vuln_id_from_tool=finding.vuln_id_from_tool):
                        self.assertFalse(finding.active)

    def test_parse_file_cli_nmap_scanme(self):
        """Test from the CLI"""
        with open(get_unit_tests_scans_path("mozilla_observatory") / "nmap_scanme.json", encoding="utf-8") as testfile:
            parser = MozillaObservatoryParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(12, len(findings))
            for finding in findings:
                if finding.vuln_id_from_tool == "content-security-policy":
                    with self.subTest(vuln_id_from_tool=finding.vuln_id_from_tool):
                        self.assertTrue(finding.active)
                        self.assertEqual("Content Security Policy (CSP) header not implemented", finding.title)
                        self.assertEqual("Medium", finding.severity)
                        self.assertIn("Content Security Policy (CSP) header not implemented", finding.description)
                elif finding.vuln_id_from_tool == "strict-transport-security":
                    with self.subTest(vuln_id_from_tool=finding.vuln_id_from_tool):
                        self.assertTrue(finding.active)
                        self.assertEqual("HTTP Strict Transport Security (HSTS) header cannot be set, as site contains an invalid certificate chain", finding.title)
                        self.assertEqual("Medium", finding.severity)
                        self.assertIn("HTTP Strict Transport Security (HSTS) header cannot be set, as site contains an invalid certificate chain", finding.description)
                elif finding.vuln_id_from_tool == "x-xss-protection":
                    with self.subTest(vuln_id_from_tool=finding.vuln_id_from_tool):
                        self.assertTrue(finding.active)
                        self.assertEqual("X-XSS-Protection header not implemented", finding.title)
                        self.assertEqual("Low", finding.severity)
                        self.assertIn("X-XSS-Protection header not implemented", finding.description)
                elif finding.vuln_id_from_tool == "x-frame-options":
                    with self.subTest(vuln_id_from_tool=finding.vuln_id_from_tool):
                        self.assertTrue(finding.active)
                        self.assertEqual("X-Frame-Options (XFO) header not implemented", finding.title)
                        self.assertEqual("Medium", finding.severity)
                        self.assertIn("X-Frame-Options (XFO) header not implemented", finding.description)
                elif finding.vuln_id_from_tool == "x-content-type-options":
                    with self.subTest(vuln_id_from_tool=finding.vuln_id_from_tool):
                        self.assertTrue(finding.active)
                        self.assertEqual("X-Content-Type-Options header not implemented", finding.title)
                        self.assertEqual("Low", finding.severity)
                        self.assertIn("X-Content-Type-Options header not implemented", finding.description)
                elif finding.vuln_id_from_tool == "subresource-integrity":
                    with self.subTest(vuln_id_from_tool=finding.vuln_id_from_tool):
                        self.assertTrue(finding.active)
                        self.assertEqual('Subresource Integrity (SRI) not implemented, and external scripts are loaded over HTTP or use protocol-relative URLs via src="//..."', finding.title)
                        self.assertEqual("High", finding.severity)
                        self.assertIn("Subresource Integrity (SRI) not implemented", finding.description)
                elif finding.vuln_id_from_tool == "redirection":
                    with self.subTest(vuln_id_from_tool=finding.vuln_id_from_tool):
                        self.assertTrue(finding.active)
                        self.assertEqual("Initial redirection from HTTP to HTTPS is to a different host, preventing HSTS", finding.title)
                        self.assertEqual("Low", finding.severity)
                        self.assertIn("Initial redirection from HTTP to HTTPS is to a different host, preventing HSTS", finding.description)
                elif finding.vuln_id_from_tool == "referrer-policy-private":
                    with self.subTest(vuln_id_from_tool=finding.vuln_id_from_tool):
                        self.assertTrue(finding.active)
                        self.assertEqual("Referrer-Policy header not implemented", finding.title)
                        self.assertEqual("Info", finding.severity)
                        self.assertIn("Referrer-Policy header not implemented", finding.description)
                else:
                    with self.subTest(vuln_id_from_tool=finding.vuln_id_from_tool):
                        self.assertFalse(finding.active)

    def test_parse_file_cli_nmap_scanme_no_name_attribute(self):
        """Test from the CLI"""
        with open(get_unit_tests_scans_path("mozilla_observatory") / "nmap_scanme_2022.json", encoding="utf-8") as testfile:
            parser = MozillaObservatoryParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(12, len(findings))
            for finding in findings:
                if finding.vuln_id_from_tool == "content-security-policy":
                    with self.subTest(vuln_id_from_tool=finding.vuln_id_from_tool):
                        self.assertTrue(finding.active)
                        self.assertEqual("Content Security Policy (CSP) header not implemented", finding.title)
                        self.assertEqual("Medium", finding.severity)
                        self.assertIn("Content Security Policy (CSP) header not implemented", finding.description)
                elif finding.vuln_id_from_tool == "strict-transport-security":
                    with self.subTest(vuln_id_from_tool=finding.vuln_id_from_tool):
                        self.assertTrue(finding.active)
                        self.assertEqual("HTTP Strict Transport Security (HSTS) header cannot be set for sites not available over HTTPS", finding.title)
                        self.assertEqual("Medium", finding.severity)
                        self.assertIn("HTTP Strict Transport Security (HSTS) header cannot be set for sites not available over HTTPS", finding.description)
                elif finding.vuln_id_from_tool == "x-xss-protection":
                    with self.subTest(vuln_id_from_tool=finding.vuln_id_from_tool):
                        self.assertTrue(finding.active)
                        self.assertEqual("X-XSS-Protection header not implemented", finding.title)
                        self.assertEqual("Low", finding.severity)
                        self.assertIn("X-XSS-Protection header not implemented", finding.description)
                elif finding.vuln_id_from_tool == "x-frame-options":
                    with self.subTest(vuln_id_from_tool=finding.vuln_id_from_tool):
                        self.assertTrue(finding.active)
                        self.assertEqual("X-Frame-Options (XFO) header not implemented", finding.title)
                        self.assertEqual("Medium", finding.severity)
                        self.assertIn("X-Frame-Options (XFO) header not implemented", finding.description)
                elif finding.vuln_id_from_tool == "x-content-type-options":
                    with self.subTest(vuln_id_from_tool=finding.vuln_id_from_tool):
                        self.assertTrue(finding.active)
                        self.assertEqual("X-Content-Type-Options header not implemented", finding.title)
                        self.assertEqual("Low", finding.severity)
                        self.assertIn("X-Content-Type-Options header not implemented", finding.description)
                elif finding.vuln_id_from_tool == "subresource-integrity":
                    with self.subTest(vuln_id_from_tool=finding.vuln_id_from_tool):
                        self.assertFalse(finding.active)
                        self.assertEqual("Subresource Integrity (SRI) not implemented, but all scripts are loaded from a similar origin", finding.title)
                        self.assertEqual("Info", finding.severity)
                        self.assertIn("Subresource Integrity (SRI) not implemented", finding.description)
                elif finding.vuln_id_from_tool == "redirection":
                    with self.subTest(vuln_id_from_tool=finding.vuln_id_from_tool):
                        self.assertTrue(finding.active)
                        self.assertEqual("Does not redirect to an HTTPS site", finding.title)
                        self.assertEqual("Medium", finding.severity)
                        self.assertIn("Does not redirect to an HTTPS site", finding.description)
                elif finding.vuln_id_from_tool == "referrer-policy-private":
                    with self.subTest(vuln_id_from_tool=finding.vuln_id_from_tool):
                        self.assertTrue(finding.active)
                        self.assertEqual("Referrer-Policy header not implemented", finding.title)
                        self.assertEqual("Info", finding.severity)
                        self.assertIn("Referrer-Policy header not implemented", finding.description)
                else:
                    with self.subTest(vuln_id_from_tool=finding.vuln_id_from_tool):
                        self.assertFalse(finding.active)
