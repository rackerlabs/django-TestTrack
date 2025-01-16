from dojo.models import Test
from dojo.tools.wapiti.parser import WapitiParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestWapitiParser(DojoTestCase):

    def test_parse_file_3_0_4(self):
        """Generated with version 3.0.4 on OWASP Juicy Shop"""
        with open(get_unit_tests_scans_path("wapiti") / "juicyshop.xml", encoding="utf-8") as testfile:
            parser = WapitiParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(3, len(findings))
            finding = findings[0]
            self.assertEqual("Content Security Policy Configuration: CSP is not set", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual("Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks.", finding.description)
            self.assertEqual("Configuring Content Security Policy involves adding the Content-Security-Policy HTTP header to a web page and giving it values to control what resources the user agent is allowed to load for that page.", finding.mitigation)
            finding = findings[1]
            self.assertEqual("HTTP Secure Headers: X-XSS-Protection is not set", finding.title)
            self.assertEqual("Low", finding.severity)
            finding = findings[2]
            self.assertEqual("HTTP Secure Headers: Strict-Transport-Security is not set", finding.title)
            self.assertEqual("Low", finding.severity)

    def test_parse_file_demo(self):
        """"""
        with open(get_unit_tests_scans_path("wapiti") / "demo.xml", encoding="utf-8") as testfile:
            parser = WapitiParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(3, len(findings))
            finding = findings[2]
            self.assertEqual("Secure Flag cookie: Secure flag is not set in the cookie : csrftoken", finding.title)
            self.assertEqual("Low", finding.severity)

    def test_parse_file_example(self):
        """"""
        with open(get_unit_tests_scans_path("wapiti") / "example.xml", encoding="utf-8") as testfile:
            parser = WapitiParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(5, len(findings))
            finding = findings[2]
            self.assertEqual("HTTP Secure Headers: X-XSS-Protection is not set", finding.title)
            self.assertEqual("Low", finding.severity)

    def test_parse_cwe(self):
        """File to test CWE"""
        with open(get_unit_tests_scans_path("wapiti") / "cwe.xml", encoding="utf-8") as testfile:
            parser = WapitiParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Cross Site Request Forgery: CSP is not set", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual(352, finding.cwe)
