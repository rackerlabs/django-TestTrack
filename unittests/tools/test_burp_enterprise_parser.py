
from dojo.models import Test
from dojo.tools.burp_enterprise.parser import BurpEnterpriseParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestBurpEnterpriseParser(DojoTestCase):

    def test_burp_enterprise_with_multiple_vulns(self):
        with open(get_unit_tests_scans_path() / "burp_enterprise/many_vulns.html", encoding="utf-8") as test_file:
            parser = BurpEnterpriseParser()
            findings = parser.get_findings(test_file, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(12, len(findings))

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("High", finding.severity)
                self.assertTrue(finding.dynamic_finding)
                self.assertEqual(942, finding.cwe)
                self.assertEqual("Cross-origin resource sharing: arbitrary origin trusted", finding.title)
                self.assertIn("**Issue detail**:\nThe application implements an HTML5 cross-origin resource sharing (CORS) policy", finding.description)
                self.assertIn("An HTML5 cross-origin resource sharing (CORS) policy controls", finding.impact)
                self.assertIn("[Web Security Academy: Cross-origin resource sharing (CORS)](https://portswigger.net/web-security/cors)", finding.references)
                self.assertEqual(1, len(finding.unsaved_endpoints))
                self.assertEqual("example.com", finding.unsaved_endpoints[0].host)

            with self.subTest(i=5):
                finding = findings[5]
                self.assertEqual("Info", finding.severity)
                self.assertTrue(finding.dynamic_finding)
                self.assertIsNone(finding.cwe)
                self.assertEqual("WAF Detected: redacted", finding.title)
                self.assertIn("**Issue detail**:\nFingerprint Details:\n\nWAF Type : redacted\nWAF tech. details : Cloud-based CDN, WAF & DDoS prevention", finding.description)

    def test_burp_enterprise_with_multiple_vulns_newer_format(self):
        with open(get_unit_tests_scans_path() / "burp_enterprise/many_vulns_updated_format.html", encoding="utf-8") as test_file:
            parser = BurpEnterpriseParser()
            findings = parser.get_findings(test_file, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(12, len(findings))

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Low", finding.severity)
                self.assertTrue(finding.dynamic_finding)
                self.assertEqual(523, finding.cwe)
                self.assertEqual("Strict transport security not enforced", finding.title)
                self.assertIn("**Issue description**:\nThe application fails to prevent users from connecting to it over unencrypted connections.", finding.description)
                self.assertIn("**Issue remediation**:\nThe application should instruct web browsers to only access the application using HTTPS.", finding.impact)
                self.assertIn("- [HTTP Strict Transport Security](https://developer.mozilla.org/en-US/docs/Web/Security/HTTP_strict_transport_security)", finding.references)
                self.assertEqual(7, len(finding.unsaved_endpoints))
                self.assertEqual("instance.example.com", finding.unsaved_endpoints[0].host)

            with self.subTest(i=5):
                finding = findings[5]
                self.assertEqual("Info", finding.severity)
                self.assertTrue(finding.dynamic_finding)
                self.assertEqual(116, finding.cwe)
                self.assertEqual("Content security policy: allows form hijacking", finding.title)
                self.assertIn("**Issue detail**:\nThe content security policy doesn't prevent form hijacking", finding.description)
