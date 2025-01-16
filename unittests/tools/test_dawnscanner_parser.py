import datetime

from dojo.models import Test
from dojo.tools.dawnscanner.parser import DawnScannerParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestDawnScannerParser(DojoTestCase):
    def test_burp_with_one_vuln_has_one_finding(self):
        with open(get_unit_tests_scans_path() / "dawnscanner/dawnscanner_v1.6.9.json", encoding="utf-8") as test_file:
            parser = DawnScannerParser()
            findings = parser.get_findings(test_file, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()

            self.assertEqual(4, len(findings))

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("CVE-2016-6316", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
                self.assertEqual("CVE-2016-6316", finding.unsaved_vulnerability_ids[0])
                self.assertEqual(
                    'Text declared as "HTML safe" when passed as an attribute value to a tag helper will not have quotes escaped which can lead to an XSS attack.',
                    finding.description,
                )
                self.assertEqual(
                    datetime.datetime(2019, 4, 1, 21, 14, 32, tzinfo=datetime.timezone(datetime.timedelta(seconds=0))),
                    finding.date,
                )  # 2019-04-01 21:14:32 +0000

            with self.subTest(i=3):
                finding = findings[3]
                self.assertEqual("Owasp Ror CheatSheet: Security Related Headers", finding.title)
                self.assertEqual("Info", finding.severity)
                self.assertIsNone(finding.unsaved_vulnerability_ids)
                self.assertEqual(
                    'To set a header value, simply access the response.headers object as a hash inside your controller (often in a before/after_filter). Rails 4 provides the "default_headers" functionality that will automatically apply the values supplied. This works for most headers in almost all cases.',
                    finding.description,
                )
                self.assertEqual(
                    "Use response headers like X-Frame-Options, X-Content-Type-Options, X-XSS-Protection in your project.",
                    finding.mitigation,
                )
                self.assertEqual(
                    datetime.datetime(2019, 4, 1, 21, 14, 32, tzinfo=datetime.timezone(datetime.timedelta(seconds=0))),
                    finding.date,
                )  # 2019-04-01 21:14:32 +0000
