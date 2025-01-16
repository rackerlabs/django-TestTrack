import datetime

from dojo.models import Test
from dojo.tools.cred_scan.parser import CredScanParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestCredScanParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        with open(get_unit_tests_scans_path("cred_scan") / "cred_scan_no_vuln.csv", encoding="utf-8") as testfile:
            parser = CredScanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_findings(self):
        with open(get_unit_tests_scans_path("cred_scan") / "cred_scan_one_vuln.csv", encoding="utf-8") as testfile:
            parser = CredScanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("10", finding.line)
                self.assertEqual("E:sample/dir/first/App.config", finding.file_path)
                self.assertEqual(datetime.date(2021, 4, 10), datetime.datetime.date(finding.date))

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        with open(get_unit_tests_scans_path("cred_scan") / "cred_scan_many_vuln.csv", encoding="utf-8") as testfile:
            parser = CredScanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))
