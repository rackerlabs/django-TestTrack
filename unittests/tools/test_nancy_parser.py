
from dojo.models import Test
from dojo.tools.nancy.parser import NancyParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestNancyParser(DojoTestCase):
    def test_nancy_parser_with_no_vuln_has_no_findings(self):
        with open(get_unit_tests_scans_path() / "nancy/nancy_no_findings.json", encoding="utf-8") as testfile:
            parser = NancyParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_nancy_parser_with_one_vuln_has_one_findings(self):
        with open(get_unit_tests_scans_path() / "nancy/nancy_one_findings.json", encoding="utf-8") as testfile:
            parser = NancyParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Info", finding.severity)
                self.assertIsNotNone(finding.description)
                self.assertGreater(len(finding.description), 0)
                self.assertEqual(None, finding.cve)
                self.assertEqual("CVE-2017-1000070", finding.unsaved_vulnerability_ids[0])
                self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", finding.cvssv3)

    def test_nancy_plus_parser_with_many_vuln_has_many_findings(self):
        with open(get_unit_tests_scans_path() / "nancy/nancy_many_findings.json", encoding="utf-8") as testfile:
            parser = NancyParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(13, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual(0, finding.cwe)
                self.assertIsNotNone(finding.description)
                self.assertGreater(len(finding.description), 0)
