
from dojo.models import Test
from dojo.tools.npm_audit_7_plus.parser import NpmAudit7PlusParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestNpmAudit7PlusParser(DojoTestCase):
    def test_npm_audit_7_plus_parser_with_no_vuln_has_no_findings(self):
        testfile = open(get_unit_tests_scans_path() / "npm_audit_7_plus/no_vuln.json", encoding="utf-8")
        parser = NpmAudit7PlusParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_npm_audit_7_plus_parser_with_one_vuln_has_one_findings(self):
        testfile = open(get_unit_tests_scans_path() / "npm_audit_7_plus/one_vuln.json", encoding="utf-8")
        parser = NpmAudit7PlusParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("High", finding.severity)
            self.assertEqual(400, finding.cwe)
            self.assertIsNotNone(finding.description)
            self.assertGreater(len(finding.description), 0)
            self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", finding.cvssv3)

    def test_npm_audit_7_plus_parser_with_many_vuln_has_many_findings(self):
        testfile = open(get_unit_tests_scans_path() / "npm_audit_7_plus/many_vulns.json", encoding="utf-8")
        parser = NpmAudit7PlusParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(6, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(1035, finding.cwe)
            self.assertIsNotNone(finding.description)
            self.assertGreater(len(finding.description), 0)
            self.assertEqual("@vercel/fun", finding.title)

    def test_npm_audit_7_plus_parser_issue_10801(self):
        testfile = open(get_unit_tests_scans_path() / "npm_audit_7_plus/issue_10801.json", encoding="utf-8")
        parser = NpmAudit7PlusParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(0, finding.cwe)
