from dojo.models import Test
from dojo.tools.crashtest_security.parser import CrashtestSecurityParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestCrashtestSecurityParser(DojoTestCase):
    def test_crashtest_security_json_parser_empty_file_has_no_findings(self):
        testfile = open(get_unit_tests_scans_path("crashtest_security") / "empty.json", encoding="utf-8")
        parser = CrashtestSecurityParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_crashtest_security_json_parser_full_file_has_many_findings(self):
        testfile = open(get_unit_tests_scans_path("crashtest_security") / "full.json", encoding="utf-8")
        parser = CrashtestSecurityParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(73, len(findings))
        finding = findings[0]
        self.assertIsNone(finding.unsaved_vulnerability_ids)
        finding = findings[4]
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2016-4072", finding.unsaved_vulnerability_ids[0])

    def test_crashtest_security_json_parser_extracted_data_file_has_many_findings(self):
        testfile = open(
            get_unit_tests_scans_path("crashtest_security") / "data_extracted.json", encoding="utf-8",
        )
        parser = CrashtestSecurityParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(73, len(findings))
