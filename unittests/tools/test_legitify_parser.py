from dojo.models import Test
from dojo.tools.legitify.parser import LegitifyParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestLegitifyParser(DojoTestCase):
    def test_parse_file_with_many_findings(self):
        with open(get_unit_tests_scans_path("legitify") / "legitify_many_findings.json", encoding="utf-8") as testfile:
            parser = LegitifyParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(16, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("High", finding.severity)
                self.assertEqual("code_review_not_required", finding.vuln_id_from_tool)
                self.assertEqual("Repository | Default Branch Should Require Code Review", finding.title)
                self.assertFalse(finding.dynamic_finding)
                self.assertTrue(finding.static_finding)
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()

    def test_parse_file_with_one_finding(self):
        with open(get_unit_tests_scans_path("legitify") / "legitify_one_finding.json", encoding="utf-8") as testfile:
            parser = LegitifyParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("High", finding.severity)
                self.assertEqual("code_review_not_required", finding.vuln_id_from_tool)
                self.assertEqual("Repository | Default Branch Should Require Code Review", finding.title)
                self.assertFalse(finding.dynamic_finding)
                self.assertTrue(finding.static_finding)
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()

    def test_parse_file_with_no_findings(self):
        with open(get_unit_tests_scans_path("legitify") / "legitify_no_findings.json", encoding="utf-8") as testfile:
            parser = LegitifyParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))
