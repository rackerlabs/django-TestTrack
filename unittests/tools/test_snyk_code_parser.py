from dojo.models import Test
from dojo.tools.snyk_code.parser import SnykCodeParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestSnykCodeParser(DojoTestCase):

    def test_snykParser_single_has_many_findings(self):
        testfile = open(get_unit_tests_scans_path("snyk_code") / "single_project_many_vulns.json", encoding="utf-8")
        parser = SnykCodeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(206, len(findings))

    def test_snykcode_issue_9270(self):
        with open(get_unit_tests_scans_path("snyk_code") / "snykcode_issue_9270.json", encoding="utf-8") as testfile:
            parser = SnykCodeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(39, len(findings))
