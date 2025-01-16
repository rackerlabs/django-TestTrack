from dojo.models import Test
from dojo.tools.chefinspect.parser import ChefInspectParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestChefInspectParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        with open(get_unit_tests_scans_path("chefinspect") / "no_finding.log", encoding="utf-8") as testfile:
            parser = ChefInspectParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        with open(get_unit_tests_scans_path("chefinspect") / "one_finding.log", encoding="utf-8") as testfile:
            parser = ChefInspectParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        with open(get_unit_tests_scans_path("chefinspect") / "many_findings.log", encoding="utf-8") as testfile:
            parser = ChefInspectParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(10, len(findings))
