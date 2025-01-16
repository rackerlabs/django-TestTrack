from dojo.models import Test
from dojo.tools.brakeman.parser import BrakemanParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestBrakemanParser(DojoTestCase):

    def test_parse_file_no_finding(self):
        with open(get_unit_tests_scans_path("brakeman") / "no_finding.json", encoding="utf-8") as testfile:
            parser = BrakemanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_has_two_findings(self):
        with open(get_unit_tests_scans_path("brakeman") / "two_findings.json", encoding="utf-8") as testfile:
            parser = BrakemanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(2, len(findings))

    def test_parse_file_has_many_findings(self):
        with open(get_unit_tests_scans_path("brakeman") / "many_findings.json", encoding="utf-8") as testfile:
            parser = BrakemanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(18, len(findings))
