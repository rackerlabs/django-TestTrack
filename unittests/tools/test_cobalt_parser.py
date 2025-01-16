from dojo.models import Test
from dojo.tools.cobalt.parser import CobaltParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestCobaltParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):

        with open(get_unit_tests_scans_path("cobalt") / "cobalt_no_vuln.csv", encoding="utf-8") as testfile:
            parser = CobaltParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_findings(self):
        with open(get_unit_tests_scans_path("cobalt") / "cobalt_one_vuln.csv", encoding="utf-8") as testfile:
            parser = CobaltParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        with open(get_unit_tests_scans_path("cobalt") / "cobalt_many_vuln.csv", encoding="utf-8") as testfile:
            parser = CobaltParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(9, len(findings))
