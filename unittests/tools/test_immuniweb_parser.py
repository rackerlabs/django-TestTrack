from dojo.models import Test
from dojo.tools.immuniweb.parser import ImmuniwebParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestImmuniwebParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        with open(get_unit_tests_scans_path("immuniweb") / "ImmuniWeb-0-vuln.xml", encoding="utf-8") as testfile:
            parser = ImmuniwebParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        with open(get_unit_tests_scans_path("immuniweb") / "ImmuniWeb-1-vuln.xml", encoding="utf-8") as testfile:
            parser = ImmuniwebParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        with open(get_unit_tests_scans_path("immuniweb") / "ImmuniWeb-multiple-vuln.xml", encoding="utf-8") as testfile:
            parser = ImmuniwebParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertGreater(len(findings), 2)
