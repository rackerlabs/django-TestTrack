from dojo.models import Test
from dojo.tools.anchorectl_vulns.parser import AnchoreCTLVulnsParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestAnchoreCTLVulnsParser(DojoTestCase):
    def test_anchore_engine_parser_has_no_finding(self):
        with open(get_unit_tests_scans_path("anchorectl_vulns") / "no_vuln.json", encoding="utf-8") as testfile:
            parser = AnchoreCTLVulnsParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_anchore_engine_parser_has_one_finding_and_it_is_correctly_parsed(self):
        with open(get_unit_tests_scans_path("anchorectl_vulns") / "one_vuln.json", encoding="utf-8") as testfile:
            parser = AnchoreCTLVulnsParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            singleFinding = findings[0]
            self.assertEqual(singleFinding.title, "CVE-2011-3389 - libgnutls30-3.5.8-5+deb9u4 (dpkg)")

            self.assertEqual(singleFinding.severity, "Medium")
            self.assertEqual(singleFinding.description, "**Image hash**: None\n\n**Package**: libgnutls30-3.5.8-5+deb9u4\n\n**Package path**: None\n\n**Package type**: dpkg\n\n**Feed**: vulnerabilities/debian:9\n\n**CPE**: None\n\n**Description**: That test description\n\n")

    def test_anchore_engine_parser_has_many_findings(self):
        with open(get_unit_tests_scans_path("anchorectl_vulns") / "many_vulns.json", encoding="utf-8") as testfile:
            parser = AnchoreCTLVulnsParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(23, len(findings))
